//
// Created by machiry on 1/30/17.
//

#include <iostream>
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/ValueSymbolTable.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/SourceMgr.h"
// #include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Analysis/CFGPrinter.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fstream>
#include <cctype>
#include <algorithm>

// #define DIFUZE_DEBUG 1

using namespace std;
using namespace llvm;

#define NETDEV_IOCTL "NETDEVIOCTL"
#define READ_HDR "FileRead"
#define WRITE_HDR "FileWrite"
#define IOCTL_HDR "IOCTL"
#define OPEN_HDR "DEVOPEN"
#define MMAP_HDR "DEVMMAP"
#define POLL_HDR "DEVPOLL"
#define RELEASE_HDR "DEVRELEASE"
#define DEVATTR_SHOW "DEVSHOW"
#define DEVATTR_STORE "DEVSTORE"
#define V4L2_IOCTL_FUNC "V4IOCTL"
#define END_HDR "ENDEND"

typedef struct {
    std::string st_name;
    long mem_id;
    std::string method_lab;
} INT_STS;


void print_err(char *prog_name) {
    std::cerr << "[!] This program identifies all the entry points from the provided bitcode file.\n";
    std::cerr << "[!] saves these entry points into provided output file, which could be used to run analysis on.\n";
    std::cerr << "[?] " << prog_name << " <llvm_linked_bit_code_file> <output_txt_file>\n";
    exit(-1);
}

std::string getFunctionFileName(Function *targetFunc) {
    SmallVector<std::pair<unsigned, MDNode *>, 4> MDs;
    targetFunc->getAllMetadata(MDs);
    std::string targetFName = "";
    for (auto &MD : MDs) {
        if (MDNode *N = MD.second) {
            if (auto *subProgram = dyn_cast<DISubprogram>(N)) {
                targetFName = subProgram->getFilename().str();
                break;
            }
        }
    }
    return targetFName;
}


bool printFuncVal(Value *currVal, FILE *outputFile, const char *hdr_str) {
    Function *targetFunction = dyn_cast<Function>(currVal->stripPointerCasts());
    if (targetFunction != nullptr && !targetFunction->isDeclaration() && targetFunction->hasName()) {
        fprintf(outputFile, "%s:%s\n", hdr_str, targetFunction->getName().str().c_str());
        return true;
    }
    return false;
}

bool printTriFuncVal(Value *currVal, FILE *outputFile, const char *hdr_str) {
    Function *targetFunction = dyn_cast<Function>(currVal->stripPointerCasts());
    if (targetFunction != nullptr && !targetFunction->isDeclaration() && targetFunction->hasName()) {
        fprintf(outputFile, "%s:%s:%s\n", hdr_str, targetFunction->getName().str().c_str(),
                            getFunctionFileName(targetFunction).c_str());
        return true;
    }
    return false;
}

void process_netdev_st(GlobalVariable *currGlobal, FILE *outputFile) {

    if(currGlobal->hasInitializer()) {
        // get the initializer.
        Constant *targetConstant = currGlobal->getInitializer();
        ConstantStruct *actualStType = dyn_cast<ConstantStruct>(targetConstant);
        if(actualStType != nullptr) {
            for (unsigned int i=0; i<actualStType->getNumOperands();i++) {
                Value *op = actualStType->getOperand(i);
                if (Function *f_op = dyn_cast<Function>(op)) {
                    if (f_op->hasName()) {
                        std::string f_name = f_op->getName().str();
                        std::transform(f_name.begin(), f_name.end(), f_name.begin(), ::tolower);
                        // dbgs() << "Operand " << i << ": "<< f_op->getName() <<"\n";
                        // get entrypoints by string match
                        // more precise than raw difuze which use hard code offset to find entrypoint
                        if (f_name.find("read") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, READ_HDR);
                        else if (f_name.find("write") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, WRITE_HDR);
                        else if (f_name.find("ioctl") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, NETDEV_IOCTL);
                        else if (f_name.find("open") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, OPEN_HDR);
                        else if (f_name.find("mmap") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, MMAP_HDR);
                        else if (f_name.find("release") != f_name.npos || f_name.find("close") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, RELEASE_HDR);
                        else if (f_name.find("poll") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, POLL_HDR);
                        else if (f_name.find("show") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, DEVATTR_SHOW);
                        else if (f_name.find("store") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, DEVATTR_STORE);
                    }
                }
            }
        }
    }
}

void process_device_attribute_st(GlobalVariable *currGlobal, FILE *outputFile) {

    if(currGlobal->hasInitializer()) {

        // get the initializer.
        Constant *targetConstant = currGlobal->getInitializer();
        ConstantStruct *actualStType = dyn_cast<ConstantStruct>(targetConstant);
        if(actualStType != nullptr) {

            for (unsigned int i=0; i<actualStType->getNumOperands();i++) {
                Value *op = actualStType->getOperand(i);
                if (Function *f_op = dyn_cast<Function>(op)) {
                    if (f_op->hasName()) {
                        std::string f_name = f_op->getName().str();
                        std::transform(f_name.begin(), f_name.end(), f_name.begin(), ::tolower);
                        // get entrypoints by string match
                        // more precise than raw difuze which use hard code offset to find entrypoint
                        if (f_name.find("read") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, READ_HDR);
                        else if (f_name.find("write") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, WRITE_HDR);
                        else if (f_name.find("ioctl") != f_name.npos)
                            printTriFuncVal(actualStType->getOperand(i), outputFile, IOCTL_HDR);
                        else if (f_name.find("open") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, OPEN_HDR);
                        else if (f_name.find("mmap") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, MMAP_HDR);
                        else if (f_name.find("release") != f_name.npos || f_name.find("close") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, RELEASE_HDR);
                        else if (f_name.find("poll") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, POLL_HDR);
                        else if (f_name.find("show") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, DEVATTR_SHOW);
                        else if (f_name.find("store") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, DEVATTR_STORE);
                    }
                }
            }
        }
    }
}

inline bool ends_with(std::string const &value, std::string const &ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

void process_file_operations_st(GlobalVariable *currGlobal, FILE *outputFile) {

    if(currGlobal->hasInitializer()) {

        // get the initializer.
        Constant *targetConstant = currGlobal->getInitializer();
        ConstantStruct *actualStType = dyn_cast<ConstantStruct>(targetConstant);
        bool ioctl_found = false, ioctl_found2 = false;
        if(actualStType != nullptr) {
#ifdef DIFUZE_DEBUG
            dbgs() << "actualStType->dump(): \n"; 
            actualStType->dump();
#endif
            Value *currFieldVal;

            for (unsigned int i=0; i<actualStType->getNumOperands();i++) {
                Value *op = actualStType->getOperand(i);
                if (Function *f_op = dyn_cast<Function>(op)) {
                    if (f_op->hasName()) {
                        std::string f_name = f_op->getName().str();
                        std::transform(f_name.begin(), f_name.end(), f_name.begin(), ::tolower);
#ifdef DIFUZE_DEBUG
                        dbgs() << "Operand " << i << ": "<< f_name <<"\n";
#endif
                        // get entrypoints by string match
                        // more precise than raw difuze which use hard code offset to find entrypoint
                        if (f_name.find("read") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, READ_HDR);
                        else if (f_name.find("write") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, WRITE_HDR);
                        else if (f_name.find("ioctl") != f_name.npos) {
#ifdef DIFUZE_DEBUG
                            dbgs() << "ioctl Operand " << i << ": "<< f_name <<"\n";
#endif
                            ioctl_found = printTriFuncVal(actualStType->getOperand(i), outputFile, IOCTL_HDR);
                        }
                        else if (f_name.find("open") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, OPEN_HDR);
                        else if (f_name.find("mmap") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, MMAP_HDR);
                        else if (f_name.find("release") != f_name.npos || f_name.find("close") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, RELEASE_HDR);
                        else if (f_name.find("poll") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, POLL_HDR);
                    }
                }
            }

            if (!ioctl_found) {
                unsigned int idx=0;
                std::string ioctlEnd = "_ioctl";
                for(idx=0; idx<actualStType->getNumOperands(); idx++) {
                    if(idx == 10 || idx == 8) {
                        continue;
                    }
                    currFieldVal = actualStType->getOperand(idx);
                    Function *targetFunction = dyn_cast<Function>(currFieldVal->stripPointerCasts());
                    if(targetFunction != nullptr && !targetFunction->isDeclaration() && targetFunction->hasName() && ends_with(targetFunction->getName().str(), ioctlEnd)) {
                        printTriFuncVal(currFieldVal, outputFile, IOCTL_HDR);
                    }
                }
            }
        }

    }
}

void process_snd_pcm_ops_st(GlobalVariable *currGlobal, FILE *outputFile) {
    if(currGlobal->hasInitializer()) {
        // get the initializer.
        Constant *targetConstant = currGlobal->getInitializer();
        ConstantStruct *actualStType = dyn_cast<ConstantStruct>(targetConstant);
        if(actualStType != nullptr) {
            for (unsigned int i=0; i<actualStType->getNumOperands();i++) {
                Value *op = actualStType->getOperand(i);
                if (Function *f_op = dyn_cast<Function>(op)) {
                    if (f_op->hasName()) {
                        std::string f_name = f_op->getName().str();
                        std::transform(f_name.begin(), f_name.end(), f_name.begin(), ::tolower);
                        // dbgs() << "Operand " << i << ": "<< f_op->getName() <<"\n";
                        // get entrypoints by string match
                        // more precise than raw difuze which use hard code offset to find entrypoint
                        if (f_name.find("read") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, READ_HDR);
                        else if (f_name.find("write") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, WRITE_HDR);
                        else if (f_name.find("ioctl") != f_name.npos)
                            printTriFuncVal(actualStType->getOperand(i), outputFile, IOCTL_HDR);
                        else if (f_name.find("open") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, OPEN_HDR);
                        else if (f_name.find("mmap") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, MMAP_HDR);
                        else if (f_name.find("release") != f_name.npos || f_name.find("close") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, RELEASE_HDR);
                        else if (f_name.find("poll") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, POLL_HDR);
                        else if (f_name.find("show") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, DEVATTR_SHOW);
                        else if (f_name.find("store") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, DEVATTR_STORE);
                    }
                }
            }
        }
    }
}

void process_v4l2_ioctl_st(GlobalVariable *currGlobal, FILE *outputFile) {
    if(currGlobal->hasInitializer()) {

        // get the initializer.
        Constant *targetConstant = currGlobal->getInitializer();
        ConstantStruct *actualStType = dyn_cast<ConstantStruct>(targetConstant);
        if(actualStType != nullptr) {
            // all fields are function pointers
            for (unsigned int i = 0; i < actualStType->getNumOperands(); i++) {
                Value *currFieldVal = actualStType->getOperand(i);
                Function *targetFunction = dyn_cast<Function>(currFieldVal);
                if (targetFunction != nullptr && !targetFunction->isDeclaration() && targetFunction->hasName()) {
                    fprintf(outputFile, "%s:%s:%u:%s\n", V4L2_IOCTL_FUNC, targetFunction->getName().str().c_str(), i,
                            getFunctionFileName(targetFunction).c_str());
                }
            }
        }

    }
}

void process_v4l2_file_ops_st(GlobalVariable *currGlobal, FILE *outputFile) {
    if(currGlobal->hasInitializer()) {
        // get the initializer.
        Constant *targetConstant = currGlobal->getInitializer();
        ConstantStruct *actualStType = dyn_cast<ConstantStruct>(targetConstant);
        if(actualStType != nullptr) {
            
            for (unsigned int i=0; i<actualStType->getNumOperands();i++) {
                Value *op = actualStType->getOperand(i);
                if (Function *f_op = dyn_cast<Function>(op)) {
                    if (f_op->hasName()) {
                        std::string f_name = f_op->getName().str();
                        std::transform(f_name.begin(), f_name.end(), f_name.begin(), ::tolower);
                        // get entrypoints by string match
                        // more precise than raw difuze which use hard code offset to find entrypoint
                        if (f_name.find("read") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, READ_HDR);
                        else if (f_name.find("write") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, WRITE_HDR);
                        else if (f_name.find("ioctl") != f_name.npos)
                            printTriFuncVal(actualStType->getOperand(i), outputFile, IOCTL_HDR);
                        else if (f_name.find("open") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, OPEN_HDR);
                        else if (f_name.find("mmap") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, MMAP_HDR);
                        else if (f_name.find("release") != f_name.npos || f_name.find("close") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, RELEASE_HDR);
                        else if (f_name.find("poll") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, POLL_HDR);
                        else if (f_name.find("show") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, DEVATTR_SHOW);
                        else if (f_name.find("store") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, DEVATTR_STORE);
                    }
                }
            }
        }
    }
}

void process_atmdev_ops_st(GlobalVariable *currGlobal, FILE *outputFile) {
    if(currGlobal->hasInitializer()) {
        // get the initializer.
        Constant *targetConstant = currGlobal->getInitializer();
        ConstantStruct *actualStType = dyn_cast<ConstantStruct>(targetConstant);
        if(actualStType != nullptr) {
            
            for (unsigned int i=0; i<actualStType->getNumOperands();i++) {
                Value *op = actualStType->getOperand(i);
                if (Function *f_op = dyn_cast<Function>(op)) {
                    if (f_op->hasName()) {
                        std::string f_name = f_op->getName().str();
                        std::transform(f_name.begin(), f_name.end(), f_name.begin(), ::tolower);
                        // get entrypoints by string match
                        // more precise than raw difuze which use hard code offset to find entrypoint
                        if (f_name.find("read") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, READ_HDR);
                        else if (f_name.find("write") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, WRITE_HDR);
                        else if (f_name.find("ioctl") != f_name.npos)
                            printTriFuncVal(actualStType->getOperand(i), outputFile, IOCTL_HDR);
                        else if (f_name.find("open") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, OPEN_HDR);
                        else if (f_name.find("mmap") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, MMAP_HDR);
                        else if (f_name.find("release") != f_name.npos || f_name.find("close") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, RELEASE_HDR);
                        else if (f_name.find("poll") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, POLL_HDR);
                        else if (f_name.find("show") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, DEVATTR_SHOW);
                        else if (f_name.find("store") != f_name.npos)
                            printFuncVal(actualStType->getOperand(i), outputFile, DEVATTR_STORE);
                    }
                }
            }
        }
    }
}

char** str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = (char**)malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}

bool process_struct_in_custom_entry_files(GlobalVariable *currGlobal, FILE *outputFile,
                                          std::vector<string> &allentries) {
    bool retVal = false;
    if(currGlobal->hasInitializer()) {
        // get the initializer.
        Constant *targetConstant = currGlobal->getInitializer();
        ConstantStruct *actualStType = dyn_cast<ConstantStruct>(targetConstant);
        if(actualStType != nullptr) {
            Type *targetType = currGlobal->getType();
            assert(targetType->isPointerTy());
            Type *containedType = targetType->getContainedType(0);
            std::string curr_st_name = containedType->getStructName().str();
            char hello_str[1024];
            for (auto curre:allentries) {
                if (curre.find(curr_st_name) != std::string::npos) {
                    strcpy(hello_str, curre.c_str());
                    // structure found
                    char **tokens = str_split(hello_str, ',');
                    assert(!strcmp(curr_st_name.c_str(), tokens[0]));
                    long ele_ind = strtol(tokens[1], NULL, 10);
                    if (actualStType->getNumOperands() > ele_ind) {
                        Value *currFieldVal = actualStType->getOperand(ele_ind);
                        Function *targetFunction = dyn_cast<Function>(currFieldVal);

                        if (targetFunction != nullptr && !targetFunction->isDeclaration() &&
                            targetFunction->hasName()) {
                            fprintf(outputFile, "%s:%s:%s\n", tokens[2], targetFunction->getName().str().c_str(),
                                    getFunctionFileName(targetFunction).c_str());
                        }
                    }
                    if (tokens) {
                        int i;
                        for (i = 0; *(tokens + i); i++) {
                            free(*(tokens + i));
                        }
                        free(tokens);
                    }
                    retVal = true;
                }
            }
        }

    }
    return retVal;
}

void process_global(GlobalVariable *currGlobal, FILE *outputFile, std::vector<string> &allentries) {
    std::string file_op_st("struct.file_operations");
    std::string dev_attr_st("struct.device_attribute");
    std::string dri_attr_st("struct.driver_attribute");
    std::string bus_attr_st("struct.bus_attribute");
    std::string net_dev_st("struct.net_device_ops");
    std::string snd_pcm_st("struct.snd_pcm_ops");
    std::string v4l2_ioctl_st("struct.v4l2_ioctl_ops");
    std::string v4l2_file_ops_st("struct.v4l2_file_operations");
    std::string atmdev_ops_st("atmdev_ops");
    std::string tty_ops_st("tty_operations");

#ifdef DIFUZE_DEBUG
    dbgs() << "Current Global Varibale\n";
    currGlobal->dump();
#endif
    Type *targetType = currGlobal->getType();
    assert(targetType->isPointerTy());
    Type *containedType = targetType->getContainedType(0);
#ifdef DIFUZE_DEBUG
    dbgs() << "containedType: " << *(containedType) << "\n";
    dbgs() << "Is a contant? " << currGlobal->isConstant() << " " << isa<ConstantStruct>(currGlobal) << "\n";
#endif
    if (containedType->isStructTy()) {
        StructType *targetSt = dyn_cast<StructType>(containedType);
        if(targetSt->isLiteral()) {
            return;
        }
        if(process_struct_in_custom_entry_files(currGlobal, outputFile, allentries)) {
            return;
        }
#ifdef DIFUZE_DEBUG
        dbgs() << "is StructTy: \n";
        dbgs() << containedType->getStructName() << "\n";
#endif
        std::string struct_name = containedType->getStructName().str();        
        if (struct_name.find(file_op_st) != struct_name.npos) {
            process_file_operations_st(currGlobal, outputFile);
        } else if(struct_name.find(dev_attr_st) != struct_name.npos || struct_name.find(dri_attr_st) != struct_name.npos) {
            process_device_attribute_st(currGlobal, outputFile);
        } else if(struct_name.find(net_dev_st) != struct_name.npos) {
            process_netdev_st(currGlobal, outputFile);
        } else if(struct_name.find(snd_pcm_st) != struct_name.npos) {
            process_snd_pcm_ops_st(currGlobal, outputFile);
        } else if(struct_name.find(v4l2_file_ops_st) != struct_name.npos) {
            process_v4l2_file_ops_st(currGlobal, outputFile);
        } else if(struct_name.find(v4l2_ioctl_st) != struct_name.npos) {
            process_v4l2_ioctl_st(currGlobal, outputFile);
        } else if(struct_name.find(atmdev_ops_st) != struct_name.npos) {
            process_atmdev_ops_st(currGlobal, outputFile);
        } else if(struct_name.find(tty_ops_st) != struct_name.npos) {
            process_file_operations_st(currGlobal, outputFile);
        } else {
            process_file_operations_st(currGlobal, outputFile);
        }
    }
}

int main(int argc, char *argv[]) {
    //check args
    if(argc < 3) {
        print_err(argv[0]);
    }

    char *src_llvm_file = argv[1];
    // final_to_check.bc.all_entries
    char *output_txt_file = argv[2];
    // hdr_file_config.txt
    char *entry_point_file = NULL;
    std::vector<string> entryPointStrings;
    entryPointStrings.clear();
    if(argc > 3) {
        entry_point_file = argv[3];
        std::ifstream infile(entry_point_file);
        std::string line;
        while (std::getline(infile, line)) {
            entryPointStrings.push_back(line);
        }
    }



    FILE *outputFile = fopen(output_txt_file, "w");
    assert(outputFile != nullptr);

    LLVMContext context;
    ErrorOr<std::unique_ptr<MemoryBuffer>> fileOrErr = MemoryBuffer::getFileOrSTDIN(src_llvm_file);

    // ErrorOr<std::unique_ptr<llvm::Module>> moduleOrErr = parseBitcodeFile(fileOrErr.get()->getMemBufferRef(), context);
    llvm::Expected<std::unique_ptr<llvm::Module>> moduleOrErr = llvm::parseBitcodeFile(fileOrErr.get()->getMemBufferRef(), context);

    if (std::error_code ec = errorToErrorCode(moduleOrErr.takeError())) {
        std::cout << "[-] Error reading module " << src_llvm_file << std::endl;
        abort();
    }
    if (moduleOrErr.get().get() == nullptr) {
        std::cout << "[-] Error reading module: " << src_llvm_file << std::endl;
        abort();
    }

    Module *m = moduleOrErr.get().get();

    Module::GlobalListType &currGlobalList = m->getGlobalList();
    for(Module::global_iterator gstart = currGlobalList.begin(), gend = currGlobalList.end(); gstart != gend; gstart++) {
        GlobalVariable *currGlobal = &(*gstart);
        process_global(currGlobal, outputFile, entryPointStrings);
    }
    fclose(outputFile);
}
