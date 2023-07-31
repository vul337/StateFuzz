//
// Created by machiry on 4/26/17.
//

#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/ValueSymbolTable.h"
#include <iostream>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/LoopInfo.h>
#include "llvm/Analysis/CFGPrinter.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/Module.h"
//#include "RangePass.h"
//#include "RangeAnalysis.h"
#include "CFGUtils.h"
#include "FileUtils.h"
#include "IOInstVisitor.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/CommandLine.h"
#include "TypePrintHelper.h"

// #define DIFUZE_DEBUG 1

using namespace llvm;
using namespace std;

namespace IOCTL_CHECKER {


    static cl::opt<std::string> checkFunctionName("ioctlFunction",
                                                  cl::desc("Function which is to be considered as entry point "
                                                                   "into the driver"),
                                                  cl::value_desc("full name of the function"), cl::init(""));

    static cl::opt<std::string> bitcodeOutDir("bcOutDir",
                                              cl::desc("Base path where LLVM output is produced."),
                                              cl::value_desc("Absolute path to the directory "
                                                             "containing the complete bitcode."),
                                              cl::init(""));

    static cl::opt<std::string> srcBaseDir("srcBaseDir",
                                           cl::desc("Base path of the kernel sources."),
                                           cl::value_desc("Absolute path to the directory "
                                                          "containing the linux source code."),
                                           cl::init(""));


    struct IoctlCmdCheckerPass: public ModulePass {
    public:
        static char ID;
        //GlobalState moduleState;

        IoctlCmdCheckerPass() : ModulePass(ID) {
        }

        ~IoctlCmdCheckerPass() {
        }

        bool runOnModule(Module &m) override {
            dbgs() << "Provided Function Name:" << checkFunctionName << "\n";
            std::set<string> all_c_preprocessed_files;

            handleArrayTypeIoctl(m);
            // return 0;
            //unimelb::WrappedRangePass &range_analysis = getAnalysis<unimelb::WrappedRangePass>();
            for(Module::iterator mi = m.begin(), ei = m.end(); mi != ei; mi++) {
                std::string tmpFilePath;
                std::string includePrefix = ".includes";
                std::string preprocessedPrefix = ".preprocessed";

                Function &currFunction = *mi;
                SmallVector<std::pair<unsigned, MDNode *>, 4> MDs;
                std::string targetFName;
                currFunction.getAllMetadata(MDs);
                //遍历函数的详细信息，找到需要预先处理的IR文件
                // parse metadata from functions, find IR files need to handle first
                for (auto &MD : MDs) {
                    if (MDNode *N = MD.second) {
                        if (auto *subProgram = dyn_cast<DISubprogram>(N)) {
                            targetFName = subProgram->getFilename().str();
                            tmpFilePath = FileUtils::getNewRelativePath(srcBaseDir, targetFName, bitcodeOutDir, preprocessedPrefix);
                            if(all_c_preprocessed_files.find(tmpFilePath) == all_c_preprocessed_files.end()) {
                                all_c_preprocessed_files.insert(tmpFilePath);
                            }
                            break;
                        }
                    }
                }
                //if the current function is the target function.
                if(!currFunction.isDeclaration() && currFunction.hasName() &&
                   currFunction.getName().str() == checkFunctionName) {
                    TypePrintHelper::setFoldersPath(srcBaseDir, bitcodeOutDir);
                    TypePrintHelper::addRequiredFile(currFunction.getEntryBlock().getFirstNonPHIOrDbg());

                    for (auto &MD : MDs) {
                        // find files and including head files need to handle first
                        if (MDNode *N = MD.second) {
                            if (auto *subProgram = dyn_cast<DISubprogram>(N)) {
                                targetFName = subProgram->getFilename().str();
                                tmpFilePath = FileUtils::getNewRelativePath(srcBaseDir, targetFName, bitcodeOutDir, preprocessedPrefix);
                                if(TypePrintHelper::requiredPreprocessingFiles.find(tmpFilePath) == TypePrintHelper::requiredPreprocessingFiles.end()) {
                                    TypePrintHelper::requiredPreprocessingFiles.insert(tmpFilePath);
                                }
                                tmpFilePath = FileUtils::getNewRelativePath(srcBaseDir, targetFName, bitcodeOutDir, includePrefix);
                                if(TypePrintHelper::requiredIncludeFiles.find(tmpFilePath) == TypePrintHelper::requiredIncludeFiles.end()) {
                                    TypePrintHelper::requiredIncludeFiles.insert(tmpFilePath);
                                }
                                break;
                            }
                        }
                    }

                    // puts analysis result into these functions
                    std::set<int> cArg;
                    std::set<int> uArg;
                    std::vector<Value*> callStack;
                    std::map<unsigned, Value*> callerArguments;
                    cArg.insert(1);
                    uArg.insert(2);
                    callerArguments.clear();
                    IOInstVisitor *currFuncVis = new IOInstVisitor(&currFunction, cArg, uArg, callerArguments,
                                                                   callStack, nullptr, 0);
                    // start analyzing target function
                    currFuncVis->analyze();
                    for(auto a:TypePrintHelper::requiredIncludeFiles) {
                        dbgs() << "Includes file:" << a << "\n";
                    }
                    for(auto a:TypePrintHelper::requiredPreprocessingFiles) {
                        dbgs() << "Preprocessed file:" << a << "\n";
                    }
                    dbgs() << "ALL PREPROCESSED FILES:\n";
                    for(auto a:all_c_preprocessed_files) {
                        dbgs() << "Compl Preprocessed file:" << a << "\n";
                    }
                }
            }
            return false;
        }



        void getAnalysisUsage(AnalysisUsage &AU) const override {
            AU.setPreservesAll();
            //AU.addRequired<InterProceduralRA<CropDFS>>();
            AU.addRequired<CallGraphWrapperPass>();
            AU.addRequired<LoopInfoWrapperPass>();
            //AU.addRequired<unimelb::WrappedRangePass>();
        }

        Function* getFinalFuncTarget(CallInst *I) {
            if(I->getCalledFunction() == nullptr) {
                Value *calledVal = I->getCalledOperand();
                if(!dyn_cast<Function>(calledVal)) {
                    return dyn_cast<Function>(calledVal->stripPointerCasts());
                }
                return dyn_cast<Function>(calledVal);
            }
            return I->getCalledFunction();
        }

        // void handleArrayTypeArgType(Function *F) {
        //     for (auto BB:F) {
        //         for (auto I:BB) {
        //             CallInst *CI = dyn_cast<CallInst>(I);
        //             if (CI) {
        //                 Function *dstFunc = this->getFinalFuncTarget(&I);
        //                 if(dstFunc != nullptr) {
        //                     if(dstFunc->isDeclaration()) {
        //                         if(dstFunc->hasName()) {
        //                             string calledfunc = I.getCalledFunction()->getName().str();
        //                             Value *targetOperand = nullptr;
        //                             Value *srcOperand = nullptr;
        //                             if(calledfunc.find("_copy_from_user") != string::npos) {
        //                                 //dbgs() << "copy_from_user:\n";
        //                                 if(I.getNumArgOperands() >= 1) {
        //                                     targetOperand = I.getArgOperand(0);
        //                                 }
        //                                 if(I.getNumArgOperands() >= 2) {
        //                                     srcOperand = I.getArgOperand(1);
        //                                 }
        //                             }
        //                             if(calledfunc.find("_copy_to_user") != string::npos) {
        //                                 // some idiot doesn't know how to parse
        //                                 /*dbgs() << "copy_to_user:\n";
        //                                 srcOperand = I.getArgOperand(0);
        //                                 targetOperand = I.getArgOperand(1);*/
        //                             }
        //                             if(targetOperand != nullptr) {
        //                                 TypePrintHelper::typeOutputHandler(targetOperand, dbgs(), this);
        //                             }
        //                         }
        //                     }
        //                 }
        //             }
        //         }
        //     }
        // }

        void handleArrayTypeIoctl(Module &m) {
            Module::GlobalListType &currGlobalList = m.getGlobalList();
            for(Module::global_iterator gstart = currGlobalList.begin(), gend = currGlobalList.end(); gstart != gend; gstart++) {
                GlobalVariable *currGlobal = &(*gstart);
                if (currGlobal == nullptr)
                    continue; 
                if (!currGlobal->hasInitializer())
                    continue;
                Type *targetType = currGlobal->getType();
                if (!(targetType->isPointerTy()))
                    continue;
                Type *containedType = targetType->getContainedType(0);
                if (!containedType->isArrayTy())
                    continue;
                std::string gv_str;
                llvm::raw_string_ostream gv_rso(gv_str);
                gv_rso << *(currGlobal);
                gv_str = gv_rso.str();
                if (gv_str.find("ioctl") == gv_str.npos || gv_str.find("_compat_") != gv_str.npos || gv_str.find("_compat.") != gv_str.npos) {
#ifdef DIFUZE_DEBUG
                dbgs() << "Non-ioctl-related OR compat-ioctl, discard\n";
#endif
                    continue;
                }
#ifdef DIFUZE_DEBUG
    dbgs() << "Current Global Varibale\n";
    // currGlobal->dump();
    dbgs() << "Type: " << (*containedType) << "\n";
#endif
#ifdef DIFUZE_DEBUG
                dbgs() << "Is ArrayTy Global Varibale\n";
#endif
                Constant *targetConstant = currGlobal->getInitializer();
                ConstantArray *actualStType = dyn_cast<ConstantArray>(targetConstant);
                if (actualStType != nullptr) {
                    if (actualStType->getNumOperands() > 200) {
#ifdef DIFUZE_DEBUG
                        dbgs() << "Too many elements, discard\n";
#endif
                        continue;
                    }
#ifdef DIFUZE_DEBUG
                    dbgs() << "actualStType->dump(): \n";
                    actualStType->dump();
#endif
                    std::map<int, std::set<uint64_t>> candidate_cmds;
                    unsigned offset, max_tmp=0;
                    Value *member, *arrayItem;
                    Type *memberType;
                    Function *f;
                    ConstantStruct *ioctlCmdStruct;
                    ConstantInt *CI;
                    bool hasFunc = false;
                    // cmds are rarely duplicate
                    // now we are finding cmds' offset
                    for (unsigned i = 0, e = actualStType->getNumOperands(); i != e; ++i) {
                        Value *arrayItem = actualStType->getOperand(i);
                        ioctlCmdStruct = dyn_cast<ConstantStruct>(arrayItem);
                        if (ioctlCmdStruct) {
#ifdef DIFUZE_DEBUG
                            dbgs() << "element "<< i <<" is ConstantStruct \n";
#endif
                            hasFunc = false;
                            for (unsigned j = 0, ste = ioctlCmdStruct->getNumOperands(); j != ste; ++j) {
                                member = ioctlCmdStruct->getOperand(j);
#ifdef DIFUZE_DEBUG
                                dbgs() << "member "<< j << " " << *(member) << "\n";
                                dbgs() << "member "<< j << " type: is " << *(member->getType()) << "\n";
#endif
                                f = dyn_cast<Function>(member);
                                if (!f)
                                    f = dyn_cast<Function>(member->stripPointerCasts());
                                if (f) {
#ifdef DIFUZE_DEBUG
                                  dbgs() << "member "<< j << " type: is function pointer !\n";
#endif
                                  hasFunc = true;
                                  break;
                                }
                            }
                            if (!hasFunc) continue;
#ifdef DIFUZE_DEBUG
                            dbgs() << "element "<< i <<" has function pointer\n";
#endif
                            for (unsigned j = 0, ste = ioctlCmdStruct->getNumOperands(); j != ste; ++j) {
                                member = ioctlCmdStruct->getOperand(j);
                                memberType = member->getType();
                                if (memberType->isIntegerTy()) {
#ifdef DIFUZE_DEBUG
                                  dbgs() << "element "<< i <<" has int member: " << j << "\n";
#endif
                                  CI = dyn_cast<ConstantInt>(member);
                                  uint64_t CI_uint64 = CI->getValue().getZExtValue();
                                  if (candidate_cmds.count(j) == 0) {
                                    std::set<uint64_t> new_s;
                                    new_s.insert(CI_uint64);
                                    candidate_cmds[j] = new_s; 
                                  } else if (candidate_cmds[j].count(CI_uint64) == 0) {
                                    candidate_cmds[j].insert(CI_uint64);
                                  }
                                }
                            }
                        }
                    }
                    for (auto iter = candidate_cmds.begin(); iter != candidate_cmds.end(); iter++) {
#ifdef DIFUZE_DEBUG
                        llvm::outs() << "find cmd offset, candidate_cmds:  " << iter->first << " : " << iter->second.size() << "\n";
#endif
                        if (iter->second.size() > max_tmp) {
                            max_tmp = iter->second.size();
                            offset = iter->first;
#ifdef DIFUZE_DEBUG
                            llvm::outs() << "new offset:  " << offset << "\n";
#endif
                        }
                    }
                    if (max_tmp == 0)
                        continue;
                    for (unsigned i = 0, e = actualStType->getNumOperands(); i != e; ++i) {
                        arrayItem = actualStType->getOperand(i);
                        ioctlCmdStruct = dyn_cast<ConstantStruct>(arrayItem);
                        if (ioctlCmdStruct) {
                            hasFunc = false;
                            for (unsigned j = 0, ste = ioctlCmdStruct->getNumOperands(); j != ste; ++j) {
                                member = ioctlCmdStruct->getOperand(j);
                                f = dyn_cast<Function>(member);
                                if (!f)
                                    f = dyn_cast<Function>(member->stripPointerCasts());
                                if (f) {
                                  hasFunc = true;
                                  break;
                                }
                            }
                            if (!hasFunc) continue;
                            ConstantInt *cmd_value = nullptr;
                            Function *function_value = nullptr;
                            for (unsigned j = 0, ste = ioctlCmdStruct->getNumOperands(); j != ste; ++j) {
                                member = ioctlCmdStruct->getOperand(j);
                                memberType = member->getType();
                                if (memberType->isIntegerTy() && j == offset) {
                                    CI = dyn_cast<ConstantInt>(member);
#ifdef DIFUZE_DEBUG
                                    dbgs() << "Cmd: " << "  " << *(CI)  << "\n";
#endif
                                    if (cmd_value != nullptr) {
                                        dbgs() << "Cmd conflict! : " << "  " << *(CI)  << "\n";
                                    }
                                    cmd_value = CI;
                                    continue;
                                } else {
                                    f = dyn_cast<Function>(member);
                                    if (!f)
                                        f = dyn_cast<Function>(member->stripPointerCasts());
                                    if (f) {
#ifdef DIFUZE_DEBUG
                                        dbgs() << "Function: " << "  " << f->getName()  << "\n";
#endif
                                        if (function_value != nullptr) {
                                            dbgs() << "Function conflict! : " << "  " << f->getName()  << "\n";
                                        }
                                        function_value = f;
                                        continue;
                                    }
                                }
#ifdef DIFUZE_DEBUG
                                dbgs() << "element " << j << "  " << *(ioctlCmdStruct->getOperand(j))  << "\n";
#endif
                            }
                            if (cmd_value != nullptr && function_value != nullptr) {
                                dbgs() << "Found Cmd:" << cmd_value->getValue().getZExtValue() << ":START\n";
                                dbgs() << "Find callsite, called function name: " << function_value->getName() << "\n";
                                // handleArrayTypeArgType(function_value);
                                int arg_no = 0;
                                int carg_no, uarg_no;
                                for(Function::arg_iterator farg_begin = function_value->arg_begin(), farg_end = function_value->arg_end();
                                    farg_begin != farg_end; farg_begin++) {
                                    std::string arg_str;
                                    llvm::raw_string_ostream rso(arg_str);
                                    rso << *(farg_begin);
                                    arg_str = rso.str();
                                    if (arg_str.find("i32 %cmd") != arg_str.npos)
                                        carg_no = arg_no;
                                    if (arg_str.find("%arg") != arg_str.npos)
                                        uarg_no = arg_no;
                                    arg_no++;
                                }
                                std::set<int> cArg;
                                std::set<int> uArg;
                                std::vector<Value*> callStack;
                                std::map<unsigned, Value*> callerArguments;
                                cArg.insert(carg_no);
                                uArg.insert(uarg_no);
                                callerArguments.clear();
                                IOInstVisitor *currFuncVis = new IOInstVisitor(function_value, cArg, uArg, callerArguments,
                                                                               callStack, nullptr, 0);
#ifdef DIFUZE_DEBUG
                                dbgs() <<  "currFuncVis->analyze() in handleArrayTypeIoctl Start\n";
#endif
                                currFuncVis->analyze();
#ifdef DIFUZE_DEBUG
                                dbgs() <<  "currFuncVis->analyze() in handleArrayTypeIoctl End\n";
#endif
                                dbgs() << "Found Cmd:" << cmd_value->getValue().getZExtValue() << ":END\n";
                            }
                        }
                    }
                }
            }
        }
    private:



    };

    char IoctlCmdCheckerPass::ID = 0;
    static RegisterPass<IoctlCmdCheckerPass> x("new-ioctl-cmd-parser", "IOCTL Command Parser", false, true);
}