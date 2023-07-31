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
//#include "IOInstVisitor.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "TypePrintHelper.h"
#include <llvm/IR/Operator.h>

// #define DIFUZE_DEBUG 1
#define MAX_RECURSIVE_DEPTH 50

typedef std::tuple<Value *, std::string, bool> trace_tuple;
std::set<trace_tuple> visitedVals;
std::set<Value *> trackedVals;

using namespace llvm;
using namespace std;

namespace IOCTL_CHECKER {


    static cl::opt<std::string> checkFunctionName("ioctlFunction",
                                                  cl::desc("Function whose device name need to be identified."),
                                                  cl::value_desc("full name of the function"), cl::init(""));


    struct DeviceNameFinderPass: public ModulePass {
    public:
        static char ID;
        //GlobalState moduleState;

        DeviceNameFinderPass() : ModulePass(ID) {
        }

        ~DeviceNameFinderPass() {
        }

        bool isCalledFunction(CallInst *callInst, std::string &funcName) {
            Function *targetFunction = nullptr;
            if(callInst != nullptr) {
                targetFunction = callInst->getCalledFunction();
                if(targetFunction == nullptr) {
                   targetFunction = dyn_cast<Function>(callInst->getCalledOperand()->stripPointerCasts());
                }
            }
            return (targetFunction != nullptr && targetFunction->hasName() &&
                    targetFunction->getName() == funcName);
        }

        llvm::GlobalVariable *getSrcTrackedVal(Value *currVal, int depth) {
#ifdef DIFUZE_DEBUG
            if (currVal != nullptr)
                dbgs() << "currVal " << *currVal << "\n";
#endif
            if (trackedVals.count(currVal) != 0)
                return nullptr;
            if (depth > MAX_RECURSIVE_DEPTH)
                return nullptr;
            llvm::GlobalVariable *currGlob = dyn_cast<llvm::GlobalVariable>(currVal);
            if(currGlob == nullptr) {
                Instruction *currInst = dyn_cast<Instruction>(currVal);
                if(currInst != nullptr) {
                    for(unsigned int i=0; i < currInst->getNumOperands(); i++) {
                        Value *currOp = currInst->getOperand(i);
                        if (currOp == nullptr)
                            continue;
                        llvm::GlobalVariable *opGlobVal = getSrcTrackedVal(currOp, depth+1);
                        if(opGlobVal == nullptr) {
                            opGlobVal = getSrcTrackedVal(currOp->stripPointerCasts(), depth+1);
                        }
                        if(opGlobVal != nullptr) {
                            currGlob = opGlobVal;
                            break;
                        }
                    }
                } else {
                    trackedVals.insert(currVal);
                    return nullptr;
                }
            }
            trackedVals.insert(currVal);
            return currGlob;
        }

        // added by sgh0t
        std::set<Value *> getSrcTrackedVal_Local(Value *currVal, int depth) {
            std::set<Value *> returnSet;
            if (depth > MAX_RECURSIVE_DEPTH)
                return returnSet;
            returnSet.clear();
            returnSet.insert(currVal);
            Instruction *currInst = dyn_cast<Instruction>(currVal);
            if(currInst != nullptr) {
                for(unsigned int i=0; i < currInst->getNumOperands(); i++) {
                    Value *currOp = currInst->getOperand(i);
                    std::set<Value *> opVal_set = getSrcTrackedVal_Local(currOp, depth+1);
                    std::set<Value *> opVal_set_cast = getSrcTrackedVal_Local(currOp->stripPointerCasts(), depth+1);
                    if(opVal_set.empty() == false) {
                        returnSet.insert(opVal_set.begin(), opVal_set.end());
                    }
                    if(opVal_set_cast.empty() == false) {
                        returnSet.insert(opVal_set_cast.begin(), opVal_set_cast.end());
                    }
                }
            }
            else if (currVal != nullptr) {
                Type *ty = currVal->getType();
                while (ty != nullptr && ty->isPointerTy()) {
                    ty = ty->getContainedType(0);
                }
                if (ty != nullptr && ty->isStructTy())
                    returnSet.insert(currVal);
            }
            return returnSet;
        }

        llvm::AllocaInst *getSrcTrackedAllocaVal(Value *currVal) {
            //dbgs() <<"dada:" << *currVal << "\n";
            llvm::AllocaInst *currGlob = dyn_cast<AllocaInst>(currVal);
            if(currGlob == nullptr) {
                Instruction *currInst = dyn_cast<Instruction>(currVal);
                if(currInst != nullptr) {
                    for(unsigned int i=0; i < currInst->getNumOperands(); i++) {
                        Value *currOp = currInst->getOperand(i);
                        llvm::AllocaInst *opGlobVal = getSrcTrackedAllocaVal(currOp);
                        if(opGlobVal == nullptr) {
                            opGlobVal = getSrcTrackedAllocaVal(currOp->stripPointerCasts());
                        }
                        if(opGlobVal != nullptr) {
                            currGlob = opGlobVal;
                            break;
                        }
                    }
                } else {
                    return nullptr;
                }
            }
            return currGlob;
        }

        llvm::Value *getSrcTrackedArgVal(Value *currVal, Function *targetFunction) {
            //dbgs() <<"dada:" << *currVal << "\n";
            Instruction *currInst = dyn_cast<Instruction>(currVal);
            if (currInst == nullptr) {
                for(auto a = targetFunction->arg_begin(), ae = targetFunction->arg_end();
                  a != ae; a++) {
                    if (&(*a) == currVal) {
                        return &(*a);
                    }
                }
            } else {

                for (unsigned int i = 0; i < currInst->getNumOperands(); i++) {
                    Value *currOp = currInst->getOperand(i);
                    llvm::Value *opGlobVal = getSrcTrackedArgVal(currOp, targetFunction);
                    if (opGlobVal == nullptr) {
                        opGlobVal = getSrcTrackedArgVal(currOp->stripPointerCasts(), targetFunction);
                    }
                    if (opGlobVal != nullptr) {
                        return opGlobVal;
                    }
                }
            }
            return nullptr;

        }

        bool getDeviceString(Value *currVal) {
            const GEPOperator *gep = dyn_cast<GEPOperator>(currVal);
            const llvm::GlobalVariable *strGlobal = nullptr;
            if(gep != nullptr) {
                 strGlobal = dyn_cast<GlobalVariable>(gep->getPointerOperand());

            }
            if (strGlobal != nullptr && strGlobal->hasInitializer()) {
                const Constant *currConst = strGlobal->getInitializer();
                const ConstantDataArray *currDArray = dyn_cast<ConstantDataArray>(currConst);
                std::string dev_name;
                llvm::raw_string_ostream os(dev_name);
                bool valid_dev_name = false;
                if(currDArray != nullptr) {
#ifdef DIFUZE_DEBUG
                    dbgs() << "dev_string: " << currDArray->getAsCString() << "\n";
#endif
                    if (currDArray->getAsCString().find("%s") == currDArray->getAsCString().npos) {
                        valid_dev_name = true;
                        dbgs() << "[+] Device Name: " << currDArray->getAsCString() << "\n";
                    }
                } else {
                    os << *currConst;
                    dev_name = os.str();
#ifdef DIFUZE_DEBUG
                    dbgs() << "dev_string: " << *currConst << "\n";
#endif
                    if (dev_name.find("%s") == dev_name.npos) {
                        valid_dev_name = true;
                        dbgs() << "[+] Device Name: " << *currConst << "\n";
                    }
                }
                return valid_dev_name;
            }
            return false;
        }

        // check if a == b or a is one of b's users to avoid duplicate analysis
        bool isSrcOrDest(Value *a, Value *b) {
            if (a == b) return true;
            for (auto u:b->users())
            {
                if (u==a)
                    return true;
            }
            return false;
        }

        // find the CallInst with data-flow analysis
        // important flag used to 
        CallInst *getRecursiveCallInst(Value *srcVal, std::string &targetFuncName, bool important=false) {
            CallInst *currInst = nullptr;
            trace_tuple trace_tuple_tmp = std::make_tuple(srcVal, targetFuncName, important);
            
            if(srcVal != nullptr) {
                currInst = dyn_cast<CallInst>(srcVal);
                if (currInst != nullptr) {
                    if (isCalledFunction(currInst, targetFuncName)) {
                        return currInst;
                    }
                }
            }

            if(visitedVals.find(trace_tuple_tmp) != visitedVals.end()) {
                return nullptr;
            }
            if (srcVal != nullptr) {
                if (ConstantInt *srcVal_constantint = dyn_cast<ConstantInt>(srcVal)) {
                    return nullptr;
                }
            }

            visitedVals.insert(trace_tuple_tmp);
            for(auto curr_use:srcVal->users()) {
                currInst = dyn_cast<CallInst>(curr_use);
                if(currInst && isCalledFunction(currInst, targetFuncName)) {
                    break;
                }
                currInst = nullptr;
            }
            if(currInst == nullptr) {
                for(auto curr_use:srcVal->users()) {
                    currInst = getRecursiveCallInst(curr_use, targetFuncName);
                    if(currInst && isCalledFunction(currInst, targetFuncName)) {
                        break;
                    }
                    currInst = nullptr;
                }
            }

            if (currInst == nullptr) {
                // only focus on variables related to cdev_init
                bool isImportant = false;
                if (important == true)
                    isImportant = important;
                else {
                    for (auto curr_use : srcVal->users()) {
                        if (CallInst *tmp_callinst = dyn_cast<CallInst>(curr_use)) {
                            if (tmp_callinst->getCalledFunction() != nullptr && 
                              tmp_callinst->getCalledFunction()->hasName()) {
                                // dbgs() << "FName: " << tmp_callinst->getCalledFunction()->getName() << "\n";
                                if ( tmp_callinst->getCalledFunction()->getName().compare("cdev_init") == 0 ||
                                  tmp_callinst->getCalledFunction()->getName().compare("cdev_add") == 0  ||
                                  tmp_callinst->getCalledFunction()->getName().compare("cdev_device_add") == 0
                                )
                                {
                                    isImportant = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                // trace variables which are src of paras at current function's callsite
                if (!isImportant)
                    return currInst;
                if (Instruction *tmp_i = dyn_cast<Instruction>(srcVal))
                    for (int i = 0; i < tmp_i->getNumOperands(); i++) {
                        if (Constant *tmp_c = dyn_cast<Constant>(tmp_i->getOperand(i)))
                            continue;
                        currInst = getRecursiveCallInst(tmp_i->getOperand(i), targetFuncName, true);
                    }
                if (currInst == nullptr) {
                    for(auto curr_use:srcVal->users()) {
                        Instruction *i = dyn_cast<Instruction>(curr_use);
                        if (i) {
                            if (LoadInst *load_i = dyn_cast<LoadInst>(i))
                                getRecursiveCallInst(load_i->getOperand(0), targetFuncName, true);
                            if (GetElementPtrInst *gep_i = dyn_cast<GetElementPtrInst>(i))
                                getRecursiveCallInst(gep_i->getOperand(0), targetFuncName, true);

                            // trace use of source function
                            Function *f = i->getParent()->getParent();
                            if (f == nullptr)
                                continue;
                            int arg_no = 0;

                            for(auto a = f->arg_begin(), ae = f->arg_end(); a != ae; a++) {
                                bool isSource = false;
                                for (auto arg_user:(*a).users()) {
                                    if (isSrcOrDest(arg_user, srcVal)) {
                                        isSource = true;
                                        break;
                                    }
                                }
                                if (isSource) {
                                    for (auto f_user:f->users()) {
                                        if (CallInst *f_callsite = dyn_cast<CallInst>(f_user)) {
                                            int arg_no_2 = 0;
                                            for(auto b = f->arg_begin(), be = f->arg_end(); b != be; b++) {
                                                // find the source variable at callsite
                                                if (arg_no_2 == arg_no && arg_no < f_callsite->getNumArgOperands())
                                                    currInst = getRecursiveCallInst(f_callsite->getArgOperand(arg_no), targetFuncName, true);
                                                if (currInst != nullptr)
                                                    return currInst;
                                                arg_no_2++;
                                            }
                                        }
                                    }
                                }
                                arg_no ++;
                            }
                        }
                        // trace sub function
                        if (CallInst *subCallInst = dyn_cast<CallInst>(curr_use)) {
                            // find paras in sub function according to current variable
                            for (int i=0; i < subCallInst->getNumArgOperands(); i++) {
                                if (isSrcOrDest(subCallInst->getArgOperand(i), srcVal))
                                {
                                    Function *subFunction = subCallInst->getCalledFunction();
                                    if (subFunction == nullptr)
                                        continue;
#ifdef DIFUZE_DEBUG
                                    if (subFunction->hasName())
                                    {
                                        dbgs() << "trace sub function: " << subFunction->getName() << "\n";
                                    }
#endif
                                    int subFunction_arg_no = 0;
                                    // for (auto &subFunctionArg:subFunction->getArgumentList()) {
                                    for(auto subFunctionArg = subFunction->arg_begin(), subFunctionArg_end = subFunction->arg_end(); subFunctionArg != subFunctionArg_end; subFunctionArg++) {
                                        currInst = getRecursiveCallInst(&(*subFunctionArg), targetFuncName, true); 
                                        subFunction_arg_no++;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return currInst;
        }

        bool handleGenericCDevRegister(Function *currFunction) {
            for(Function::iterator fi = currFunction->begin(), fe = currFunction->end(); fi != fe; fi++) {
                BasicBlock &currBB = *fi;
                for (BasicBlock::iterator i = currBB.begin(), ie = currBB.end(); i != ie; ++i) {
                    Instruction *currInstPtr = &(*i);
                    CallInst *currCall = dyn_cast<CallInst>(currInstPtr);

                    std::string allocChrDev = "alloc_chrdev_region";
                    if(isCalledFunction(currCall, allocChrDev)) {
                        Value *devNameOp = currCall->getArgOperand(3);
                        return getDeviceString(devNameOp);
                    }
                    // is the usage device_create?
                    std::string devCreateName = "device_create";
                    if(isCalledFunction(currCall, devCreateName)) {
                        Value *devNameOp = currCall->getArgOperand(4);
                        return getDeviceString(devNameOp);
                    }

                    std::string regChrDevRegion = "register_chrdev_region";
                    if(isCalledFunction(currCall, regChrDevRegion)) {
                        Value *devNameOp = currCall->getArgOperand(2);
                        return getDeviceString(devNameOp);
                    }
                }
            }
            return false;
        }

        bool handleCdevHeuristic(CallInst *cdevCallInst, llvm::GlobalVariable *fopsStructure) {
            Value *deviceStructure = cdevCallInst->getArgOperand(0);
            // 1: the most naive try
#ifdef DIFUZE_DEBUG
            if (deviceStructure != nullptr)
            {
                dbgs() << "deviceStructure: \n";
                deviceStructure->dump();
            }
#endif
            std::string cdevaddFunc_naive = "cdev_add";
            for (auto ds_user:deviceStructure->users()) {
                if (CallInst *ds_currCall = dyn_cast<CallInst>(ds_user)){
                    if (isCalledFunction(ds_currCall, cdevaddFunc_naive)) {
#ifdef DIFUZE_DEBUG
                        dbgs() << "naive cdev_add found\n";
#endif
                        // find the devt structure.
                        llvm::GlobalVariable *target_devt_naive = getSrcTrackedVal(ds_currCall->getArgOperand(1), 0);

                        llvm::AllocaInst *allocaVal_naive = nullptr;
                        Value *targetDevNo_naive;
                        targetDevNo_naive = target_devt_naive;
                        if(target_devt_naive == nullptr) {
                            allocaVal_naive = getSrcTrackedAllocaVal(ds_currCall->getArgOperand(1));
                            targetDevNo_naive = allocaVal_naive;
                        }
                        if(targetDevNo_naive == nullptr) {
                            targetDevNo_naive = getSrcTrackedArgVal(ds_currCall->getArgOperand(1), cdevCallInst->getFunction());
                        }
                        // find the uses.
                        if(targetDevNo_naive != nullptr ) {
#ifdef DIFUZE_DEBUG
                            dbgs() << "naive targetDevNo found\n";
#endif
                            std::string allocChrDevReg_naive = "alloc_chrdev_region";
                            CallInst *currCall_naive = getRecursiveCallInst(targetDevNo_naive, allocChrDevReg_naive, true);
                            if(currCall_naive != nullptr) {
#ifdef DIFUZE_DEBUG
                                dbgs() << "naive alloc_chrdev_region found\n";
#endif
                                Value *devNameOp_naive_3 = currCall_naive->getArgOperand(3);
                                if (getDeviceString(devNameOp_naive_3))
                                    return true;
                            }
                            std::string devCreate_naive = "device_create";
                            currCall_naive = getRecursiveCallInst(targetDevNo_naive, devCreate_naive, true);
                            // is the usage device_create?
                            if(currCall_naive) {
                                Value *devNameOp_naive_4 = currCall_naive->getArgOperand(4);
                                if (getDeviceString(devNameOp_naive_4))
                                    return true;
                            }
#ifdef DIFUZE_DEBUG
                            else {
                                dbgs() << "naive devNameOp Finding Error\n";
                            }
#endif
                        } 
#ifdef DIFUZE_DEBUG
                        else {
                            dbgs() << "naive targetDevNo Error\n";   
                        }
#endif
                    }
                }
            }

            // 2: find global variable
            // get the dev structure
            // llvm::GlobalVariable *globalDevSt = dyn_cast<llvm::GlobalVariable>(deviceStructure);
            llvm::GlobalVariable *globalDevSt = getSrcTrackedVal(deviceStructure, 0);
            ConstantInt *tmp_constantint;
            if (globalDevSt != nullptr)
                tmp_constantint = dyn_cast<ConstantInt>(globalDevSt);
            if(globalDevSt != nullptr && tmp_constantint == nullptr) {
#ifdef DIFUZE_DEBUG
                globalDevSt->dump();
#endif
                CallInst *cdev_call= nullptr;

                // get the cdev_add function which is using the dev structure.
                std::string cdevaddFunc = "cdev_add";
                //递归所有函数，找到字符设备添加函数
                cdev_call = getRecursiveCallInst(globalDevSt, cdevaddFunc, true);
                if(cdev_call != nullptr) {
#ifdef DIFUZE_DEBUG
                    dbgs() << "cdev_call found\n";
#endif
                    // find, the devt structure.
                    llvm::GlobalVariable *target_devt = getSrcTrackedVal(cdev_call->getArgOperand(1), 0);

                    llvm::AllocaInst *allocaVal = nullptr;
                    Value *targetDevNo;
                    targetDevNo = target_devt;

                    if(target_devt == nullptr) {
                        allocaVal = getSrcTrackedAllocaVal(cdev_call->getArgOperand(1));
                        targetDevNo = allocaVal;
                    }

                    if(targetDevNo == nullptr) {
                        targetDevNo = getSrcTrackedArgVal(cdev_call->getArgOperand(1), cdevCallInst->getFunction());
                    }

                    // find the uses.
                    if(targetDevNo != nullptr ) {
#ifdef DIFUZE_DEBUG
                        dbgs() << "targetDevNo found\n";
#endif
                        std::string allocChrDevReg = "alloc_chrdev_region";
                        CallInst *currCall = getRecursiveCallInst(targetDevNo, allocChrDevReg, true);
                        if(currCall != nullptr) {
#ifdef DIFUZE_DEBUG
                            dbgs() << "alloc_chrdev_region found\n";
#endif
                            Value *devNameOp_3 = currCall->getArgOperand(3);
                            if (getDeviceString(devNameOp_3))
                                return true;
                        }
                        std::string devCreate = "device_create";
                        currCall = getRecursiveCallInst(targetDevNo, devCreate, true);
                        // is the usage device_create?
                        if(currCall) {
                            Value *devNameOp_4 = currCall->getArgOperand(4);
                            if (getDeviceString(devNameOp_4))
                                return true;
                        }
#ifdef DIFUZE_DEBUG
                        else {
                            dbgs() << "devNameOp Finding Error\n";
                        }
#endif
                    } 
#ifdef DIFUZE_DEBUG
                    else {
                        dbgs() << "targetDevNo Error\n";   
                    }
#endif
                }
#ifdef DIFUZE_DEBUG
                else {
                    dbgs() << "cdev_add not found \n";
                }
#endif
            }

            // 3.dev is Local variable or parameter
            std::set<Value *> dev_struct_Var_set = getSrcTrackedVal_Local(deviceStructure, 0);
            for (auto dev_struct_Var:dev_struct_Var_set) {
                if (dev_struct_Var != nullptr) {

                    CallInst *cdev_call_local= nullptr;
                    std::string cdevaddFunc_local = "cdev_add";
                    cdev_call_local = getRecursiveCallInst(dev_struct_Var, cdevaddFunc_local, true);
                    if (cdev_call_local != nullptr) {
#ifdef DIFUZE_DEBUG
                        dbgs() << "Local Device cdev_add found\n";
#endif
                        Value *target_devt_local = getSrcTrackedVal(cdev_call_local->getArgOperand(1), 0);
                        llvm::AllocaInst *allocaVal_local = nullptr;
                        Value *targetDevNo_local;
                        targetDevNo_local = target_devt_local;
                        if (target_devt_local == nullptr) {
                            allocaVal_local = getSrcTrackedAllocaVal(cdev_call_local->getArgOperand(1));
                            targetDevNo_local = allocaVal_local;
                        }
                        if(targetDevNo_local == nullptr) {
                            targetDevNo_local = getSrcTrackedArgVal(cdev_call_local->getArgOperand(1), cdevCallInst->getFunction());
                        }
                        // find the uses.
                        if (targetDevNo_local != nullptr ) {
                            std::string allocChrDevReg_local = "alloc_chrdev_region";
                            CallInst *currCall_local = getRecursiveCallInst(targetDevNo_local, allocChrDevReg_local, true);
                            if(currCall_local != nullptr) {
                                Value *devNameOp_local_3 = currCall_local->getArgOperand(3);
                                if (getDeviceString(devNameOp_local_3))
                                    return true;
                            }
                            std::string devCreate_local = "device_create";
                            currCall_local = getRecursiveCallInst(targetDevNo_local, devCreate_local, true);
                            // is the usage device_create?
                            if(currCall_local) {
                                Value *devNameOp_local_4 = currCall_local->getArgOperand(4);
                                if (getDeviceString(devNameOp_local_4))
                                    return true;
                            }
#ifdef DIFUZE_DEBUG
                            else {
                                dbgs() << "devNameOp_local Finding Error\n";
                            }
#endif
                        }
#ifdef DIFUZE_DEBUG
                        else {
                            dbgs() << "targetDevNo_local Error\n";   
                        }
#endif
                    }
#ifdef DIFUZE_DEBUG
                    else
                        dbgs() << "Local Device cdev_add Error\n";
#endif
                }
            }
            return handleGenericCDevRegister(cdevCallInst->getParent()->getParent());
        }

        bool handleProcCreateHeuristic(CallInst *procCallInst, llvm::GlobalVariable *fopsStructure) {
            Value *devNameOp = procCallInst->getArgOperand(0);
            return getDeviceString(devNameOp);
        }

        bool handleMiscDevice_Element(llvm::ConstantStruct *miscDevice) {
            bool res = false;
            if (miscDevice->getType()->hasName()) {
                std::string structureName = miscDevice->getType()->getName().str();
#ifdef DIFUZE_DEBUG
                dbgs() << "devStructType: " << structureName << "\n";
#endif
                if (structureName == "struct.miscdevice" || structureName.find("struct.miscdevice.") != string::npos) {
                    Value *devNameVal = miscDevice->getOperand(1);
#ifdef DIFUZE_DEBUG
                    dbgs() << "[+] devNameval Found\n";
                    if (devNameVal != nullptr)
                        devNameVal->dump();
#endif
                    return getDeviceString(devNameVal);
                } else {
                    for(unsigned int i=0; i < miscDevice->getNumOperands(); i++) {
                        if (ConstantStruct *outputSt = dyn_cast<ConstantStruct>(miscDevice->getOperand(i)))
                        {
                            res = res | handleMiscDevice_Element(outputSt);
                            if (res)
                                return true;
                        }
                    }
                }
            }
            return res;
        }
        bool handleMiscDevice(llvm::GlobalVariable *miscDevice) {
            if(miscDevice->hasInitializer()) {
                ConstantStruct *outputSt = dyn_cast<ConstantStruct>(miscDevice->getInitializer());
                handleMiscDevice_Element(outputSt);
            }
            return false;
        }


        bool handleDynamicMiscOps(StoreInst *srcStoreInst) {
#ifdef DIFUZE_DEBUG
                dbgs() << "[debug] handleDynamicMiscOps\n";
#endif
#define MISC_FILENAME_INDX 1
            // OK this is the store instruction which is trying to store fops into a misc device
            BasicBlock *targetBB = srcStoreInst->getParent();
            // iterate thru all the instructions to find any store to a misc device name field.
            std::set<Value *> nameField;
            for (BasicBlock::iterator i = targetBB->begin(), ie = targetBB->end(); i != ie; ++i) {
                Instruction *currInstPtr = &(*i);
                GetElementPtrInst *gepInst = dyn_cast<GetElementPtrInst>(currInstPtr);
                if(gepInst && gepInst->getNumOperands() > 2) {
#ifdef DIFUZE_DEBUG
                    dbgs() << *(gepInst->getSourceElementType()) << "\n";
#endif
                    StructType *targetStruct = dyn_cast<StructType>(gepInst->getSourceElementType());
#ifdef DIFUZE_DEBUG
                    dbgs() << targetStruct->getName() << "\n";
#endif
                    if (targetStruct != nullptr && !(targetStruct->isLiteral()) && 
                            (targetStruct->getName().str()=="struct.miscdevice" || targetStruct->getName().str().find("struct.miscdevice.")!=string::npos)
                       ) {
#ifdef DIFUZE_DEBUG
                        dbgs() <<  "Found:" << *gepInst << "\n";
#endif
                        ConstantInt *fieldInt = dyn_cast<ConstantInt>(gepInst->getOperand(2));
                        if(fieldInt) {
                            if(fieldInt->getZExtValue() == MISC_FILENAME_INDX) {
                                nameField.insert(&(*i));
                            }
                        }
                    }
                }

                // Are we storing into name field of a misc structure?
                StoreInst *currStInst = dyn_cast<StoreInst>(currInstPtr);
                if(currStInst) {
                    Value *targetPtr = currStInst->getPointerOperand()->stripPointerCasts();
                    if(nameField.find(targetPtr) != nameField.end()) {
                        // YES.
                        // find the name
                        return getDeviceString(currStInst->getOperand(0));
                    }
                }
            }
            return false;
        }

        void handleV4L2Dev(Module &m) {
#define VFL_TYPE_GRABBER	0
#define VFL_TYPE_VBI		1
#define VFL_TYPE_RADIO		2
#define VFL_TYPE_SUBDEV		3
#define VFL_TYPE_SDR		4
#define VFL_TYPE_TOUCH		5

            std::map<uint64_t, std::string> v4l2TypeNameMap;
            v4l2TypeNameMap[VFL_TYPE_GRABBER] = "/dev/video[X]";
            v4l2TypeNameMap[VFL_TYPE_VBI] = "/dev/vbi[X]";
            v4l2TypeNameMap[VFL_TYPE_RADIO] = "/dev/radio[X]";
            v4l2TypeNameMap[VFL_TYPE_SUBDEV] = "/dev/subdev[X]";
            v4l2TypeNameMap[VFL_TYPE_SDR] = "/dev/swradio[X]";
            v4l2TypeNameMap[VFL_TYPE_TOUCH] = "/dev/v4l-touch[X]";

            // find all functions
            for(Module::iterator mi = m.begin(), ei = m.end(); mi != ei; mi++) {
                Function &currFunction = *mi;
                if(!currFunction.isDeclaration() && currFunction.hasName()) {
                    string currFuncName = currFunction.getName().str();
                    if(currFuncName.find("init") != string::npos || currFuncName.find("probe") != string::npos) {
                        for(Function::iterator fi = currFunction.begin(), fe = currFunction.end(); fi != fe; fi++) {
                            BasicBlock &currBB = *fi;
                            for (BasicBlock::iterator i = currBB.begin(), ie = currBB.end(); i != ie; ++i) {
                                Instruction *currInstPtr = &(*i);
                                CallInst *currCall = dyn_cast<CallInst>(currInstPtr);
                                if(currCall != nullptr) {
                                    Function *calledFunc = currCall->getCalledFunction();
                                    if (calledFunc != nullptr && calledFunc->hasName() &&
                                        (calledFunc->getName()=="__video_register_device" || calledFunc->getName().str().find("__video_register_device.")!=string::npos)
                                    ) {
                                        Value *devType = currCall->getArgOperand(1);
                                        //InterProceduralRA<CropDFS> &range_analysis = getAnalysis<InterProceduralRA<CropDFS>>();
                                        //Range devRange = range_analysis.getRange(devType);
                                        ConstantInt *cInt = dyn_cast<ConstantInt>(devType);
                                        if (cInt) {
                                            uint64_t typeNum = cInt->getZExtValue();
                                            if (v4l2TypeNameMap.find(typeNum) != v4l2TypeNameMap.end()) {
                                                dbgs() << "[+] V4L2 Device: " << v4l2TypeNameMap[typeNum] << "\n";
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        bool runOnModule(Module &m) override {
            dbgs() << "[+] Provided Function Name: " << checkFunctionName << "\n";

            for(Module::iterator mi = m.begin(), ei = m.end(); mi != ei; mi++) {

                Function &currFunction = *mi;
                //if the current function is the target function.
                if(!currFunction.isDeclaration() && currFunction.hasName() &&
                   currFunction.getName().str() == checkFunctionName) {

                    llvm::GlobalVariable *targetFopsStructure = nullptr;
                    for(auto curr_use: currFunction.users()) {
                        if(curr_use->getType()->isStructTy()) {
                            for(auto curr_use1: curr_use->users()) {
                                llvm::GlobalVariable *currGlobal = dyn_cast<llvm::GlobalVariable>(curr_use1);
                                if(currGlobal != nullptr) {
                                    targetFopsStructure = currGlobal;
                                    dbgs() << "[+] Found Fops Structure: " << targetFopsStructure->getName() << "\n";
                                    break;

                                }
                            }
                            if(targetFopsStructure != nullptr) {
                                break;
                            }
                        }
                    }

                    if(targetFopsStructure == nullptr) {
                        dbgs() << "[-] Unable to find fops structure which is using this function.\n";
                    } else {
#ifdef DIFUZE_DEBUG
                        dbgs() << "[+] fops structure found.\n";
#endif
                        for(auto curr_usage:targetFopsStructure->users()) {
#ifdef DIFUZE_DEBUG
                            dbgs() << "current opsStructure User: " << *curr_usage << "\n";
#endif
                            CallInst *currCallInst = nullptr;
                            std::string cdevInitName = "cdev_init";
                            currCallInst = getRecursiveCallInst(curr_usage, cdevInitName, true);
#ifdef DIFUZE_DEBUG
                            if (currCallInst != nullptr) {
                                dbgs() << cdevInitName << " CallInst Found!\n";
                            }
#endif
                            if(isCalledFunction(currCallInst, cdevInitName)) {
                                if(handleCdevHeuristic(currCallInst, targetFopsStructure)) {
                                    dbgs() << "[+] Device Type: char\n";
                                    dbgs() << "[+] Found using first cdev heuristic\n";
                                    return false;
                                }
                            }

                            std::string regChrDev = "__register_chrdev";
                            currCallInst = getRecursiveCallInst(curr_usage, regChrDev, true);
#ifdef DIFUZE_DEBUG
                            if (currCallInst != nullptr) {
                                dbgs() << regChrDev << " CallInst Found!\n";
                            }
#endif
                            if(isCalledFunction(currCallInst, regChrDev)) {
                                if(getDeviceString(currCallInst->getArgOperand(3))) {
                                    dbgs() << "[+] Device Type: char\n";
                                    dbgs() << "[+] Found using register chrdev heuristic\n";
                                    return false;
                                }

                            }


                            std::string procCreateData = "proc_create_data";
                            std::string procCreateName = "proc_create";
                            currCallInst = dyn_cast<CallInst>(curr_usage);
#ifdef DIFUZE_DEBUG
                            if (currCallInst != nullptr) {
                                dbgs() << procCreateName << " " << procCreateData << " CallInst Found!\n";
                            }
#endif      
                            if(isCalledFunction(currCallInst, procCreateData) ||
                                    isCalledFunction(currCallInst, procCreateName)) {
                                if(handleProcCreateHeuristic(currCallInst, targetFopsStructure)) {
                                    dbgs() << "[+] Device Type: proc\n";
                                    dbgs() << "[+] Found using proc create heuristic\n";
                                    return false;
                                }
                            }
                            // Handling misc devices
                            // Standard. (when misc device is defined as static)
                            if(curr_usage->getType()->isStructTy()) {
#ifdef DIFUZE_DEBUG
                                dbgs() << "curr ops usage is structTy\n";
#endif
                                llvm::GlobalVariable *currGlobal = nullptr;
                                // OK, find the miscdevice
                                if (llvm::GlobalVariable *currGlob_tmp=dyn_cast<llvm::GlobalVariable>(curr_usage))
                                    currGlobal = currGlob_tmp;
                                else {
                                    for(auto curr_use1: curr_usage->users()) {
#ifdef DIFUZE_DEBUG
                                        dbgs() << "current opsStructure User's user: " << *curr_use1 << "\n";
#endif
                                        if (curr_use1->getType()->isStructTy())
                                        {
                                            for(auto curr_use2: curr_use1->users()) {
#ifdef DIFUZE_DEBUG
                                                dbgs() << "current opsStructure User's user' user: " << *curr_use2 << "\n";
#endif
                                                currGlobal = dyn_cast<llvm::GlobalVariable>(curr_use2);
                                                if (currGlobal != nullptr) {
#ifdef DIFUZE_DEBUG
                                                    dbgs() << "GlobalVariable :" << *currGlobal<<"\n";
#endif
                                                    break;
                                                }
                                            }
                                            if (currGlobal != nullptr)
                                                break;
                                        }
                                        currGlobal = dyn_cast<llvm::GlobalVariable>(curr_use1);
                                        if (currGlobal != nullptr) {
#ifdef DIFUZE_DEBUG
                                          dbgs() << "GlobalVariable :" << *currGlobal<<"\n";
#endif
                                          break;
                                        }
                                    }
                                }
                                if(currGlobal != nullptr) {
                                    CallInst *currCallInst = nullptr;
                                    std::string misc_reg_name = "misc_register";
                                    currCallInst = getRecursiveCallInst(currGlobal, misc_reg_name, true);
                                    if (currCallInst != nullptr) {
                                        if (handleMiscDevice(currGlobal)) {
                                            dbgs() << "[+] Device Type: misc\n";
                                            dbgs() << "[+] Found using misc heuristic\n";
                                            return false;
                                        }
                                    }
                                }
#ifdef DIFUZE_DEBUG
                                else {
                                    dbgs() << "[!] cannot find GlobalVariable for miscdevice\n";
                                }
#endif
                            }

                            // when misc device is created manually
                            // using kmalloc
                            StoreInst *currStore = dyn_cast<StoreInst>(curr_usage);
                            if(currStore != nullptr) {
                                // OK, we are storing into a structure.
                                if(handleDynamicMiscOps(currStore)) {
                                    dbgs() << "[+] Device Type: misc\n";
                                    dbgs() << "[+] Found using dynamic misc heuristic\n";
                                    return false;
                                }
                                Value *s_tmp_ptr = currStore->getPointerOperand();
#ifdef DIFUZE_DEBUG
                                dbgs() << "currStore->getPointerOperand(): " << *s_tmp_ptr << "\n";
#endif
                                llvm::GlobalVariable *currGlobal_store = nullptr;
                                for(auto curr_use2: s_tmp_ptr->users()) {
#ifdef DIFUZE_DEBUG
                                    dbgs() << "current opsStructure User's user: " << *curr_use2 << "\n";
#endif
                                    currGlobal_store = dyn_cast<llvm::GlobalVariable>(curr_use2);
                                    if (currGlobal_store != nullptr) {
#ifdef DIFUZE_DEBUG
                                        dbgs() << "GlobalVariable :" << *currGlobal_store<<"\n";
#endif
                                        break;
                                    }
                                }
                                if (currGlobal_store == nullptr) {
                                    if (Instruction *s_tmp_inst = dyn_cast<Instruction>(s_tmp_ptr)) {
                                        for(unsigned int i=0; i < s_tmp_inst->getNumOperands(); i++) {
                                            Value *currOp = s_tmp_inst->getOperand(i);
#ifdef DIFUZE_DEBUG
                                            dbgs() << "current opsStructure User's operand: " << *currOp << "\n";
#endif
                                            currGlobal_store = getSrcTrackedVal(currOp, 0);
                                            if (currGlobal_store != nullptr) {
#ifdef DIFUZE_DEBUG
                                                dbgs() << "GlobalVariable :" << *currGlobal_store<<"\n";
#endif
                                                break;
                                            }
                                        }
                                    }
                                }
                                if (currGlobal_store != nullptr) {
                                    for(auto curr_usage:currGlobal_store->users()) {
#ifdef DIFUZE_DEBUG
                                        dbgs() << "current opsStructure User: " << *curr_usage << "\n";
#endif
                                        std::string cdevInitName = "cdev_init";
                                        CallInst *currCallInst = nullptr;
                                        currCallInst = getRecursiveCallInst(curr_usage, cdevInitName, true);
                                        if(isCalledFunction(currCallInst, cdevInitName)) {
                                            if(handleCdevHeuristic(currCallInst, targetFopsStructure)) {
                                                dbgs() << "[+] Device Type: char\n";
                                                dbgs() << "[+] Found using first cdev heuristic\n";
                                                return false;
                                            }
                                        }
                                        cdevInitName = "cdev_add";
                                        currCallInst = getRecursiveCallInst(curr_usage, cdevInitName, true);
                                        if(isCalledFunction(currCallInst, cdevInitName)) {
                                            if(handleCdevHeuristic(currCallInst, targetFopsStructure)) {
                                                dbgs() << "[+] Device Type: char\n";
                                                dbgs() << "[+] Found using first cdev heuristic\n";
                                                return false;
                                            }
                                        }
                                    }
                                }
                            }

                            // Handling v4l2 devices
                            // More information: https://01.org/linuxgraphics/gfx-docs/drm/media/kapi/v4l2-dev.html
                            Type *targetFopsType = targetFopsStructure->getType()->getContainedType(0);
                            if(targetFopsType->isStructTy()) {
                                StructType *fopsStructType = dyn_cast<StructType>(targetFopsType);
                                if(fopsStructType->hasName()) {
                                    std::string structureName = fopsStructType->getStructName().str();
                                    if(structureName=="struct.v4l2_ioctl_ops" || structureName.find("struct.v4l2_ioctl_ops.")!=string::npos) {
                                        handleV4L2Dev(m);
                                        dbgs() << "[+] Device Type: v4l2\n";
                                        dbgs() << "[+] Look into: /sys/class/video4linux/<devname>/name to know the details\n";
                                        return false;
                                    }
                                }
                            }

                        }
                    }
                }
            }
            return true;
        }



        void getAnalysisUsage(AnalysisUsage &AU) const override {
            AU.setPreservesAll();
            //AU.addRequired<InterProceduralRA<CropDFS>>();
            AU.addRequired<CallGraphWrapperPass>();
            AU.addRequired<LoopInfoWrapperPass>();
            //AU.addRequired<unimelb::WrappedRangePass>();
        }

    private:



    };

    char DeviceNameFinderPass::ID = 0;
    static RegisterPass<DeviceNameFinderPass> x("dev-name-finder", "Device name finder", false, true);
}

