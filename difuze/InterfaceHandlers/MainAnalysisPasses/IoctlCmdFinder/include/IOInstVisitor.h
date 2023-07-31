//
// Created by machiry on 4/24/17.
//

#ifndef PROJECT_IOINSTVISITOR_H
#define PROJECT_IOINSTVISITOR_H

#include <set>
#include "llvm/Pass.h"
//#include "llvm/PassAnalysisSupport.h"
//#include "dsa/DSGraph.h"
//#include "dsa/DataStructure.h"
#include "llvm/Analysis/AliasSetTracker.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/Support/Format.h"
#include <llvm/IR/DebugLoc.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Metadata.h>
#include "llvm/IR/CFG.h"

// #define  DIFUZE_DEBUG 1

using namespace llvm;
namespace IOCTL_CHECKER {
    class IOInstVisitor : public InstVisitor<IOInstVisitor> {
    public:

        Function *targetFunction;

        // All instructions whose result depend on the value
        // value which is derived from cmd arg value.
        std::set<Value*> allCmdInstrs;
        std::set<Value*> allCmdCallInstrs;
        // similar to cmd arg, this is for use arg.
        std::set<Value*> allArgInstrs;
        // value of the cmd, for
        // which the current branch belongs to
        // by default this will be nullptr
        Value *currCmdValue;
        // call stack.
        std::vector<Value*> callStack;

        std::set<BasicBlock*> visitBBs;
        std::map<BasicBlock*, int> visitBB_count;

        // map that stores the actual values passed by the caller,
        // this is useful in determining the type of argument.
        std::map<Value*, Value*> callerArgs;

        std::set<Function*> printedFuncs;

        // Range analysis results.
        //RangeAnalysis *range_analysis;

        // Pointer to the visitor which called.
        IOInstVisitor *calledVisitor;

        unsigned long curr_func_depth;


        IOInstVisitor(Function *targetFunc, std::set<int> &cmdArg, std::set<int> &uArg, std::map<unsigned, Value*> &callerArguments,
                      std::vector<Value*> &calledStack, IOInstVisitor *calledVisitor, unsigned long curr_func_depth) {
            // Initialize all values.
            _super = static_cast<InstVisitor *>(this);
            this->targetFunction = targetFunc;
            unsigned int farg_no=0;

            // add all callsites into allCmdCallInstrs
            for (Value::user_iterator it = targetFunc->user_begin(), ie = targetFunc->user_end();
                 it != ie; ++it) {
                if (*it == nullptr)
                    continue;
                if (CallInst *pCallInst = dyn_cast<CallInst>(*it))
                {
                    allCmdInstrs.insert(pCallInst);
                    allCmdCallInstrs.insert(pCallInst);
                }
            }

            for(Function::arg_iterator farg_begin = targetFunc->arg_begin(), farg_end = targetFunc->arg_end();
                farg_begin != farg_end; farg_begin++) {
                Value *currfArgVal = &(*farg_begin);
                // 把第二个和第三个参数加入集合
                if(cmdArg.find(farg_no) != cmdArg.end()) {
                    allCmdInstrs.insert(currfArgVal);
                    allCmdCallInstrs.insert(currfArgVal);
                }
                if(uArg.find(farg_no) != uArg.end()) {
                    allArgInstrs.insert(currfArgVal);
                }
                if(callerArguments.find(farg_no) != callerArguments.end()) {
                    this->callerArgs[currfArgVal] = callerArguments[farg_no];
                }
                farg_no++;
            }

            this->calledVisitor = calledVisitor;

            this->callStack.insert(this->callStack.end(), calledStack.begin(), calledStack.end());
            this->currCmdValue = nullptr;
            this->curr_func_depth = curr_func_depth;
            this->printedFuncs.clear();
        }

        bool isVisited(BasicBlock *currBB) {
            return this->visitBBs.find(currBB) != this->visitBBs.end();
        }

        void addBBToVisit(BasicBlock *currBB) {
            if(this->visitBBs.find(currBB) == this->visitBBs.end()) {
                this->visitBBs.insert(currBB);
            }
        }

        bool isCmdAffected(Value *targetValue) {

            if (Instruction *I = dyn_cast<Instruction>(targetValue)) {
                for (unsigned int i = 0; i < I->getNumOperands(); i++) {
                    Value *currValue = I->getOperand(i);
                    if (currValue != nullptr) {
                        Value *strippedValue = currValue->stripPointerCasts();
                        // 指令和cmd相关
                        if (allCmdInstrs.find(currValue) != allCmdInstrs.end() ||
                            allCmdInstrs.find(strippedValue) != allCmdInstrs.end()) {
                            // insert only if this is not present.
                            if (allCmdInstrs.find(I) == allCmdInstrs.end()) {
                                allCmdInstrs.insert(I);
                                break;
                            }
                        }
                    }
                }
            }

#ifdef DIFUZE_DEBUG
            dbgs() << "In isCmdAffected\n    " << *targetValue << "\n";
            
            // for debug
            std::set<Value*>::iterator it, ie;
            for(it=allCmdInstrs.begin(), ie=allCmdInstrs.end();it!=ie;it++) {
                dbgs() << "allCmdInstrs: " << *(*it) <<"\n";
            }
            for(it=allCmdCallInstrs.begin(), ie=allCmdCallInstrs.end();it!=ie;it++) {
                dbgs() << "allCmdCallInstrs: " << *(*it) <<"\n";
            }
#endif

            if(allCmdInstrs.find(targetValue) == allCmdInstrs.end()) {//如果找到最后一条指令了
                return allCmdInstrs.find(targetValue->stripPointerCasts()) != allCmdInstrs.end();
            }
            return true;
        }

        bool isArgAffected(Value *targetValue) {
            if(allArgInstrs.find(targetValue) == allArgInstrs.end()) {
                return allArgInstrs.find(targetValue->stripPointerCasts()) != allArgInstrs.end();
            }
            return true;
        }

        virtual void visit(Instruction &I) {
#ifdef DEBUG_INSTR_VISIT
            dbgs() << "Visiting instruction:";
            I.print(dbgs());
            dbgs() << "\n";
#endif

            // if this is not a call instruction.
            if(!dyn_cast<CallInst>(&I) /*&& !dyn_cast<PHINode>(&I)*/) {
                Value *storePtrArg = nullptr;
                if(dyn_cast<StoreInst>(&I)) {
                    storePtrArg = dyn_cast<StoreInst>(&I)->getPointerOperand()->stripPointerCasts();
                }
                for (unsigned int i = 0; i < I.getNumOperands(); i++) {
                    Value *currValue = I.getOperand(i);
                    if (currValue != nullptr) {
                        Value *strippedValue = currValue->stripPointerCasts();
                        // instruction is related to cmd
                        if (allCmdInstrs.find(currValue) != allCmdInstrs.end() ||
                            allCmdInstrs.find(strippedValue) != allCmdInstrs.end()) {
                            // insert only if this is not present.
                            if (allCmdInstrs.find(&I) == allCmdInstrs.end()) {
                                allCmdInstrs.insert(&I);
                            }
                            if(storePtrArg != nullptr) {
                                if (allCmdInstrs.find(storePtrArg) == allCmdInstrs.end()) {
                                    allCmdInstrs.insert(storePtrArg);
                                }
                            }
                        }
                        if (allArgInstrs.find(currValue) != allArgInstrs.end() ||
                            allArgInstrs.find(strippedValue) != allArgInstrs.end()) {
                            // only insert if this instruction is not present.
                            if (allArgInstrs.find(&I) == allArgInstrs.end()) {
                                allArgInstrs.insert(&I);
                            }
                            
                            if(storePtrArg != nullptr) {
                                if (allArgInstrs.find(storePtrArg) == allArgInstrs.end()) {
                                    allArgInstrs.insert(storePtrArg);
                                }
                            }
                        }

                    }

                }
            }
            else {
                // dbgs() << "It's a CallInst\n";
                Value *storePtrArg = nullptr;
                if(dyn_cast<StoreInst>(&I)) {
                    storePtrArg = dyn_cast<StoreInst>(&I)->getPointerOperand()->stripPointerCasts();
                }
                for (unsigned int i = 0; i < I.getNumOperands(); i++) {
                    Value *currValue = I.getOperand(i);
                    if (currValue != nullptr) {
                        Value *strippedValue = currValue->stripPointerCasts();
                        // instruction is related to cmd
                        if (allCmdCallInstrs.find(currValue) != allCmdCallInstrs.end() ||
                            allCmdCallInstrs.find(strippedValue) != allCmdCallInstrs.end()) {
                            // insert only if this is not present.
                            if (allCmdCallInstrs.find(&I) == allCmdCallInstrs.end()) {
                                allCmdCallInstrs.insert(&I);
                            }
                            if(storePtrArg != nullptr) {
                                if (allCmdCallInstrs.find(storePtrArg) == allCmdCallInstrs.end()) {
                                    allCmdCallInstrs.insert(storePtrArg);
                                }
                            }
                        }

                    }

                }
            }

            this->_super->visit(I);
        }

        // visitor functions.

        virtual void visitCallInst(CallInst &I);

        virtual void visitICmpInst(ICmpInst &I);



        bool visitBB(BasicBlock *BB);

        // main analysis function.
        void analyze();

        bool handleCmdSwitch(SwitchInst *targetSwitchInst, std::set<BasicBlock*> &totalVisited);

        bool handleCmdCond(BranchInst *I, std::set<BasicBlock*> &totalVisited);

        void visitAllBBs(BasicBlock *startBB, std::set<BasicBlock*> &visitedBBs,
                         std::set<BasicBlock*> &totalVisited, std::set<BasicBlock*> &visitedInThisIteration, int depth);
    private:
        InstVisitor *_super;
        void getArgPropogationInfo(CallInst *I, std::set<int> &cmdArg, std::set<int> &uArg, std::map<unsigned, Value*> &callerArgInfo);

        bool isInstrToPropogate(Instruction *I);

        Function* getFinalFuncTarget(CallInst *I);
    };
}

#endif //PROJECT_IOINSTVISITOR_H

