
//
// Created by machiry on 4/24/17.
//

#include "IOInstVisitor.h"
#include <CFGUtils.h>
#include "TypePrintHelper.h"
#include "Annotation.h"
#include <iostream>

using namespace llvm;
using namespace std;
using namespace KIntAnnotation;
#define MAX_FUNC_DEPTH 7
#define MAX_VISITALLBBS_DEPTH 50
#define MAX_VISITALLBBS_COUNT 50

// #define DIFUZE_DEBUG 1
namespace IOCTL_CHECKER {
    std::set<std::string> visitedLIds;
    std::set<std::string> visitedSIds;
    // the main analysis function.
    void IOInstVisitor::analyze() {
        // No what we need is:
        // Traverse the CFG in Breadth first order.
        std::vector<BasicBlock*> processQueue;
        std::vector<BasicBlock*>::iterator ret;
        if (this->targetFunction->isDeclaration() == false) {
            std::vector<std::vector<BasicBlock *> *> *traversalOrder =
                    BBTraversalHelper::getSCCTraversalOrder(*(this->targetFunction));
            for(unsigned int i = 0; i < traversalOrder->size(); i++) {
                // current strongly connected component.
                std::vector<BasicBlock *> *currSCC = (*(traversalOrder))[i];
                for (unsigned int j = 0; j < currSCC->size(); j++) {
                    BasicBlock *currBB = (*currSCC)[j];
                    ret = std::find(processQueue.begin(), processQueue.end(), currBB);
                    if (ret == processQueue.end())
                        processQueue.insert(processQueue.end(), currBB);
                }
            }
        }

        bool is_handled;
        std::set<BasicBlock*> totalVisitedBBs;
#ifdef DIFUZE_DEBUG
        dbgs() << "while(!processQueue.empty()) :\n";
#endif        
        while(!processQueue.empty()) {
            BasicBlock *currBB = processQueue[0];
            // remove first element
            processQueue.erase(processQueue.begin());
            // visitBB for isCmdAffected analysis later
#ifdef DIFUZE_DEBUG
            dbgs() << "line 59: if(this->visitBB(currBB)): " << currBB->getName() << "\n";
#endif
            if(this->visitBB(currBB)) {
                dbgs() << "Found a common structure\n";
            }
            // TerminatorInst *terminInst = currBB->getTerminator();
	        Instruction *terminInst = currBB->getTerminator();

            is_handled = false;

            if(terminInst != nullptr) {
                // first check if the instruction is affected by cmd value
                if(terminInst->getNumSuccessors() > 1 && isCmdAffected(terminInst)) {
                    // is this a switch?
                    SwitchInst *dstSwitch = dyn_cast<SwitchInst>(currBB->getTerminator());
                    if(dstSwitch != nullptr) {
#ifdef DIFUZE_DEBUG
                        dbgs() << "Trying switch processing for:" << currBB->getName() << ":" << this->targetFunction->getName() <<"\n";
#endif
                        // is switch handle cmd switch.
                        is_handled = handleCmdSwitch(dstSwitch, totalVisitedBBs);
                    } else {
#ifdef DIFUZE_DEBUG
                        dbgs() << "START:Trying branch processing for:" << currBB->getName() << ":" << this->targetFunction->getName() <<"\n";
#endif
                        // not switch?, check if the branch instruction
                        // if this is branch, handle cmd branch
                        BranchInst *brInst = dyn_cast<BranchInst>(terminInst);
                        if(brInst == nullptr) {
                            dbgs() << "Culprit:" << "\n";
                            currBB->dump();
                        }
                        assert(brInst != nullptr);
                        is_handled = handleCmdCond(brInst, totalVisitedBBs);
#ifdef DIFUZE_DEBUG
                        dbgs() << "END:Trying branch processing for:" << currBB->getName() << ":" << this->targetFunction->getName() <<"\n";
#endif
                    }
                }
                // avoid duplication for queue
                if(is_handled) {
                    std::vector<BasicBlock*> reachableBBs;
                    reachableBBs.clear();
                    BBTraversalHelper::getAllReachableBBs(currBB, processQueue, reachableBBs);
                    //dbgs() << "Removing all successor BBs from:" << currBB->getName() << ":" << this->targetFunction->getName() << "\n";
                    for(unsigned int i=0; i < reachableBBs.size(); i++) {
                        // remove all reachable BBs as these are already handled.
                        processQueue.erase(std::remove(processQueue.begin(), processQueue.end(), reachableBBs[i]),
                                           processQueue.end());
                    }
                }
            } else {
                assert(false);
            }
        }
    }

    void IOInstVisitor::visitAllBBs(BasicBlock *startBB, std::set<BasicBlock*> &visitedBBs,
                                    std::set<BasicBlock*> &totalVisited, std::set<BasicBlock*> &visitedInThisIteration, int depth) {
        // TerminatorInst *terminInst;
	    Instruction *terminInst;
        bool is_handled;
        if (visitBB_count.count(startBB) != 0) {
            if (visitBB_count[startBB] > MAX_VISITALLBBS_COUNT)
                return;
            visitBB_count[startBB] += 1;
        } else {
            visitBB_count[startBB] = 1;
        }
        if (depth > MAX_VISITALLBBS_DEPTH) {
          return;
        }
#ifdef DIFUZE_DEBUG
        dbgs() << "visitAllBBs depth: " << depth << ", count: "<< visitBB_count[startBB] << "\n";
        dbgs() << "visiting BB: " << startBB << ": "<< (*startBB) << "\n";
        // for (auto vBB:visitedBBs) {
        //     dbgs() << "visitedBBs:" << vBB->getName() << ":" << this->targetFunction->getName() <<"\n";
        // }
#endif

        if(visitedBBs.find(startBB) == visitedBBs.end() && totalVisited.find(startBB) == totalVisited.end()) {
            visitedBBs.insert(startBB);
            visitedInThisIteration.insert(startBB);

            // Print Lid and Sid for this case BB
            for (BasicBlock::iterator i = startBB->begin(), ie = startBB->end(); i != ie; ++i) {
                Instruction *currInstPtr = &(*i);
                if (LoadInst *L = dyn_cast<LoadInst>(currInstPtr)) {
                    std::string LId = getLoadId(L);
                    if (LId.find("struct.") != 0 && LId.find("var.") != 0)
                        continue;
                    if (visitedLIds.find(LId) == visitedLIds.end() && LId.find("struct.thread_info,") == LId.npos) {
                      std::string op_name_str;
                      llvm::raw_string_ostream rso(op_name_str);
                      rso << *(L->getPointerOperand());
                      op_name_str = rso.str();
                      op_name_str = op_name_str.substr(0, op_name_str.find(" ="));
                      dbgs() << "find LoadId: {" << LId << " | Load pointer value: " << op_name_str << " | Type: " << *(L->getPointerOperand()->getType()->getContainedType(0)) << "}\n";
                      visitedLIds.insert(LId);
                    }
                } else if (StoreInst *S = dyn_cast<StoreInst>(currInstPtr)) {
                    std::string SId = getStoreId(S);
                    if (SId.find("struct.") != 0 && SId.find("var.") != 0)
                        continue;
                    std::string op_name_str;
                    llvm::raw_string_ostream rso(op_name_str);
                    rso << *(S->getPointerOperand());
                    op_name_str = rso.str();
                    op_name_str = op_name_str.substr(0, op_name_str.find("="));
                    if (visitedSIds.find(SId) == visitedSIds.end() && SId.find("struct.thread_info,") == SId.npos) {
                      dbgs() << "find StoreId: {" << SId << " | Store pointer value: " << op_name_str << " | Type: " << *(S->getPointerOperand()->getType()->getContainedType(0)) << "}\n";
                      visitedSIds.insert(SId);
                    }
                }
            }

#ifdef DIFUZE_DEBUG
            dbgs() << "line 154: if(this->visitBB(currBB))\n";
#endif
            // if no copy_from/to_user function is found?
            if(!this->visitBB(startBB)) {

                terminInst = startBB->getTerminator();
                is_handled = false;
                
                if(terminInst != nullptr) {
                    // first check if the instruction is affected by cmd value
                    if (terminInst->getNumSuccessors() > 1 && isCmdAffected(terminInst)) {
                        // is this a switch?
                        SwitchInst *dstSwitch = dyn_cast<SwitchInst>(startBB->getTerminator());
                        if (dstSwitch != nullptr) {
#ifdef DIFUZE_DEBUG
                            dbgs() << "Trying switch processing for:" << startBB->getName() << ":" << this->targetFunction->getName() <<"\n";
#endif
                            // is switch handle cmd switch.
                            is_handled = handleCmdSwitch(dstSwitch, totalVisited);
                        } else {
#ifdef DIFUZE_DEBUG
                            dbgs() << "START:Trying branch processing for:" << startBB->getName() << ":" << this->targetFunction->getName() <<"\n";
#endif
                            // not switch?, check if the branch instruction
                            // if this is branch, handle cmd branch
                            BranchInst *brInst = dyn_cast<BranchInst>(terminInst);
                            if (brInst == nullptr) {
                                dbgs() << "Culprit:" << "\n";
                                startBB->dump();
                            }
                            assert(brInst != nullptr);
                            is_handled = handleCmdCond(brInst, totalVisited);
#ifdef DIFUZE_DEBUG
                            dbgs() << "END:Trying branch processing for:" << startBB->getName() << ":" << this->targetFunction->getName() <<"\n";
#endif
                        }
                    }
                }
                if(!is_handled) {
                    // then visit its successors.
                    for (auto sb = succ_begin(startBB), se = succ_end(startBB); sb != se; sb++) {
                        BasicBlock *currSucc = *sb;
#ifdef DIFUZE_DEBUG
            dbgs() << "line 195: visitAllBBs: " <<  currSucc->getName() << ":" << this->targetFunction->getName() <<"\n";
#endif
                        this->visitAllBBs(currSucc, visitedBBs, totalVisited, visitedInThisIteration, depth+1);
                    }
                }
            }
#ifdef DIFUZE_DEBUG
            dbgs() << "line 204: eraseBB: " <<  startBB->getName() << ":" << this->targetFunction->getName() <<"\n";
#endif
            visitedBBs.erase(startBB);
        }
    }

    bool IOInstVisitor::handleCmdSwitch(SwitchInst *targetSwitchInst, std::set<BasicBlock*> &totalVisited) {
#ifdef DIFUZE_DEBUG
        dbgs() << "handleCmdSwitch: " << *targetSwitchInst << "\n";
#endif
        Value *targetSwitchCond = targetSwitchInst->getCondition();
        std::set<BasicBlock*> visitedInThisIteration;
        if(this->isCmdAffected(targetSwitchCond)) {
            // for(auto cis=targetSwitchInst->case_begin(), cie=targetSwitchInst->case_end(); cis != cie; cis++) {
	    for (auto &cis : targetSwitchInst->cases()) {
                ConstantInt *cmdVal = cis.getCaseValue();
                BasicBlock *caseStartBB = cis.getCaseSuccessor();
                std::set<BasicBlock*> visitedBBs;
                visitedBBs.clear();
                // start the print
                //dbgs() << "Num of cases:" << targetSwitchInst->getNumCases() << "\n";
                dbgs() << "Found Cmd:" << cmdVal->getValue().getZExtValue() << ":START\n";
                visitedLIds.clear();
                visitedSIds.clear();
                Instruction *Inst = dyn_cast<Instruction>(&(caseStartBB->front()));
                if (DILocation *Loc = Inst->getDebugLoc()) {
                    unsigned Line = Loc->getLine() - 1;
                    StringRef File = Loc->getFilename();
                    dbgs() << "Cmd In File:"<<File << ":Line:" << Line << "\n";
                }
                std::set<Function*> printedFuncs_backup;
                printedFuncs_backup = std::move(this->printedFuncs);
                // Now visit all the successors
                visitAllBBs(caseStartBB, visitedBBs, totalVisited, visitedInThisIteration, 0);
                this->printedFuncs = std::move(printedFuncs_backup);
                dbgs() << "Found Cmd:" << cmdVal->getValue().getZExtValue() << ":END\n";
            }
            totalVisited.insert(visitedInThisIteration.begin(), visitedInThisIteration.end());
            return true;
        }
        return false;
    }

    bool IOInstVisitor::handleCmdCond(BranchInst *I, std::set<BasicBlock*> &totalVisited) {
        // OK, So, this is a branch instruction,
        // We could possibly have cmd value compared against.
        if(this->currCmdValue != nullptr) {
            //dbgs() << "CMDCOND:::" << *(this->currCmdValue) << "\n";
            std::set<BasicBlock*> visitedBBs;
            visitedBBs.clear();
            std::set<BasicBlock*> visitedInThisIteration;
            Value *cmdValue = this->currCmdValue;
            ConstantInt *cInt = dyn_cast<ConstantInt>(cmdValue);
            if(cInt != nullptr) {
                dbgs() << "Found Cmd(BR):" << cInt->getZExtValue() << "," << cInt->getZExtValue() << ":START\n";
                this->currCmdValue = nullptr;
                for (auto sb = succ_begin(I->getParent()), se = succ_end(I->getParent()); sb != se; sb++) {
                    BasicBlock *currSucc = *sb;
                    if(totalVisited.find(currSucc) == totalVisited.end()) {
                        this->visitAllBBs(currSucc, visitedBBs, totalVisited, visitedInThisIteration, 0);
                    }
                }
                dbgs() << "Found Cmd(BR):" << cInt->getZExtValue() << "," << cInt->getZExtValue() << ":END\n";
                // insert all the visited BBS into total visited.
                totalVisited.insert(visitedInThisIteration.begin(), visitedInThisIteration.end());
                return true;
            }
        }
        return false;
    }

    Function* IOInstVisitor::getFinalFuncTarget(CallInst *I) {
        if(I->getCalledFunction() == nullptr) {
            Value *calledVal = I->getCalledOperand();
            if(dyn_cast<Function>(calledVal)) {
                return dyn_cast<Function>(calledVal->stripPointerCasts());
            }
        }
        return I->getCalledFunction();

    }

    // visitor instructions
    // check if callsite is related to cmd, if so then print
    void IOInstVisitor::visitCallInst(CallInst &I) {
        Function *parentFunc = I.getFunction();
        Function *calledFunc = nullptr;

        if (I.getCalledFunction() != nullptr)
            calledFunc = I.getCalledFunction();
        else
            calledFunc = dyn_cast<Function>(I.getCalledOperand()->stripPointerCasts());

#ifdef DIFUZE_DEBUG
        dbgs() << "visitCallInst: " << I << "\n";
        std::string loc;
		raw_string_ostream rso_loc(loc);
		const DebugLoc &LOC = I.getDebugLoc();
		LOC.print(rso_loc);
        dbgs() << "LOC.print: " << rso_loc.str() << "\n";
#endif
        if (I.getCalledFunction() != nullptr) {
            if (I.getCalledFunction()->getName().str().find("llvm.") == 0)
                return;
            if (I.getCalledFunction()->getName().str().find("binder_ioctl_write_read") != I.getCalledFunction()->getName().str().npos)
                return;
#ifdef DIFUZE_DEBUG
            dbgs() << I.getCalledFunction()->getName().str() << "\n";
            if (I.getCalledFunction()->isDeclaration()==false)
                dbgs() << "I.getCalledFunction()->isDeclaration()==false\n";
            else
                dbgs() << "I.getCalledFunction()->isDeclaration()==true\n";
#endif
        } else {
            Function * calledFunc = dyn_cast<Function>(I.getCalledOperand()->stripPointerCasts());
#ifdef DIFUZE_DEBUG
            if (calledFunc != nullptr) {
                dbgs() << calledFunc->getName() << "\n";
            }
#endif
        }

        if (calledFunc == nullptr) {
            return;
        }
        if (calledFunc != nullptr && calledFunc->isDeclaration()==false && this->printedFuncs.find(calledFunc) == this->printedFuncs.end())
        {
                
            Value::user_iterator it, ie;
            for (it = parentFunc->user_begin(), ie = parentFunc->user_end();
                    it != ie; ++it) {
                if (*it == nullptr) continue;
                CallInst *pCallInst = dyn_cast<CallInst>(*it);
                if (pCallInst == nullptr)
                    continue;
#ifdef DIFUZE_DEBUG
                dbgs() << "check isCmdAffected\n    " << *pCallInst << "\n";
#endif

                if (isCmdAffected(dyn_cast<Instruction>(pCallInst)))
                {
                    this->printedFuncs.insert(calledFunc);
                    dbgs() << "Find callsite, called function name: " << calledFunc->getName().str() << "\n";
                    break;
                }
            }
            // top level ioctl
            if (it == ie)
            {
                if (parentFunc->getName().find("ioctl") != parentFunc->getName().npos)
                this->printedFuncs.insert(calledFunc);
                dbgs() << "Find callsite, called function name: " << calledFunc->getName().str() << "\n";
            }
        }

        Function *dstFunc = this->getFinalFuncTarget(&I);
        if(dstFunc != nullptr) {
            if(dstFunc->isDeclaration()) {
                if(dstFunc->hasName()) {
                    string calledfunc = calledFunc->getName().str();
                    Value *targetOperand = nullptr;
                    Value *srcOperand = nullptr;
                    if(calledfunc.find("_copy_from_user") != string::npos) {
                        //dbgs() << "copy_from_user:\n";
                        if(I.getNumArgOperands() >= 1) {
                            targetOperand = I.getArgOperand(0);
                        }
                        if(I.getNumArgOperands() >= 2) {
                            srcOperand = I.getArgOperand(1);
                        }
                    }
                    if(calledfunc.find("_copy_to_user") != string::npos) {
                        // some idiot doesn't know how to parse
                        /*dbgs() << "copy_to_user:\n";
                        srcOperand = I.getArgOperand(0);
                        targetOperand = I.getArgOperand(1);*/
                    }
                    if(srcOperand != nullptr) {
                        // sanity, this should be user value argument.
                        // only consider value arguments.
                        if(!this->isArgAffected(srcOperand)) {
                            // dbgs() << "Found a copy from user from non-user argument\n";
                            //srcOperand = nullptr;
                            //targetOperand = nullptr;
                        }
                    }
                    if(targetOperand != nullptr) {
                        TypePrintHelper::typeOutputHandler(targetOperand, dbgs(), this);
                    }
                }
            } else {
                // check if maximum function depth is reached.
                if(this->curr_func_depth > MAX_FUNC_DEPTH) {
                    return;
                }
                // we need to follow the called function, only if this is not recursive.
                if(std::find(this->callStack.begin(), this->callStack.end(), &I) == this->callStack.end()) {
                    std::vector<Value*> newCallStack;
                    newCallStack.insert(newCallStack.end(), this->callStack.begin(), this->callStack.end());
                    newCallStack.insert(newCallStack.end(), &I);
                    std::set<int> cmdArg;
                    std::set<int> uArg;
                    std::map<unsigned, Value*> callerArgMap;
                    cmdArg.clear();
                    uArg.clear();
                    callerArgMap.clear();
                    // get propagation info
                    this->getArgPropogationInfo(&I, cmdArg, uArg, callerArgMap);
                    // analyze only if one of the argument is a command or argument
                    if(cmdArg.size() > 0 || uArg.size() > 0) {
                        IOInstVisitor *childFuncVisitor = new IOInstVisitor(dstFunc, cmdArg, uArg, callerArgMap,
                                                                            newCallStack, this,
                                                                            this->curr_func_depth + 1);
                        childFuncVisitor->allCmdInstrs.insert(this->allCmdCallInstrs.begin(), this->allCmdCallInstrs.end());
                        childFuncVisitor->allCmdCallInstrs.insert(this->allCmdCallInstrs.begin(), this->allCmdCallInstrs.end());
                        // do not filter printedFuncs, functions occurs multiple times are some tool-functions, we filter them.
                        // childFuncVisitor->printedFuncs.insert(this->printedFuncs.begin(), this->printedFuncs.end());
                        childFuncVisitor->analyze();
                    }

                }
            }
        } else {
            // check if maximum function depth is reached.
            if(this->curr_func_depth > MAX_FUNC_DEPTH) {
                return;
            }
            if(!I.isInlineAsm()) {
                // TODO: Push the function pointer handling code.

            }
        }
    }

    // get cmd value from comparison instructions
    void IOInstVisitor::visitICmpInst(ICmpInst &I) {
        // check if we doing cmd == comparision.
        if(I.isEquality()) {
            Value *op1 = I.getOperand(0);
            Value *op2 = I.getOperand(1);
            Value *targetValueArg = nullptr;
            if(this->isCmdAffected(op1)) {
                targetValueArg = op2;
            } else if(this->isCmdAffected(op2)) {
                targetValueArg = op1;
            }
            if(targetValueArg != nullptr) {
                //dbgs() << "Setting value for:" << I << "\n";
                this->currCmdValue = targetValueArg;
            }
        }
    }

    bool IOInstVisitor::visitBB(BasicBlock *BB) {
#ifdef DIFUZE_DEBUG
        dbgs() << "START TRYING TO VISIT:" << BB->getName() << ":" << this->targetFunction->getName() << "\n";
#endif
        // call virtual void visit(Instruction &I)
        _super->visit(BB->begin(), BB->end());
#ifdef DIFUZE_DEBUG
        dbgs() << "END TRYING TO VISIT:" << BB->getName() << ":" << this->targetFunction->getName() << "\n";
#endif
        return false;
    }

    void IOInstVisitor::getArgPropogationInfo(CallInst *I, std::set<int> &cmdArg, std::set<int> &uArg,
                                              std::map<unsigned, Value*> &callerArgInfo) {
        int curr_arg_indx = 0;
        for(User::op_iterator arg_begin = I->arg_begin(), arg_end = I->arg_end();
            arg_begin != arg_end; arg_begin++) {
            Value *currArgVal = (*arg_begin).get();
            if(this->isCmdAffected(currArgVal)) {
                cmdArg.insert(curr_arg_indx);
            }
            if(this->isArgAffected(currArgVal)) {
                uArg.insert(curr_arg_indx);
            }
            callerArgInfo[curr_arg_indx] = currArgVal;
            curr_arg_indx++;
        }
    }
}

