//===- MemSSA.cpp -- Base class of pointer analyses------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013-2017>  <Yulei Sui>
//

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//===----------------------------------------------------------------------===//

/*
 * MemSSA.cpp
 *
 *  Created on: Dec 14, 2013
 *      Author: Yulei Sui
 */

#include "SVF-FE/LLVMUtil.h"
#include "MSSA/MemPartition.h"
#include "MSSA/MemSSA.h"
#include "Graphs/SVFGStat.h"
#include "Util/BasicTypes.h"
#include "Util/Annotation.h"
#include <string>
#include <llvm/IR/DebugLoc.h>
#include <llvm/IR/GetElementPtrTypeIterator.h>

//#define DEBUG 1

using namespace KIntAnnotation;
using namespace SVFUtil;


static llvm::cl::opt<bool> DumpRace("dump-race", llvm::cl::init(false),
		llvm::cl::desc(""));
static llvm::cl::opt<bool> DumpMSSA("dump-mssa", llvm::cl::init(false),
                              llvm::cl::desc("Dump memory SSA"));
static llvm::cl::opt<string> MSSAFun("mssafun",  llvm::cl::init(""),
                               llvm::cl::desc("Please specify which function needs to be dumped"));

static llvm::cl::opt<std::string> MemPar("mempar", llvm::cl::value_desc("memory-partition-type"),
                                   llvm::cl::desc("memory partition strategy"));
static std::string kDistinctMemPar = "distinct";
static std::string kIntraDisjointMemPar = "intra-disjoint";
static std::string kInterDisjointMemPar = "inter-disjoint";


double MemSSA::timeOfGeneratingMemRegions = 0;	///< Time for allocating regions
double MemSSA::timeOfCreateMUCHI  = 0;	///< Time for generating mu/chi for load/store/calls
double MemSSA::timeOfInsertingPHI  = 0;	///< Time for inserting phis
double MemSSA::timeOfSSARenaming  = 0;	///< Time for SSA rename

/*!
 * Constructor
 */
MemSSA::MemSSA(BVDataPTAImpl* p, bool ptrOnlyMSSA) : df(NULL),dt(NULL) {
    pta = p;
    assert((pta->getAnalysisTy()!=PointerAnalysis::Default_PTA)
           && "please specify a pointer analysis");

    if (!MemPar.getValue().empty()) {
        std::string strategy = MemPar.getValue();
        if (strategy == kDistinctMemPar)
            mrGen = new DistinctMRG(pta, ptrOnlyMSSA);
        else if (strategy == kIntraDisjointMemPar)
            mrGen = new IntraDisjointMRG(pta, ptrOnlyMSSA);
        else if (strategy == kInterDisjointMemPar)
            mrGen = new InterDisjointMRG(pta, ptrOnlyMSSA);
        else
            assert(false && "unrecognised memory partition strategy");
    }
    else {
        mrGen = new IntraDisjointMRG(pta, ptrOnlyMSSA);
    }

    stat = new MemSSAStat(this);

    /// Generate whole program memory regions
    double mrStart = stat->getClk();
    mrGen->generateMRs();
    double mrEnd = stat->getClk();
    timeOfGeneratingMemRegions += (mrEnd - mrStart)/TIMEINTERVAL;
}

/*!
 * Set DF/DT
 */
void MemSSA::setCurrentDFDT(DominanceFrontier* f, DominatorTree* t) {
    df = f;
    dt = t;
    usedRegs.clear();
    reg2BBMap.clear();
}

/*!
 * Start building memory SSA
 */
void MemSSA::buildMemSSA(const Function& fun, DominanceFrontier* f, DominatorTree* t) {

    assert(!isExtCall(&fun) && "we do not build memory ssa for external functions");

    DBOUT(DMSSA, llvm::outs() << "Building Memory SSA for function " << fun.getName()
          << " \n");

    setCurrentDFDT(f,t);

    /// Create mus/chis for loads/stores/calls for memory regions
    double muchiStart = stat->getClk();
    createMUCHI(fun);
    double muchiEnd = stat->getClk();
    timeOfCreateMUCHI += (muchiEnd - muchiStart)/TIMEINTERVAL;

    /// Insert PHI for memory regions
    double phiStart = stat->getClk();
    insertPHI(fun);
    double phiEnd = stat->getClk();
    timeOfInsertingPHI += (phiEnd - phiStart)/TIMEINTERVAL;

    /// SSA rename for memory regions
    double renameStart = stat->getClk();
    SSARename(fun);
    double renameEnd = stat->getClk();
    timeOfSSARenaming += (renameEnd - renameStart)/TIMEINTERVAL;

}

/*!
 * Create mu/chi according to memory regions
 * collect used mrs in usedRegs and construction map from region to BB for prune SSA phi insertion
 */
void MemSSA::createMUCHI(const Function& fun) {

	PAG* pag = pta->getPAG();

    DBOUT(DMSSA,
          llvm::outs() << "\t creating mu chi for function " << fun.getName()
          << "\n");
    // 1. create mu/chi
    //	insert a set of mus for memory regions at each load
    //  inset a set of chis for memory regions at each store

    // 2. find global names (region name before renaming) of each memory region,
    // collect used mrs in usedRegs, and collect its def basic block in reg2BBMap
    // in the form of mu(r) and r = chi (r)
    // a) mu(r):
    // 		if(r \not\in varKills) global = global \cup r
    // b) r = chi(r):
    // 		if(r \not\in varKills) global = global \cup r
    //		varKills = varKills \cup r
    //		block(r) = block(r) \cup bb_{chi}

    /// get all reachable basic blocks from function entry
    /// ignore dead basic blocks
    BBList reachableBBs;
    getFunReachableBBs(&fun,getDT(fun),reachableBBs);

    for (BBList::const_iterator iter = reachableBBs.begin(), eiter = reachableBBs.end();
            iter != eiter; ++iter) {
        const BasicBlock* bb = *iter;
        varKills.clear();
        for (BasicBlock::const_iterator it = bb->begin(), eit = bb->end();
                it != eit; ++it) {
            const Instruction* inst = &*it;
            if(mrGen->hasPAGEdgeList(inst)) {
                PAGEdgeList& pagEdgeList = mrGen->getPAGEdgesFromInst(inst);
                for (PAGEdgeList::const_iterator bit = pagEdgeList.begin(),
                        ebit = pagEdgeList.end(); bit != ebit; ++bit) {
                    const PAGEdge* inst = *bit;
                    if (const LoadPE* load = SVFUtil::dyn_cast<LoadPE>(inst))
                        AddLoadMU(bb, load, mrGen->getLoadMRSet(load));
                    else if (const StorePE* store = SVFUtil::dyn_cast<StorePE>(inst))
                        AddStoreCHI(bb, store, mrGen->getStoreMRSet(store));
                }
            }
            if (isNonInstricCallSite(inst)) {
                const CallBlockNode* cs = pag->getICFG()->getCallBlockNode(inst);
                if(mrGen->hasRefMRSet(cs))
                    AddCallSiteMU(cs,mrGen->getCallSiteRefMRSet(cs));

                if(mrGen->hasModMRSet(cs))
                    AddCallSiteCHI(cs,mrGen->getCallSiteModMRSet(cs));
            }
        }
    }

    // create entry chi for this function including all memory regions
    // initialize them with version 0 and 1 r_1 = chi (r_0)
    for (MRSet::iterator iter = usedRegs.begin(), eiter = usedRegs.end();
            iter != eiter; ++iter) {
        const MemRegion* mr = *iter;
        // initialize mem region version and stack for renaming phase
        mr2CounterMap[mr] = 0;
        mr2VerStackMap[mr].clear();
        ENTRYCHI* chi = new ENTRYCHI(&fun, mr);
        chi->setOpVer(newSSAName(mr,chi));
        chi->setResVer(newSSAName(mr,chi));
        funToEntryChiSetMap[&fun].insert(chi);

        /// if the function does not have a reachable return instruction from function entry
        /// then we won't create return mu for it
        if(functionDoesNotRet(&fun) == false) {
            RETMU* mu = new RETMU(&fun, mr);
            funToReturnMuSetMap[&fun].insert(mu);
        }

    }

}

/*
 * Insert phi node
 */
void MemSSA::insertPHI(const Function& fun) {

    DBOUT(DMSSA,
          llvm::outs() << "\t insert phi for function " << fun.getName() << "\n");

    const DominanceFrontier* df = getDF(fun);
    // record whether a phi of mr has already been inserted into the bb.
    BBToMRSetMap bb2MRSetMap;

    // start inserting phi node
    for (MRSet::iterator iter = usedRegs.begin(), eiter = usedRegs.end();
            iter != eiter; ++iter) {
        const MemRegion* mr = *iter;

        BBList bbs = reg2BBMap[mr];
        while (!bbs.empty()) {
            const BasicBlock* bb = bbs.back();
            bbs.pop_back();
            dominanceFrontierBase::const_iterator it = df->find(const_cast<BasicBlock*>(bb));
            if(it == df->end()) {
                wrnMsg("bb not in the dominance frontier map??");
                continue;
            }
            const dominanceFrontierBase::DomSetType& domSet = it->second;
            for (dominanceFrontierBase::DomSetType::const_iterator bit =
                        domSet.begin(); bit != domSet.end(); ++bit) {
                const BasicBlock* pbb = *bit;
                // if we never insert this phi node before
                if (0 == bb2MRSetMap[pbb].count(mr)) {
                    bb2MRSetMap[pbb].insert(mr);
                    // insert phi node
                    AddMSSAPHI(pbb,mr);
                    // continue to insert phi in its iterative dominate frontiers
                    bbs.push_back(pbb);
                }
            }
        }
    }

}

/*!
 * SSA construction algorithm
 */
void MemSSA::SSARename(const Function& fun) {

    DBOUT(DMSSA,
          llvm::outs() << "\t ssa rename for function " << fun.getName() << "\n");

    SSARenameBB(fun.getEntryBlock());
}

/*!
 * Renaming for each memory regions
 * See the renaming algorithm in book Engineering A Compiler (Figure 9.12)
 */
void MemSSA::SSARenameBB(const BasicBlock& bb) {

	PAG* pag = pta->getPAG();
    // record which mem region needs to pop stack
    MRVector memRegs;

    // rename phi result op
    // for each r = phi (...)
    // 		rewrite r as new name
    if (hasPHISet(&bb))
        RenamePhiRes(getPHISet(&bb),memRegs);


    // process mu and chi
    // for each mu(r)
    // 		rewrite r with top mrver of stack(r)
    // for each r = chi(r')
    // 		rewrite r' with top mrver of stack(r)
    // 		rewrite r with new name

    for (BasicBlock::const_iterator it = bb.begin(), eit = bb.end();
            it != eit; ++it) {
        const Instruction* inst = &*it;
        if(mrGen->hasPAGEdgeList(inst)) {
            PAGEdgeList& pagEdgeList = mrGen->getPAGEdgesFromInst(inst);
            for(PAGEdgeList::const_iterator bit = pagEdgeList.begin(), ebit= pagEdgeList.end();
                    bit!=ebit; ++bit) {
                const PAGEdge* inst = *bit;
                if (const LoadPE* load = SVFUtil::dyn_cast<LoadPE>(inst))
                    RenameMuSet(getMUSet(load));

                else if (const StorePE* store = SVFUtil::dyn_cast<StorePE>(inst))
                    RenameChiSet(getCHISet(store),memRegs);

            }
        }
        if (isNonInstricCallSite(inst)) {
            const CallBlockNode* cs = pag->getICFG()->getCallBlockNode(inst);
            if(mrGen->hasRefMRSet(cs))
                RenameMuSet(getMUSet(cs));

            if(mrGen->hasModMRSet(cs))
                RenameChiSet(getCHISet(cs),memRegs);
        }
        else if(isReturn(inst)) {
            RenameMuSet(getReturnMuSet(bb.getParent()));
        }
    }


    // fill phi operands of succ basic blocks
    for (succ_const_iterator sit = succ_begin(&bb), esit = succ_end(&bb);
            sit != esit; ++sit) {
        const BasicBlock* succ = *sit;
        u32_t pos = getBBPredecessorPos(&bb, succ);
        if (hasPHISet(succ))
            RenamePhiOps(getPHISet(succ),pos,memRegs);
    }

    // for succ basic block in dominator tree
    DominatorTree* dt = getDT(*bb.getParent());
    if(DomTreeNode *dtNode = dt->getNode(const_cast<BasicBlock*>(&bb))) {
        for (DomTreeNode::iterator DI = dtNode->begin(), DE = dtNode->end();
                DI != DE; ++DI) {
            SSARenameBB(*((*DI)->getBlock()));
        }
    }
    // for each r = chi(..), and r = phi(..)
    // 		pop ver stack(r)
    while (!memRegs.empty()) {
        const MemRegion* mr = memRegs.back();
        memRegs.pop_back();
        mr2VerStackMap[mr].pop_back();
    }

}

MRVer* MemSSA::newSSAName(const MemRegion* mr, MSSADEF* def) {
    assert(0 != mr2CounterMap.count(mr)
           && "did not find initial version in map? ");
    assert(0 != mr2VerStackMap.count(mr)
           && "did not find initial stack in map? ");

    VERSION version = mr2CounterMap[mr];
    mr2CounterMap[mr] = version + 1;
    MRVer* mrVer = new MRVer(mr, version, def);
    mr2VerStackMap[mr].push_back(mrVer);
    return mrVer;
}

/*!
 * Clean up memory
 */
void MemSSA::destroy() {

    for (LoadToMUSetMap::iterator iter = load2MuSetMap.begin(), eiter =
                load2MuSetMap.end(); iter != eiter; ++iter) {
        for (MUSet::iterator it = iter->second.begin(), eit =
                    iter->second.end(); it != eit; ++it) {
            delete *it;
        }
    }

    for (StoreToChiSetMap::iterator iter = store2ChiSetMap.begin(), eiter =
                store2ChiSetMap.end(); iter != eiter; ++iter) {
        for (CHISet::iterator it = iter->second.begin(), eit =
                    iter->second.end(); it != eit; ++it) {
            delete *it;
        }
    }

    for (CallSiteToMUSetMap::iterator iter = callsiteToMuSetMap.begin(),
            eiter = callsiteToMuSetMap.end(); iter != eiter; ++iter) {
        for (MUSet::iterator it = iter->second.begin(), eit =
                    iter->second.end(); it != eit; ++it) {
            delete *it;
        }
    }

    for (CallSiteToCHISetMap::iterator iter = callsiteToChiSetMap.begin(),
            eiter = callsiteToChiSetMap.end(); iter != eiter; ++iter) {
        for (CHISet::iterator it = iter->second.begin(), eit =
                    iter->second.end(); it != eit; ++it) {
            delete *it;
        }
    }

    for (FunToEntryChiSetMap::iterator iter = funToEntryChiSetMap.begin(),
            eiter = funToEntryChiSetMap.end(); iter != eiter; ++iter) {
        for (CHISet::iterator it = iter->second.begin(), eit =
                    iter->second.end(); it != eit; ++it) {
            delete *it;
        }
    }

    for (FunToReturnMuSetMap::iterator iter = funToReturnMuSetMap.begin(),
            eiter = funToReturnMuSetMap.end(); iter != eiter; ++iter) {
        for (MUSet::iterator it = iter->second.begin(), eit =
                    iter->second.end(); it != eit; ++it) {
            delete *it;
        }
    }

    for (BBToPhiSetMap::iterator iter = bb2PhiSetMap.begin(), eiter =
                bb2PhiSetMap.end(); iter != eiter; ++iter) {
        for (PHISet::iterator it = iter->second.begin(), eit =
                    iter->second.end(); it != eit; ++it) {
            delete *it;
        }
    }

    delete mrGen;
    mrGen = NULL;
    delete stat;
    stat = NULL;
    pta = NULL;
}

/*!
 * Perform statistics
 */
void MemSSA::performStat() {
    if(pta->printStat())
        stat->performStat();
}

/*!
 * Get loadMU numbers
 */
u32_t MemSSA::getLoadMuNum() const
{
    u32_t num = 0;
    LoadToMUSetMap::const_iterator it = load2MuSetMap.begin();
    LoadToMUSetMap::const_iterator eit = load2MuSetMap.end();
    for (; it != eit; it++) {
        const MUSet & muSet = it->second;
        num+= muSet.size();
    }
    return num;
}


/*!
 * Get StoreCHI numbers
 */
u32_t MemSSA::getStoreChiNum() const
{
    u32_t num = 0;
    StoreToChiSetMap::const_iterator it = store2ChiSetMap.begin();
    StoreToChiSetMap::const_iterator eit = store2ChiSetMap.end();
    for (; it != eit; it++) {
        const CHISet& chiSet = it->second;
        num += chiSet.size();
    }
    return num;
}


/*!
 * Get EntryCHI numbers
 */
u32_t MemSSA::getFunEntryChiNum() const
{
    u32_t num = 0;
    FunToEntryChiSetMap::const_iterator it = funToEntryChiSetMap.begin();
    FunToEntryChiSetMap::const_iterator eit = funToEntryChiSetMap.end();
    for (; it != eit; it++) {
        const CHISet& chiSet = it->second;
        num += chiSet.size();
    }
    return num;
}


/*!
 * Get RetMU numbers
 */
u32_t MemSSA::getFunRetMuNum() const
{
    u32_t num = 0;
    FunToReturnMuSetMap::const_iterator it = funToReturnMuSetMap.begin();
    FunToReturnMuSetMap::const_iterator eit = funToReturnMuSetMap.end();
    for (; it != eit; it++) {
        const MUSet & muSet = it->second;
        num+= muSet.size();
    }
    return num;
}


/*!
 * Get CallMU numbers
 */
u32_t MemSSA::getCallSiteMuNum() const
{
    u32_t num = 0;
    CallSiteToMUSetMap::const_iterator it = callsiteToMuSetMap.begin();
    CallSiteToMUSetMap::const_iterator eit = callsiteToMuSetMap.end();
    for (; it != eit; it++) {
        const MUSet & muSet = it->second;
        num+= muSet.size();
    }
    return num;
}


/*!
 * Get CallCHI numbers
 */
u32_t MemSSA::getCallSiteChiNum() const
{
    u32_t num = 0;
    CallSiteToCHISetMap::const_iterator it = callsiteToChiSetMap.begin();
    CallSiteToCHISetMap::const_iterator eit = callsiteToChiSetMap.end();
    for (; it != eit; it++) {
        const CHISet & chiSet = it->second;
        num+= chiSet.size();
    }
    return num;
}


/*!
 * Get PHI numbers
 */
u32_t MemSSA::getBBPhiNum() const
{
    u32_t num = 0;
    BBToPhiSetMap::const_iterator it = bb2PhiSetMap.begin();
    BBToPhiSetMap::const_iterator eit = bb2PhiSetMap.end();
    for (; it != eit; it++) {
        const PHISet & phiSet = it->second;
        num+= phiSet.size();
    }
    return num;
}


static bool isStackAccess(llvm::Value *the_value) {

	if (llvm::AllocaInst *ai = SVFUtil::dyn_cast<llvm::AllocaInst>(the_value)) {
		return true;
	} else if (StoreInst *si = SVFUtil::dyn_cast<llvm::StoreInst>(the_value)) {
		return isStackAccess(si->getPointerOperand());
	} else if (LoadInst *li = SVFUtil::dyn_cast<llvm::LoadInst>(the_value)) {
		return isStackAccess(li->getPointerOperand());
	} else if (CastInst *ci = SVFUtil::dyn_cast<llvm::CastInst>(the_value)) {
		return isStackAccess(ci->getOperand(0));
	}

	return false;
}

// modified by sgh0t
static inline void printType(llvm::Instruction &inst, llvm::raw_ostream& Out) {
	//       What I'm interested in is
	//       1. load
	//       2. store
	//       3. Extcall
	//       3-1. memcpy
	//       3-2. memmove
	//       3-3. ?
	//       4. ?
	Out << "({";
	if (LoadInst *li = SVFUtil::dyn_cast<llvm::LoadInst>(&inst)) {
        Out << getLoadId(li);
	} else if(StoreInst *si = SVFUtil::dyn_cast<llvm::StoreInst>(&inst)) {
		Out << getStoreId(si);
	}

	// I don't exit the program in the case that I don't expect
	// In that case, result file will contain ({}) and I can string search it to identify what I missed.
	Out << "})";
}



/*!
 * Print SSA
 */
void MemSSA::dumpMSSA(llvm::raw_ostream& Out) {
	if (!DumpMSSA)
		return;

    PAG* pag = pta->getPAG();
	for (SVFModule::iterator fit = pta->getModule()->begin(), efit = pta->getModule()->end();
			fit != efit; ++fit) {
		Function& fun = **fit;
		if(MSSAFun!="" && MSSAFun!=fun.getName())
			continue;

		Out << "==========FUNCTION: " << fun.getName() << "==========\n";
		// dump function entry chi nodes
		if (hasFuncEntryChi(&fun) && !DumpRace) { // I don't need ENCHI
			CHISet & entry_chis = getFuncEntryChiSet(&fun);
			for (CHISet::iterator chi_it = entry_chis.begin(); chi_it != entry_chis.end(); chi_it++) {
                Out << "[+] hasFuncEntryChi: \n";
				(*chi_it)->dump();
			}
		}

		for (Function::iterator bit = fun.begin(), ebit = fun.end();
				bit != ebit; ++bit) {
			BasicBlock& bb = *bit;
			if (bb.hasName() && !DumpRace) // I don't need the bb name
				Out << bb.getName() << "\n";
			PHISet& phiSet = getPHISet(&bb);
			for(PHISet::iterator pi = phiSet.begin(), epi = phiSet.end(); !DumpRace && pi !=epi; ++pi) { // Also I don't have any interest on PHI
                Out << "[+] PHISet: \n";
				(*pi)->dump();
			}

			bool last_is_chi = false;
			for (BasicBlock::iterator it = bb.begin(), eit = bb.end();
					it != eit; ++it) {
				Instruction& inst = *it;
#ifdef DEBUG
                Out << "\ncurrent instruction: \n";
                inst.print(Out);
                Out << "\n";
#endif
				if (isCallSite(&inst) && isExtCall(&inst)==false && !DumpRace) {
					const CallBlockNode* cs = pag->getICFG()->getCallBlockNode(&inst);
					if(hasMU(cs)) {
						if (!last_is_chi) {
							Out << "\n";
						}
						for (MUSet::iterator mit = getMUSet(cs).begin(), emit = getMUSet(cs).end();
								mit != emit; ++mit) {
                            Out << "[+] CallSite MUSet: \n";
							(*mit)->dump();
						}
					}

					Out << inst << "\n";

					if(hasCHI(cs)) {
						for (CHISet::iterator cit = getCHISet(cs).begin(), ecit = getCHISet(cs).end();
								cit != ecit; ++cit) {
                            Out << "[+] CallSite CHISet: \n";
							(*cit)->dump();
						}
						Out << "\n";
						last_is_chi = true;
					}
					else
						last_is_chi = false;
				}
				else {
					bool dump_preamble = false;
					bool has_chi_or_mu = false;
					bool has_debug_loc = (inst.getDebugLoc() || !DumpRace);
                    // Out << "has_debug_loc : " << has_debug_loc << "\n";

					PAGEdgeList& pagEdgeList = mrGen->getPAGEdgesFromInst(&inst);
					// if (isStackAccess(&inst)) {
                    //     Out << "isStackAccess\n";
					// 	continue;
                    // }
					for(PAGEdgeList::const_iterator bit = pagEdgeList.begin(), ebit= pagEdgeList.end();
							bit!=ebit && has_debug_loc; ++bit) {
						const PAGEdge* edge = *bit;
#ifdef DEBUG
                        llvm::outs() << "srcID: " << edge->getSrcID() << " dstID: " << edge->getDstID() << "\n";
#endif
						if (const LoadPE* load = dyn_cast<LoadPE>(edge)) {
                            // Out << "is loadInst\n";
							MUSet& muSet = getMUSet(load);
							for(MUSet::iterator it = muSet.begin(), eit = muSet.end(); it!=eit; ++it) {
								if (!dump_preamble && !last_is_chi) {
									Out << "\n";
									dump_preamble = true;
								}
								has_chi_or_mu = true;
                                Out << "[+] LoadInst MUSet: \n";
								(*it)->dump();
							}
						}
					}

					if (!DumpRace) {
						Out << inst << "\n";
					}

					bool has_chi = false;
					for(PAGEdgeList::const_iterator bit = pagEdgeList.begin(), ebit= pagEdgeList.end();
							bit!=ebit && has_debug_loc; ++bit) {
						const PAGEdge* edge = *bit;
						if (const StorePE* store = dyn_cast<StorePE>(edge)) {
                            // Out << "is StoreInst\n";
							CHISet& chiSet = getCHISet(store);
							for(CHISet::iterator it = chiSet.begin(), eit = chiSet.end(); it!=eit; ++it) {
								has_chi = true;
								has_chi_or_mu = true;
                                Out << "[+] StoreInst CHISet: \n";
								(*it)->dump();
							}
						}
					}

					if (DumpRace && has_chi_or_mu) {
						// Print out the debug location
						if (inst.getDebugLoc()) { // Here I is an LLVM instruction
                            const llvm::DebugLoc &Loc = inst.getDebugLoc();
							Out << "\t[[";
							Loc.print(Out);
							Out << "]]";
							// Print out the type
                            // todo modified by sgh0t
							printType(inst, Out);
							Out << '\n';
						}
					}

					if (has_chi) {
						Out << "\n";
						last_is_chi = true;
					}
					else
						last_is_chi = false;
				}
			}
		}

		// dump return mu nodes
		if (hasReturnMu(&fun) && !DumpRace) {
			MUSet & return_mus = getReturnMuSet(&fun);
			for (MUSet::iterator mu_it = return_mus.begin(); mu_it != return_mus.end(); mu_it++) {
                Out << "[+] getReturnMuSet: \n";
				(*mu_it)->dump();
			}
		}
	}
}