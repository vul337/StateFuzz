/*
 * Call graph construction
 *
 * Copyright (C) 2012 Xi Wang, Haogang Chen, Nickolai Zeldovich
 * Copyright (C) 2015 - 2016 Chengyu Song 
 * Copyright (C) 2016 Kangjie Lu
 *
 * For licensing details see LICENSE
 */


// add MLTA from CCS 2019 Kangjie Lu's paper, which is the best paper award winner

/*
 processInitializers: 
    Recursively handle scenarios where variable variables are initialized with function pointers
    If initialized to a structure, recursively process structure members to see if any members are function pointers
    The structure uses getOperand(i) to access the members
doModulePass
    doFunctionPass
 */

#include <llvm/IR/DebugInfo.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/Debug.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/IR/Operator.h>

#include "CallGraph.h"
#include "Annotation.h"
#include "Common.h"

#define TYPE_BASED
#define MLTA_BASED
#define OS llvm::errs()
#define Diag llvm::errs()
// #define DEBUG
// #define DEBUG_MLTA

using namespace llvm;
using namespace std;

std::map<std::string, int> CallerCountMap;
std::map<std::string, int> CalleeCountMap;
DenseMap<size_t, FuncSet> typeFuncsMap;
unordered_map<size_t, set<size_t>> typeConfineMap;
unordered_map<size_t, set<size_t>> typeTransitMap;
set<size_t> typeEscapeSet;

std::string extract_str(std::string str, std::string pattern)
{
    std::string raw_str;
    std::string::size_type pos;
    std::vector<std::string> result;
    raw_str = str;
    // extend string length
    str += pattern;
    int size = str.size();

    if (str.find(pattern, 0) >= raw_str.size() || str.find("\n", 0) < raw_str.size())
    {
        return raw_str;
    }
    for (int i = 0; i < size; i++)
    {
        pos = str.find(pattern, i);
        if (pos < size && pos >= i)
        {
            std::string s = str.substr(i, pos - i);
            result.push_back(s);
            i = pos + pattern.size() - 1;
        }
    }
    if (result.size() <= 1)
        return raw_str;
    return result[result.size() - 1];
}

Function *CallGraphPass::getFuncDef(Function *F)
{
    FuncMap::iterator it = Ctx->Funcs.find(extract_str(getScopeName(F), ".llvm."));
    if (it != Ctx->Funcs.end())
        return it->second;
    else
        return F;
}

bool CallGraphPass::isCompositeType(Type *Ty)
{
    if (Ty->isStructTy() || Ty->isArrayTy() || Ty->isVectorTy())
        return true;
    else
        return false;
}

// Get the composite type of the lower layer. Layers are split by
// memory loads
Value *CallGraphPass:: nextLayerBaseType(Value *V, Type * &BTy, 
		int &Idx, const DataLayout *DL) {

#ifdef DEBUG
    errs() << " get nextLayerBaseType from: " << *V << "\n";
#endif
	// Two ways to get the next layer type: GetElementPtrInst and
	// LoadInst
	// Case 1: GetElementPtrInst
	if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(V)) {
		Type *PTy = GEP->getPointerOperand()->getType();
		Type *Ty = PTy->getPointerElementType();
		if ((Ty->isStructTy() || Ty->isArrayTy() || Ty->isVectorTy()) 
				&& GEP->hasAllConstantIndices()) {
			BTy = Ty;
			User::op_iterator ie = GEP->idx_end();
			ConstantInt *ConstI = dyn_cast<ConstantInt>((--ie)->get());
			Idx = ConstI->getSExtValue();
			return GEP->getPointerOperand();
		}
		else
			return NULL;
	}
	// Case 2: LoadInst
	else if (LoadInst *LI = dyn_cast<LoadInst>(V)) {
		return nextLayerBaseType(LI->getOperand(0), BTy, Idx, DL);
	}
	// Other instructions such as CastInst
	// FIXME: may introduce false positives
#if 1
	else if (UnaryInstruction *UI = dyn_cast<UnaryInstruction>(V)) {
		return nextLayerBaseType(UI->getOperand(0), BTy, Idx, DL);
	}
#endif
	else
		return NULL;
}

bool CallGraphPass::isCompatibleType(Type *T1, Type *T2)
{
    if (T1->isPointerTy())
    {
        if (!T2->isPointerTy())
            return false;

        Type *ElT1 = T1->getPointerElementType();
        Type *ElT2 = T2->getPointerElementType();
        // assume "void *" and "char *" are equivalent to any pointer type
        if (ElT1->isIntegerTy(8) /*|| ElT2->isIntegerTy(8)*/)
            return true;

        return isCompatibleType(ElT1, ElT2);
    }
    else if (T1->isArrayTy())
    {
        if (!T2->isArrayTy())
            return false;

        Type *ElT1 = T1->getArrayElementType();
        Type *ElT2 = T2->getArrayElementType();
        return isCompatibleType(ElT1, ElT1);
    }
    else if (T1->isIntegerTy())
    {
        // assume pointer can be cased to the address space size
        if (T2->isPointerTy() && T1->getIntegerBitWidth() == T2->getPointerAddressSpace())
            return true;

        // assume all integer type are compatible
        if (T2->isIntegerTy())
            return true;
        else
            return false;
    }
    else if (T1->isStructTy())
    {
        StructType *ST1 = cast<StructType>(T1);
        StructType *ST2 = dyn_cast<StructType>(T2);
        if (!ST2)
            return false;

        // literal has to be equal
        if (ST1->isLiteral() != ST2->isLiteral())
            return false;

        // literal, compare content
        if (ST1->isLiteral())
        {
            unsigned numEl1 = ST1->getNumElements();
            if (numEl1 != ST2->getNumElements())
                return false;

            for (unsigned i = 0; i < numEl1; ++i)
            {
                if (!isCompatibleType(ST1->getElementType(i), ST2->getElementType(i)))
                    return false;
            }
            return true;
        }

        // not literal, use name?
        return ST1->getStructName().equals(ST2->getStructName());
    }
    else if (T1->isFunctionTy())
    {
        FunctionType *FT1 = cast<FunctionType>(T1);
        FunctionType *FT2 = dyn_cast<FunctionType>(T2);
        if (!FT2)
            return false;

        if (!isCompatibleType(FT1->getReturnType(), FT2->getReturnType()))
            return false;

        // assume varg is always compatible with varg?
        if (FT1->isVarArg())
        {
            if (FT2->isVarArg())
                return true;
            else
                return false;
        }

        // compare args, again ...
        unsigned numParam1 = FT1->getNumParams();
        if (numParam1 != FT2->getNumParams())
            return false;

        for (unsigned i = 0; i < numParam1; ++i)
        {
            if (!isCompatibleType(FT1->getParamType(i), FT2->getParamType(i)))
                return false;
        }
        return true;
    }
    else
    {
        // errs() << "Unhandled Types:" << *T1 << " :: " << *T2 << "\n";
        return T1->getTypeID() == T2->getTypeID();
    }
}

// find callees for indirect call based on type_based approach
bool CallGraphPass::findCalleesByType(CallInst *CI, FuncSet &FS)
{
    auto *CB = dyn_cast<CallBase>(CI);
    // errs() << "Indirect Call: " << *CI << "\n";
    for (Function *F : Ctx->AddressTakenFuncs)
    {

        // just compare known args
        if (F->getFunctionType()->isVarArg())
        {
            errs() << "VarArg: " << F->getName() << "\n";
            //report_fatal_error("VarArg address taken function\n");
        }
        else if (F->arg_size() != CB->arg_size())
        {
            // errs() << "ArgNum mismatch: " << F->getName() << "\n";
            continue;
        }
        // Check whether the return value type is consistent, 
        // that is, the return value of addresstaken function F and the return value of CallSite
        else if (!isCompatibleType(F->getReturnType(), CI->getType()))
        {
            continue;
        }
        if (F->isIntrinsic())
        {
            // errs() << "Intrinsic: " << F->getName() << "\n";
            continue;
        }

        // type matching on args
        // match arguments one by one
        bool Matched = true;
        auto AI = CB->arg_begin();
        for (Function::arg_iterator FI = F->arg_begin(), FE = F->arg_end(); FI != FE; ++FI, ++AI)
        {
            // check type mis-match
            Type *FormalTy = FI->getType();
            Type *ActualTy = (*AI)->getType();

            if (isCompatibleType(FormalTy, ActualTy))
                continue;
            else
            {
                Matched = false;
                break;
            }
        }

        if (Matched)
        {
            FS.insert(F);
        }
    }

    return false;
}

bool CallGraphPass::findCalleesByMLTASingleLayer(CallInst *CI, FuncSet &FS) {

    // Initial set: first-layer results
    FuncSet FS1 = Ctx->sigFuncsMap[callHash(CI)];
    if (FS1.size() == 0) {
        // No need to go through MLTA if the first layer is empty
#ifdef DEBUG_MLTA
        errs() << "Call Inst: " << *CI << "\n";
        errs() << "no FuncSet found for callhash: " << callHash(CI) << "\n";
#endif
        return false;
    }

    FuncSet FS2, FST;

    Type *LayerTy = NULL;
    int FieldIdx = -1;
    Value *CV = CI->getCalledOperand();

#ifdef DEBUG_MLTA
    errs() << "---------------------start MLTA-------------------------\n";
    errs() << "Call Inst: " << *CI << "\n";
    errs() << "Call Inst belongs to Function: " << CI->getFunction()->getName() << "\n";
    errs() << "Call Inst belogns to Module: " << CI->getModule()->getName() << "\n";
    errs() << "Called Value: " << *CV << "\n";
#endif // DEBUG
    // Get the second-layer type
    CV = nextLayerBaseType(CV, LayerTy, FieldIdx, DL);
    int LayerNo = 1;

    if (CV) {
        // Step 1: ensure the type hasn't escaped
        if ((typeEscapeSet.find(typeHash(LayerTy)) != typeEscapeSet.end()) || 
                (typeEscapeSet.find(typeIdxHash(LayerTy, FieldIdx)) !=
                 typeEscapeSet.end())) {
            errs() << "Type Escaped" << "\n";
        } else {
        // Step 2: get the funcset and merge
            ++LayerNo;
#ifdef DEBUG_MLTA
            // errs() << "Current Value" << *CV << "\n";
            errs() << "-------------------------------\nLayerNo: " << LayerNo << "\n";
            errs() << "Layer Type: " << *LayerTy << ", offset: " << FieldIdx << "\n";
            errs() << "typeIdxHash: " << typeIdxHash(LayerTy, FieldIdx) << "\n";
            errs() << "-------------------------------\n";
#endif // DEBUG
            FS2 = typeFuncsMap[typeIdxHash(LayerTy, FieldIdx)];
            FST.clear();
            funcSetIntersection(FS1, FS2, FST);
#ifdef DEBUG_MLTA
            errs() << "Last level FS1 size: " << FS1.size() << "\n";
            for (auto F : FS1){
                // errs() << F << "\n";
                errs() << F->getName() << "; ";
                errs() << "\n";
            }
            errs() << "Current level FS2 size: " << FS2.size() << "\n";
            for (auto F : FS2){
                // errs() << F << "\n";
                errs() << F->getName() << "; ";
                errs() << "\n";
            }
            errs() << "Intersection FST size: " << FST.size() << "\n";
#endif // DEBUG

        // Step 3: get transitted funcsets and merge
        // NOTE: this nested loop can be slow
#if 1
            unsigned TH = typeHash(LayerTy);
            list<unsigned> LT;
            LT.push_back(TH);
            while (!LT.empty()) {
                unsigned CT = LT.front();
                LT.pop_front();

                for (auto H : typeTransitMap[CT]) {
                    FS2 = typeFuncsMap[hashIdxHash(H, FieldIdx)];
                    FST.clear();
                    funcSetIntersection(FS1, FS2, FST);
                    FS1 = FST;
                }
            }
#endif
        }
        FS1 = FST;
    }

    FS = FS1;
#ifdef DEBUG_MLTA
    errs() << "Final FS size: " << FS.size() << "\n";
    for (auto F : FS)
    {
        // errs() << F << "\n";
        errs() << F->getName() << "; ";
        errs() << "\n";
    }
    errs() << "---------------------end MLTA-------------------------\n";
#endif // DEBUG
    return true;
}


// find callees for indirect call based on MLTA approach
bool CallGraphPass::findCalleesByMLTA(CallInst *CI, FuncSet &FS) {

	// Initial set: first-layer results
	FuncSet FS1 = Ctx->sigFuncsMap[callHash(CI)];
	if (FS1.size() == 0) {
		// No need to go through MLTA if the first layer is empty
		return false;
	}

	FuncSet FS2, FST;

	Type *LayerTy = NULL;
	int FieldIdx = -1;
	Value *CV = CI->getCalledOperand();

	// Get the second-layer type
	CV = nextLayerBaseType(CV, LayerTy, FieldIdx, DL);

	int LayerNo = 1;
	while (CV) {
		// Step 1: ensure the type hasn't escaped
#if 1
		if ((typeEscapeSet.find(typeHash(LayerTy)) != typeEscapeSet.end()) || 
				(typeEscapeSet.find(typeIdxHash(LayerTy, FieldIdx)) !=
				 typeEscapeSet.end())) {

			break;
		}
#endif

		// Step 2: get the funcset and merge
		++LayerNo;
        // errs() << "LayerNo: " << LayerNo << "\n";
		FS2 = typeFuncsMap[typeIdxHash(LayerTy, FieldIdx)];
		FST.clear();
		//FS2非空
        if (!FS2.empty()){
            funcSetIntersection(FS1, FS2, FST);
#ifdef DEBUG
            errs() << "Last level FS1 size: " << FS1.size() << "\n";
            for (auto F : FS1){
                errs() << F << "\n";
                errs() << F->getName() << "; ";
                errs() << "\n";
            }
            errs() << "Current level FS2 size: " << FS2.size() << "\n";
            for (auto F : FS2){
                errs() << F << "\n";
                errs() << F->getName() << "; ";
                errs() << "\n";
            }
            errs() << "Intersection FST size: " << FST.size() << "\n";
#endif // DEBUG
        }
        else {
            //FS2为空，没有候选Callee，为了避免漏报，使用上一轮的匹配结果作为输出。
#ifdef DEBUG
            errs() << "Current level FS2 empty!\n";
#endif // DEBUG
            break;
        }


		// Step 3: get transitted funcsets and merge
		// NOTE: this nested loop can be slow
#if 1
		unsigned TH = typeHash(LayerTy);
		list<unsigned> LT;
		LT.push_back(TH);
		while (!LT.empty()) {
			unsigned CT = LT.front();
			LT.pop_front();

			for (auto H : typeTransitMap[CT]) {
				FS2 = typeFuncsMap[hashIdxHash(H, FieldIdx)];
				FST.clear();
				funcSetIntersection(FS1, FS2, FST);
				FS1 = FST;
			}
		}
#endif

		// Step 4: go to a lower layer
		CV = nextLayerBaseType(CV, LayerTy, FieldIdx, DL);
		FS1 = FST;
	}

	FS = FS1;

	return true;
}

void CallGraphPass::funcSetIntersection(FuncSet &FS1, FuncSet &FS2,
                                        FuncSet &FS)
{
    FS.clear();
    for (auto F : FS1) {
      for (auto F2 : FS2) {
        if (F->getName() == F2->getName())
          FS.insert(F);
      }
    }
}

bool CallGraphPass::mergeFuncSet(FuncSet &S, const std::string &Id, bool InsertEmpty)
{
    FuncPtrMap::iterator i = Ctx->FuncPtrs.find(Id);
    if (i != Ctx->FuncPtrs.end())
        return mergeFuncSet(S, i->second);
    else if (InsertEmpty)
        Ctx->FuncPtrs.insert(std::make_pair(Id, FuncSet()));
    return false;
}

bool CallGraphPass::mergeFuncSet(std::string &Id, const FuncSet &S, bool InsertEmpty)
{
    FuncPtrMap::iterator i = Ctx->FuncPtrs.find(Id);
    if (i != Ctx->FuncPtrs.end())
        return mergeFuncSet(i->second, S);
    else if (!S.empty())
        return mergeFuncSet(Ctx->FuncPtrs[Id], S);
    else if (InsertEmpty)
        Ctx->FuncPtrs.insert(std::make_pair(Id, FuncSet()));
    return false;
}

bool CallGraphPass::mergeFuncSet(FuncSet &Dst, const FuncSet &Src)
{
    bool Changed = false;
    for (FuncSet::const_iterator i = Src.begin(), e = Src.end(); i != e; ++i)
    {
        assert(*i);
        Changed |= Dst.insert(*i).second;
    }
    return Changed;
}

bool CallGraphPass::findFunctions(Value *V, FuncSet &S)
{
    SmallPtrSet<Value *, 4> Visited;
    return findFunctions(V, S, Visited);
}

bool CallGraphPass::findFunctions(Value *V, FuncSet &S,
                                  SmallPtrSet<Value *, 4> Visited)
{
    if (!Visited.insert(V).second)
        return false;

    // real function, S = S + {F}
    if (Function *F = dyn_cast<Function>(V))
    {
        // prefer the real definition to declarations
        F = getFuncDef(F);
        return S.insert(F).second;
    }

    // bitcast, ignore the cast
    if (CastInst *B = dyn_cast<CastInst>(V))
        return findFunctions(B->getOperand(0), S, Visited);

    // const bitcast, ignore the cast
    if (ConstantExpr *C = dyn_cast<ConstantExpr>(V))
    {
        if (C->isCast())
        {
            return findFunctions(C->getOperand(0), S, Visited);
        }
        // FIXME GEP
    }

    if (GetElementPtrInst *G = dyn_cast<GetElementPtrInst>(V))
    {
        return false;
    }
    else if (isa<ExtractValueInst>(V))
    {
        return false;
    }

    if (isa<AllocaInst>(V))
    {
        return false;
    }

    if (BinaryOperator *BO = dyn_cast<BinaryOperator>(V))
    {
        Value *op0 = BO->getOperand(0);
        Value *op1 = BO->getOperand(1);
        if (!isa<Constant>(op0) && isa<Constant>(op1))
            return findFunctions(op0, S, Visited);
        else if (isa<Constant>(op0) && !isa<Constant>(op1))
            return findFunctions(op1, S, Visited);
        else
            return false;
    }

    // PHI node, recursively collect all incoming values
    if (PHINode *P = dyn_cast<PHINode>(V))
    {
        bool Changed = false;
        for (unsigned i = 0; i != P->getNumIncomingValues(); ++i)
            Changed |= findFunctions(P->getIncomingValue(i), S, Visited);
        return Changed;
    }

    // select, recursively collect both paths
    if (SelectInst *SI = dyn_cast<SelectInst>(V))
    {
        bool Changed = false;
        Changed |= findFunctions(SI->getTrueValue(), S, Visited);
        Changed |= findFunctions(SI->getFalseValue(), S, Visited);
        return Changed;
    }

    // arguement, S = S + FuncPtrs[arg.ID]
    if (Argument *A = dyn_cast<Argument>(V))
    {
        bool InsertEmpty = isFunctionPointer(A->getType());
        return mergeFuncSet(S, getArgId(A), InsertEmpty);
    }

    // return value, S = S + FuncPtrs[ret.ID]
    if (CallInst *CI = dyn_cast<CallInst>(V))
    {
        // update callsite info first
        FuncSet &FS = Ctx->Callees[CI];
        //FS.setCallerInfo(CI, &Ctx->Callers);
        findFunctions(CI->getCalledOperand(), FS);
        bool Changed = false;
        for (Function *CF : FS)
        {
            bool InsertEmpty = isFunctionPointer(CI->getType());
            Changed |= mergeFuncSet(S, getRetId(CF), InsertEmpty);
        }
        return Changed;
    }

    // loads, S = S + FuncPtrs[struct.ID]
    if (LoadInst *L = dyn_cast<LoadInst>(V))
    {
        std::string Id = getLoadId(L);
        if (!Id.empty())
        {
            bool InsertEmpty = isFunctionPointer(L->getType());
            return mergeFuncSet(S, Id, InsertEmpty);
        }
        else
        {
            Function *f = L->getParent()->getParent();
            // errs() << "Empty LoadID: " << extract_str(f->getName(), ".llvm.") << "::" << *L << "\n";
            return false;
        }
    }

    // ignore other constant (usually null), inline asm and inttoptr
    if (isa<Constant>(V) || isa<InlineAsm>(V) || isa<IntToPtrInst>(V))
        return false;

    //V->dump();
    //report_fatal_error("findFunctions: unhandled value type\n");
    // errs() << "findFunctions: unhandled value type: " << *V << "\n";
    return false;
}

bool CallGraphPass::findCallees(CallInst *CI, FuncSet &FS)
{
#ifdef DEBUG
    Diag << "findCallees for " << *CI << "\n";
#endif
    Function *CF = CI->getCalledFunction();

    if (CF)
    {
        // prefer the real definition to declarations
        CF = getFuncDef(CF);
        // errs() << "direct call: " << CF->getName() << "\n";
        return FS.insert(CF).second;
    }

    // save called values for point-to analysis
    Ctx->IndirectCallInsts.push_back(CI);

#ifdef MLTA_BASED
    // return findCalleesByMLTA(CI, FS);
    return findCalleesByMLTASingleLayer(CI, FS);
#endif

#ifdef TYPE_BASED
    // use type matching to concervatively find
    // possible targets of indirect call
    return findCalleesByType(CI, FS);
#else
    // use assignments based approach to find possible targets
    return findFunctions(CI->getCalledOperand(), FS);
#endif
}

bool CallGraphPass::runOnFunction(Function *F)
{
    bool Changed = false;

    for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; ++i)
    {
        Instruction *I = &*i;
        // map callsite to possible callees
        if (CallInst *CI = dyn_cast<CallInst>(I))
        {
            // ignore inline asm or intrinsic calls
            if (CI->isInlineAsm() || (CI->getCalledFunction() && CI->getCalledFunction()->isIntrinsic()))
                continue;

            // might be an indirect call, find all possible callees
            //Ctx->Callees[CI] 代表CallInst调用点的所有候选callee集合
            FuncSet &FS = Ctx->Callees[CI];
            if (!findCallees(CI, FS))
                continue;
#if (!defined TYPE_BASED) && (!defined MLTA_BASED)
// #ifndef TYPE_BASED
            // looking for function pointer arguments
            for (unsigned no = 0, ne = CI->getNumArgOperands(); no != ne; ++no)
            {
                Value *V = CI->getArgOperand(no);
                if (!isFunctionPointerOrVoid(V->getType()))
                    continue;

                // find all possible assignments to the argument
                FuncSet VS;
                if (!findFunctions(V, VS))
                    continue;

                // update argument FP-set for possible callees
                for (Function *CF : FS)
                {
                    if (!CF)
                    {
                        WARNING("NULL Function " << *CI << "\n");
                        assert(0);
                    }
                    std::string Id = getArgId(CF, no);
                    Changed |= mergeFuncSet(Ctx->FuncPtrs[Id], VS);
                }
            }
#endif
        }
// #ifndef TYPE_BASED
#if (!defined TYPE_BASED) && (!defined MLTA_BASED)
        if (StoreInst *SI = dyn_cast<StoreInst>(I))
        {
            // stores to function pointers
            Value *V = SI->getValueOperand();
            if (isFunctionPointerOrVoid(V->getType()))
            {
                std::string Id = getStoreId(SI);
                if (!Id.empty())
                {
                    FuncSet FS;
                    findFunctions(V, FS);
                    Changed |= mergeFuncSet(Id, FS, isFunctionPointer(V->getType()));
                }
            }
        }
        else if (ReturnInst *RI = dyn_cast<ReturnInst>(I))
        {
            // function returns
            if (isFunctionPointerOrVoid(F->getReturnType()))
            {
                Value *V = RI->getReturnValue();
                std::string Id = getRetId(F);
                FuncSet FS;
                findFunctions(V, FS);
                Changed |= mergeFuncSet(Id, FS, isFunctionPointer(V->getType()));
            }
        }
#endif
    }

    return Changed;
}

bool CallGraphPass::typeConfineInStore(StoreInst *SI)
{

    Value *PO = SI->getPointerOperand();
    Value *VO = SI->getValueOperand();

    // Case 1: The value operand is a function
    if (Function *F = dyn_cast<Function>(VO))
    {
        Type *STy;
        int Idx;
        if (nextLayerBaseType(PO, STy, Idx, DL))
        {
            typeFuncsMap[typeIdxHash(STy, Idx)].insert(F);
            return true;
        }
        else
        {
            // TODO: OK, for now, let's only consider composite type;
            // skip for other cases
            return false;
        }
    }

    // Cast 2: value-based store
    // A composite-type object is stored
    Type *EPTy = dyn_cast<PointerType>(PO->getType())->getElementType();
    Type *VTy = VO->getType();
    if (isCompositeType(VTy))
    {
        if (isCompositeType(EPTy))
        {
            typeConfineMap[typeHash(EPTy)].insert(typeHash(VTy));
            return true;
        }
        else
        {
            escapeType(EPTy);
            return false;
        }
    }

    // Case 3: reference (i.e., pointer)-based store
    if (isa<ConstantPointerNull>(VO))
        return false;
    // FIXME: Get the correct types
    PointerType *PVTy = dyn_cast<PointerType>(VO->getType());
    if (!PVTy)
        return false;

    Type *EVTy = PVTy->getElementType();

    // Store something to a field of a composite-type object
    Type *STy;
    int Idx;
    if (nextLayerBaseType(PO, STy, Idx, DL))
    {
        // The value operand is a pointer to a composite-type object
        if (isCompositeType(EVTy))
        {
            typeConfineMap[typeIdxHash(STy,Idx)].insert(typeHash(EVTy));
            return true;
        }
        else
        {
            // TODO: The type is escaping?
            // Example: mm/mempool.c +188: pool->free = free_fn;
            // free_fn is a function pointer from an function
            // argument
            escapeType(STy, Idx);
            return false;
        }
    }

    return false;
}

bool CallGraphPass::typeConfineInCast(CastInst *CastI)
{

    // If a function address is ever cast to another type and stored
    // to a composite type, the escaping analysis will capture the
    // composite type and discard it

    Value *ToV = CastI, *FromV = CastI->getOperand(0);
    Type *ToTy = ToV->getType(), *FromTy = FromV->getType();
    if (isCompositeType(FromTy))
    {
        transitType(ToTy, FromTy);
        return true;
    }

    if (!FromTy->isPointerTy() || !ToTy->isPointerTy())
        return false;
    Type *EToTy = dyn_cast<PointerType>(ToTy)->getElementType();
    Type *EFromTy = dyn_cast<PointerType>(FromTy)->getElementType();
    if (isCompositeType(EToTy) && isCompositeType(EFromTy))
    {
        transitType(EToTy, EFromTy);
        return true;
    }

    return false;
}

void CallGraphPass::escapeType(Type *Ty, int Idx)
{
    if (Idx == -1)
        typeEscapeSet.insert(typeHash(Ty));
    else
        typeEscapeSet.insert(typeIdxHash(Ty, Idx));
}

void CallGraphPass::transitType(Type *ToTy, Type *FromTy,
                                int ToIdx, int FromIdx)
{
    if (ToIdx != -1 && FromIdx != -1)
        typeTransitMap[typeIdxHash(ToTy,ToIdx)].insert(typeIdxHash(FromTy, FromIdx));
    else
        typeTransitMap[typeHash(ToTy)].insert(typeHash(FromTy));
}

// collect function pointer assignments in global initializers
void CallGraphPass::processInitializers(Module *M, Constant *C, GlobalValue *V, std::string Id)
{
    // structs
    // ConstantStruct globale variable type declare
    // sub type in struct + variable name
#ifdef DEBUG
    if (M != nullptr)
        errs() << "CallGraphPass::processInitializers: Module " << M->getName() << "\n";
    if (C != nullptr)
        errs() << "Constant: " << *C << "\n";
    if (V != nullptr)
        errs() << "GlobalValue: " << *V << "\n";
    errs() << "Id: " << Id << "\n";
#endif
    if (ConstantStruct *CS = dyn_cast<ConstantStruct>(C))
    {
        // StructType type info of global variables
        // that is, type info in ConstantStruct
        StructType *STy = CS->getType();
    
        if ((!STy->hasName() || STy->isLiteral()) && Id.empty() && V != nullptr)
        {
            Id = getVarId(V);
#ifdef DEBUG
            errs() << "Id = getVarId(V): " << Id << "\n";
#endif
        }
        for (unsigned i = 0; i != STy->getNumElements(); ++i)
        {
            Type *ETy = STy->getElementType(i);
#ifdef DEBUG
            errs() << "Type: " << *ETy << "\n";
#endif
            if (ETy->isStructTy())
            {
                std::string new_id;
                if (Id.empty() && !STy->isLiteral())
                    new_id = STy->getStructName().str() + "," + std::to_string(i);
                else
                    new_id = Id + "," + std::to_string(i);
                processInitializers(M, CS->getOperand(i), NULL, new_id);
            }
            else if (ETy->isArrayTy())
            {
                // nested array of struct
                processInitializers(M, CS->getOperand(i), NULL, "");
            }
            else if (isFunctionPointer(ETy))
            {
                // found function pointers in struct fields
                if (Function *F = dyn_cast<Function>(CS->getOperand(i)))
                {
                    std::string new_id;
                    if (!STy->isLiteral())
                    {
                        // STy is a struct definition
                        if (STy->getStructName().startswith("struct.anon.") ||
                            STy->getStructName().startswith("union.anon"))
                        {
                            if (Id.empty())
                                new_id = getStructId(STy, M, i);
                        }
                        else
                        {
                            new_id = getStructId(STy, M, i);
                        }
                    }
                    if (!new_id.empty() || !Id.empty()) {
                        if (new_id.empty()) {
                          new_id = Id + "," + std::to_string(i);
                        }
                        // new_id is (struct type + offset) to present function
                        // pointer
                        Ctx->FuncPtrs[new_id].insert(getFuncDef(F));
                    }
                }
            }
        }
    }
    else if (ConstantArray *CA = dyn_cast<ConstantArray>(C))
    {
        // array, conservatively collects all possible pointers
        for (unsigned i = 0; i != CA->getNumOperands(); ++i)
            processInitializers(M, CA->getOperand(i), V, Id);
    }
    else if (Function *F = dyn_cast<Function>(C))
    {
        // global function pointer variables
        if (V)
        {
            std::string Id = getVarId(V);
#ifdef DEBUG
            errs() << "new id: " << Id << "\n";
#endif
            Ctx->FuncPtrs[Id].insert(getFuncDef(F));
        }
    }
}

bool CallGraphPass::typeConfineInInitializer(User *Ini)
{

    list<User *> LU;
    LU.push_back(Ini);

    while (!LU.empty())
    {
        User *U = LU.front();
        LU.pop_front();
#ifdef DEBUG
        errs() << "\nConfine ConstantStruct: " << *U << "\n";
#endif
        int idx = 0;
        for (auto oi = U->op_begin(), oe = U->op_end();
             oi != oe; ++oi)
        {
            Value *O = *oi;
            Type *OTy = O->getType();
            // Case 1: function address is assigned to a type
            if (Function *F = dyn_cast<Function>(O))
            {
                // ITy为嵌套F的结构体
                Type *ITy = U->getType();
                // TODO: use offset?
                unsigned ONo = oi->getOperandNo();
#ifdef DEBUG
                errs() << "Function Type: " << *(F->getType()) << "\n";
                errs() << "Hash id: Type: " << *ITy << ", offset: " << ONo << "\n";
                errs() << "typeIdxHash: " << typeIdxHash(ITy, ONo) << "\n";
#endif // DEBUG
                typeFuncsMap[typeIdxHash(ITy, ONo)].insert(F);
            }
            // Case 2: a composite-type object (value) is assigned to a
            // field of another composite-type object
            else if (isCompositeType(OTy))
            {
                // confine composite types
                Type *ITy = U->getType();
                unsigned ONo = oi->getOperandNo();
#ifdef DEBUG
                errs() << "Type: " << *OTy << " offset: " << ONo << "\n";
                errs() << "typeIdxHash: " << typeIdxHash(ITy, ONo) << "\n";
#endif // DEBUG
                typeConfineMap[typeIdxHash(ITy, ONo)].insert(typeHash(OTy));

                // recognize nested composite types
                User *OU = dyn_cast<User>(O);
                LU.push_back(OU);
            }
            // Case 3: a reference (i.e., pointer) of a composite-type
            // object is assigned to a field of another composite-type
            // object
            else if (PointerType *POTy = dyn_cast<PointerType>(OTy))
            {
                if (isa<ConstantPointerNull>(O))
                    continue;
                // if the pointer points a composite type, skip it as
                // there should be another initializer for it, which
                // will be captured

                // now consider if it is a bitcast from a function
                // address
                if (BitCastOperator *CO =
                        dyn_cast<BitCastOperator>(O))
                {
                    // TODO: ? to test if all address-taken functions
                    // are captured
                }
            }
        }
    }

    return true;
}

bool CallGraphPass::doInitialization(Module *M)
{
    DL = &(M->getDataLayout());
    // collect function pointer assignments in global initializers
    for (GlobalVariable &G : M->globals())
    {
        // hasInitializer - Definitions have initializers, declarations don't.
        if (G.hasInitializer())
        {
            #ifdef DEBUG
                        errs() << "GlobalVariable: " << G << "\n";
            #endif
            // getInitializer - Return the initializer for this global variable.
            // The main purpose is to collect the function pointer information in the global variable structure 
            // and establish the mapping through new_id
            // Ctx->FuncPtrs[Id].insert(getFuncDef(F));
            processInitializers(M, G.getInitializer(), &G, "");
#ifdef MLTA_BASED
            // when enable MLTA and initialize global variables
            // build map of typeConfineMap[hash(struct, idx)] = icall
            typeConfineInInitializer(G.getInitializer());
#endif
        }
    }

    for (Function &F : *M)
    {
#ifdef MLTA_BASED
        if (F.isDeclaration())
            continue;

        for (inst_iterator i = inst_begin(F), e = inst_end(F);
             i != e; ++i)
        {
            Instruction *I = &*i;
            // store instruction assigns value to function pointer
            if (StoreInst *SI = dyn_cast<StoreInst>(I))
                typeConfineInStore(SI);
            else if (CastInst *CastI = dyn_cast<CastInst>(I))
                typeConfineInCast(CastI);
        }

        // Collect global function definitions.
        if (F.hasExternalLinkage() && !F.empty())
        {
            // External linkage always ends up with the function name.
            StringRef FName = F.getName();
            // Special case: make the names of syscalls consistent.
            if (FName.startswith("SyS_"))
                FName = StringRef("sys_" + FName.str().substr(4));

            // Map functions to their names.
            Ctx->GlobalFuncs[FName.str()] = &F;
        }

        // Keep a single copy for same functions (inline functions)
        size_t fh = funcHash(&F);
        if (Ctx->UnifiedFuncMap.find(fh) == Ctx->UnifiedFuncMap.end())
        {
            Ctx->UnifiedFuncMap[fh] = &F;
            Ctx->UnifiedFuncSet.insert(&F);

        }
#endif
        // collect address-taken functions
        // hasAddressTaken - returns true if there are any uses of this function other than direct calls or invokes to it, or blockaddress expressions.
        if (F.hasAddressTaken())
        {
            Ctx->AddressTakenFuncs.insert(&F);
            Ctx->sigFuncsMap[funcHash(&F, false)].insert(&F);
#ifdef DEBUG
            errs() << "sigFuncsMap[F] count After function: " << F.getName() << ", " << Ctx->sigFuncsMap[funcHash(&F, false)].size() << "\n";
            errs() << "funcHash(&F, false): " << funcHash(&F, false) << "\n";
#endif
        }
        else{
            //对没有addresstaken的函数也存储签名，通过MLTA来匹配。
            Ctx->sigFuncsMap[funcHash(&F, false)].insert(&F);
#ifdef DEBUG
            errs() << "Function has no address taken: " << F.getName() << "\n ";
            errs() << "funcHash(&F, false): " << funcHash(&F, false) << "\n";
#endif      

        }
        
    }

    return false;
}

bool CallGraphPass::doFinalization(Module *M)
{

    // update callee mapping
    for (Function &F : *M)
    {
        for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; ++i)
        {
            // map callsite to possible callees
            if (CallInst *CI = dyn_cast<CallInst>(&*i))
            {
                FuncSet &FS = Ctx->Callees[CI];
                // calculate the caller info here
                for (Function *CF : FS)
                {
                    CallInstSet &CIS = Ctx->Callers[CF];
                    CIS.insert(CI);
                }
            }
        }
    }

    return false;
}

bool CallGraphPass::doModulePass(Module *M)
{
    bool Changed = true, ret = false;
    while (Changed)
    {
        Changed = false;
        for (Function &F : *M)
            Changed |= runOnFunction(&F);
        ret |= Changed;
    }
    return ret;
}

// debug
void CallGraphPass::dumpFuncPtrs()
{
    //raw_ostream &OS = outs();
    for (FuncPtrMap::iterator i = Ctx->FuncPtrs.begin(),
                              e = Ctx->FuncPtrs.end();
         i != e; ++i)
    {
        //if (i->second.empty())
        //    continue;
        OS << i->first << "\n";
        FuncSet &v = i->second;
        for (FuncSet::iterator j = v.begin(), ej = v.end();
             j != ej; ++j)
        {
            OS << "  " << ((*j)->hasInternalLinkage() ? "f" : "F")
               << " " << extract_str((*j)->getName().str(), ".llvm.") << "\n";
        }
    }
}

stringsetMap CallGraphPass::dumpCallees()
{
    stringsetMap CallMap;
    RES_REPORT("\n[dumpCallees]\n");
    //raw_ostream &OS = outs();
    std::string Caller;
    std::string Callee;
    //OS << "Num of Callees: " << Ctx->Callees.size() << "\n";
    for (CalleeMap::iterator i = Ctx->Callees.begin(), e = Ctx->Callees.end(); i != e; ++i)
    {
        CallInst *CI = i->first;
        FuncSet &v = i->second;
        // only dump indirect call?
        //if (CI->isInlineAsm() || CI->getCalledFunction() /*|| v.empty()*/)
        //   continue;
        // getCalledFunction() Return the function called, or null if this is an indirect function invocation
        if (v.empty() || CI->isInlineAsm() || (CI->getCalledFunction() && CI->getCalledFunction()->isIntrinsic()))
            continue;
        Function *CallerF = CI->getParent()->getParent();
        // #ifdef DEBUG
        //         errs() << "CI's Caller(CallerF): " << *CallerF << "\n";
        // #endif
        //RES_REPORT("\t");
        //v = Ctx->Callees[CI];
        if (CallerF && CallerF->hasName())
        {
            std::string Caller = extract_str(getScopeName(CallerF), ".llvm.");
            ///OS << "Caller:" << Caller << ": ";
            ///OS << "Callees: ";
            if (CallMap.count(Caller) == 0)
            {
                strset Calleeset;
                for (FuncSet::iterator j = v.begin(), ej = v.end(); j != ej; ++j)
                {
                    std::string Callee = extract_str((*j)->getName().str(), ".llvm.");
                    ;
                    if (Callee != Caller && Calleeset.count(Callee) == 0)
                    {
                        ///OS << Callee << "::";
#ifdef DEBUG
                        errs() << "Caller: " << Caller << " insert Callee: " << Callee << "\n";
#endif
                        if (CallerCountMap.count(Callee) == 0)
                            CallerCountMap[Callee] = 1;
                        else
                            CallerCountMap[Callee] += 1;
                        if (CalleeCountMap.count(Caller) == 0)
                            CalleeCountMap[Caller] = 1;
                        else
                            CalleeCountMap[Caller] += 1;
                        Calleeset.insert(Callee);
                    }
                }
                CallMap.insert({Caller, Calleeset});
            }
            else
            {
                for (FuncSet::iterator j = v.begin(), ej = v.end(); j != ej; ++j)
                {
                    std::string Callee = extract_str((*j)->getName().str(), ".llvm.");
                    if (Callee != Caller && CallMap[Caller].count(Callee) == 0)
                    {
                        ///OS << Callee << "::";
#ifdef DEBUG
                        errs() << "Caller: " << Caller << " insert Callee: " << Callee << "\n";
#endif
                        if (CallerCountMap.count(Callee) == 0)
                            CallerCountMap[Callee] = 1;
                        else
                            CallerCountMap[Callee] += 1;
                        if (CalleeCountMap.count(Caller) == 0)
                            CalleeCountMap[Caller] = 1;
                        else
                            CalleeCountMap[Caller] += 1;
                        CallMap[Caller].insert(Callee);
                    }
                }
            }

        }
        else
            RES_REPORT("(anonymous):");
    }
    return CallMap;
    RES_REPORT("\n[End of dumpCallees]\n");
}

std::map<std::string, int> CallGraphPass::dumpCallerCountMap()
{
    return CallerCountMap;
}

std::map<std::string, int> CallGraphPass::dumpCalleeCountMap()
{
    return CalleeCountMap;
}

void CallGraphPass::dumpCallers()
{
    RES_REPORT("\n[dumpCallers]\n");
    for (auto M : Ctx->Callers)
    {
        Function *F = M.first;
        CallInstSet &CIS = M.second;
        RES_REPORT("F : " << extract_str(getScopeName(F), ".llvm.") << "\n");
        //RES_REPORT("F : " << *F << "\n");

        for (CallInst *CI : CIS)
        {
            Function *CallerF = CI->getParent()->getParent();
            RES_REPORT("\t");
            if (CallerF && CallerF->hasName())
            {
                RES_REPORT("(" << extract_str(getScopeName(CallerF), ".llvm.") << ") ");
            }
            else
            {
                RES_REPORT("(anonymous) ");
            }

            RES_REPORT(*CI << "\n");
        }
    }
    RES_REPORT("\n[End of dumpCallers]\n");
}

