#ifndef _RANGE_H
#define _RANGE_H

#include <map>

#include "Global.h"
#include "CRange.h"

typedef std::map<std::string, CRange> RangeMap;
typedef std::map<llvm::Value*, CRange> ValueRangeMap;
typedef std::map<llvm::BasicBlock*, ValueRangeMap> FuncValueRangeMaps;

#define IntRanges (*(RangeMap *)(Ctx->get("IntRanges")))
#define FuncVRMs (*(FuncValueRangeMaps *)(Ctx->get("FuncVRMs")))

class RangePass : public IterativeModulePass {
private:
	const unsigned MaxIterations;	
	
	bool safeUnion(CRange &CR, const CRange &R);
	bool unionRange(std::string, const CRange &, llvm::Value *);
	bool unionRange(llvm::BasicBlock *, llvm::Value *, const CRange &);
	CRange getRange(llvm::BasicBlock *, llvm::Value *);

	void collectInitializers(llvm::GlobalVariable *, llvm::Constant *);
	bool updateRangeFor(llvm::Function *);
	bool updateRangeFor(llvm::BasicBlock *);
	bool updateRangeFor(llvm::Instruction *);

	typedef std::set<std::string> ChangeSet;
	ChangeSet Changes;
	
	typedef std::pair<const llvm::BasicBlock *, const llvm::BasicBlock *> Edge;
	typedef llvm::SmallVector<Edge, 16> EdgeList;
	EdgeList BackEdges;
	
	bool isBackEdge(const Edge &);
	
	CRange visitBinaryOp(llvm::BinaryOperator *);
	CRange visitCastInst(llvm::CastInst *);
	CRange visitSelectInst(llvm::SelectInst *);
	CRange visitPHINode(llvm::PHINode *);
	
	bool visitCallInst(llvm::CallInst *);
	bool visitReturnInst(llvm::ReturnInst *);
	bool visitStoreInst(llvm::StoreInst *);

	void visitBranchInst(llvm::BranchInst *, 
						 llvm::BasicBlock *, ValueRangeMap &);
	void visitTerminator(llvm::Instruction *,
						 llvm::BasicBlock *, ValueRangeMap &);
	void visitSwitchInst(llvm::SwitchInst *, 
						 llvm::BasicBlock *, ValueRangeMap &);

public:
	RangePass(GlobalContext *Ctx_)
		: IterativeModulePass(Ctx_, "Range"), MaxIterations(10) {
		Ctx->add("IntRanges", new RangeMap());
		Ctx->add("FuncVRMs", new FuncValueRangeMaps());
	}
	
	virtual bool doInitialization(llvm::Module *);
	virtual bool doModulePass(llvm::Module *M);
	virtual bool doFinalization(llvm::Module *);

	// debug
	void dumpRange();
};
#endif
