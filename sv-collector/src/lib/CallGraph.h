#ifndef _CALL_GRAPH_H
#define _CALL_GRAPH_H

#include "Global.h"



class CallGraphPass : public IterativeModulePass {
private:
    const DataLayout *DL;
    llvm::Function *getFuncDef(llvm::Function *F);
    bool runOnFunction(llvm::Function*);
    void processInitializers(llvm::Module*, llvm::Constant*, llvm::GlobalValue*, std::string);
    bool findCallees(llvm::CallInst*, FuncSet&);
    bool isCompatibleType(llvm::Type *T1, llvm::Type *T2);
    bool isCompositeType(llvm::Type *Ty);
    bool findCalleesByType(llvm::CallInst*, FuncSet&);
    bool findCalleesByMLTA(llvm::CallInst*, FuncSet&);
    bool findCalleesByMLTASingleLayer(llvm::CallInst*, FuncSet&);
    bool mergeFuncSet(FuncSet &S, const std::string &Id, bool InsertEmpty);
    bool mergeFuncSet(std::string &Id, const FuncSet &S, bool InsertEmpty);
    bool mergeFuncSet(FuncSet &Dst, const FuncSet &Src);
    bool findFunctions(llvm::Value*, FuncSet&);
    bool findFunctions(llvm::Value*, FuncSet&, 
                       llvm::SmallPtrSet<llvm::Value*,4>);
    bool typeConfineInInitializer(User *Ini);
    bool typeConfineInStore(StoreInst *SI);
    bool typeConfineInCast(CastInst *CastI);
    void escapeType(Type *Ty, int Idx = -1);
    void transitType(Type *ToTy, Type *FromTy,
                     int ToIdx = -1, int FromIdx = -1);
    Value *nextLayerBaseType(Value *V, Type *&BTy, int &Idx,
                             const DataLayout *DL);
    void funcSetIntersection(FuncSet &FS1, FuncSet &FS2, FuncSet &FS); 
    

public:
    CallGraphPass(GlobalContext *Ctx_)
        : IterativeModulePass(Ctx_, "CallGraph") { }
    virtual bool doInitialization(llvm::Module *);
    virtual bool doFinalization(llvm::Module *);
    virtual bool doModulePass(llvm::Module *);

    // debug
    void dumpFuncPtrs();
    stringsetMap dumpCallees();
    void dumpCallers();
    std::map<std::string, int> dumpCallerCountMap();
    std::map<std::string, int> dumpCalleeCountMap();
};

#endif
