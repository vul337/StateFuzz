#ifndef _SVANALYSIS_H
#define _SVANALYSIS_H

#include "Global.h"

#define MAXREF 30
#define MAXCALLDEPTH 10
#define MAXCALLNUM 60
#define MAXCALLEENUM 300

using namespace llvm;
using namespace std;

extern stringsetMap CallMap;
extern std::map<std::string, int> myCallerCountMap;
extern std::map<std::string, int> myCalleeCountMap;
extern std::map<std::string, std::string> idValueMap;
extern stringsetMap sys_calleemap;
extern strset sys_calleeset;
extern stringsetMap sysLIdMap; 
extern stringsetMap sysSIdMap;
extern std::string syscaller;
extern stringsetMap depmap;
extern strset sysfunc;
extern strset LIdset;
extern strset SIdset;
extern stringsetMap LIdMap; 
extern stringsetMap SIdMap;
extern int SvConditionBranches;
extern strset globalSIdSet;
extern std::set<std::string> sv_black_list;

void dumpIdMap();
void erase_notsysfunc();
void dumpsysfunc();
void dumpCallMap();
void circle_callee(std::string caller, int layer);
std::vector<std::string> split(std::string str,std::string pattern);
void createsysIdMap();
void dumpsyscallee();
void dumpsysIdMap();
void sysIdCount();
void createdepmap();
void dumpdepmap();
void dumpdepjson();
void dumpdepcountjson();
void dumpbcfile();
void findSuspicionSvCandidates();
bool inCondition(llvm::Value *v, int level);
void printTypeRecursive(Type *targetType, bool first, std::vector<std::string> &tyVec);

class LinuxSVA : public IterativeModulePass {

public:

private:
    bool runOnFunction(llvm::Function*, GlobalVariable*);

public:
    LinuxSVA(GlobalContext *Ctx_)
        : IterativeModulePass(Ctx_, "LinuxSVA") {
    }
    virtual bool doModulePass(llvm::Module*);

    virtual bool doInitialization(llvm::Module*);
    
    virtual bool doFinalization(llvm::Module*);
};

#endif
