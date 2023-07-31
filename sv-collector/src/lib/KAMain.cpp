/*
 * main function
 *
 * Copyright (C) 2012 Xi Wang, Haogang Chen, Nickolai Zeldovich
 * Copyright (C) 2015 Byoungyoung Lee
 * Copyright (C) 2015 - 2017 Chengyu Song 
 * Copyright (C) 2016 Kangjie Lu
 *
 * For licensing details see LICENSE
 */

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
//not int clang8 #include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/SystemUtils.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/Path.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>

#include <memory>
#include <vector>
#include <sstream>
#include <sys/resource.h>

#include "Global.h"
#include "CallGraph.h"
#include "StateVariableAnalysis.h"
#include "Pass.h"
#include "Annotation.h"

using namespace llvm;
using namespace std;

// #define DEBUG

// command line parameters definition
cl::list<std::string> InputFilenames(
    cl::Positional, cl::OneOrMore, cl::desc("<input bitcode files>"));

cl::opt<unsigned> VerboseLevel(
    "htleak-verbose", cl::desc("Print information about actions taken"),
    cl::init(0));

cl::opt<bool> DumpCallees(
    "dump-call-graph", cl::desc("Dump call graph"), cl::NotHidden, cl::init(false));

cl::opt<bool> DumpCallers(
    "dump-caller-graph", cl::desc("Dump caller graph"), cl::NotHidden, cl::init(false));

cl::opt<bool> DoSafeStack(
    "safe-stack", cl::desc("Perfrom safe stack analysis"), cl::NotHidden, cl::init(false));

cl::opt<bool> DumpStackStats(
    "dump-stack-stats", cl::desc("Dump stack stats"), cl::NotHidden, cl::init(false));

cl::opt<bool> DoLSS(
    "linux-ss", cl::desc("Discover security sensitive data in Linux kernel"),
    cl::NotHidden, cl::init(false));

cl::opt<bool> DoSVA(
    "StateVariable-Analysis", cl::desc("StateVariable Ana1ysis for Interfaces"),
    cl::NotHidden, cl::init(false));

GlobalContext GlobalCtx;

#define Diag llvm::errs()

stringsetMap CallMap;
std::map<std::string, int> myCallerCountMap;
std::map<std::string, int> myCalleeCountMap;
std::map<std::string, std::string> idValueMap;
stringsetMap sys_calleemap;
strset sys_calleeset;
stringsetMap sysLIdMap;
stringsetMap sysSIdMap;
std::map<std::string, IdInstMap> sysLInstMap;
std::map<std::string, IdInstMap> sysSInstMap;
std::string syscaller;
stringsetMap depmap;
strset LIdset;
std::map<std::string, int> SvIdMap;
std::map<std::string, int> funcSvLoadMap;
strset SIdset;
std::vector<std::pair<std::string, int>> call_stack;
strset sysfunc;
stringsetMap LIdMap;
stringsetMap SIdMap;
std::map<std::string, IdInstMap> LInstMap;
std::map<std::string, IdInstMap> SInstMap;
strset SvCandidates;
strset SuspicionSvCandidates;
int SvConditionBranches = 0;
strset globalSIdSet;

void IterativeModulePass::run(ModuleList &modules)
{
  ModuleList::iterator i, e;
  Diag << "[" << ID << "] Initializing " << modules.size() << " modules ";
  bool again = true;
  while (again)
  {
    again = false;
    for (i = modules.begin(), e = modules.end(); i != e; ++i)
    {
      again |= doInitialization(i->first);
    }
  }

  unsigned iter = 0, changed = 1;
  while (changed)
  {
    ++iter;
    changed = 0;
    for (i = modules.begin(), e = modules.end(); i != e; ++i)
    {
      bool ret = doModulePass(i->first);
      if (ret)
      {
        ++changed;
      }
    }
  }

  again = true;
  while (again)
  {
    again = false;
    for (i = modules.begin(), e = modules.end(); i != e; ++i)
    {
      // TODO: Dump the results.
      again |= doFinalization(i->first);
    }
  }
}

bool incond;

llvm::SmallPtrSet<llvm::Instruction *, 8> InstSet;

void doBasicInitialization(Module *M)
{
  // struct analysis
  GlobalCtx.structAnalyzer.run(M, &(M->getDataLayout()));
  // collect global object definitions
  for (GlobalVariable &G : M->globals())
  {
    if (G.hasExternalLinkage())
    {
      GlobalCtx.Gobjs[G.getName().str()] = &G;
    }
  }
  int fcount = 0;
  // collect global function definitions
  for (Function &F : *M)
  {
    if (!F.empty())
    {
      // external linkage always ends up with the function name
      std::string FName = F.getName().str();
#ifdef DEBUG
      Diag << "doBasicInitialization for Function: " << FName << "\n";
#endif
      // collects syscall entry functions
      //   if (FName.startswith("SyS_") || FName.startswith("sys_") || FName.startswith("__x64_sys_")) {
      //   	sysfunc.insert(FName);
      //   }
      IdInstMap SIdInstMap;
      IdInstMap LIdInstMap;
      LIdset.clear();
      SIdset.clear();
      for (BasicBlock &BB : F)
      {
        for (Instruction &I : BB)
        {
          if (StoreInst *S = dyn_cast<StoreInst>(&I))
          {
            std::string SId = getStoreId(S);
            // filter thread_info false positive
            if (sv_black_list.count(SId) != 0)
                continue;
            if (SId.find("struct.thread_info,") != SId.npos)
                continue;
#ifdef DEBUG
            Diag << "\n" << "StoreInst:  " << *S << "\n";
            Diag << FName << " : SId-" << ":  " << SId << "\n";
#endif
            // check is struct and global variables
            if (
                (SId[0] == 's' && SId[1] == 't' && SId[2] == 'r' && SId[3] == 'u' && SId[4] == 'c' && SId[5] == 't' && SId[6] == '.') || (SId[0] == 'v' && SId[1] == 'a' && SId[2] == 'r' && SId[3] == '.'))
            {
              std::string op_name_str;
              llvm::raw_string_ostream rso(op_name_str);
              rso << *(S->getPointerOperand());
              op_name_str = op_name_str.substr(0, op_name_str.find(" ="));
              if (idValueMap.count(SId) == 0 || std::strstr(idValueMap[SId].c_str(), "unknown")) {
                idValueMap[SId] = op_name_str;
                Diag << "[+] Found Id: " << SId
                     << " | Store pointer value: " << op_name_str << " | Type: "
                     << *(S->getPointerOperandType()->getContainedType(0))
                     << "\n";
                // Diag << "[+] Store pointer value: " << *(S->getPointerOperand()) << "\n";
              }
              if (SIdset.insert(SId).second)
                SIdInstMap[SId] = S;
            }
          }
          else if (LoadInst *L = dyn_cast<LoadInst>(&I))
          {
            std::string LId = getLoadId(L);
            // filter thread_info false positive
            if (sv_black_list.count(LId) != 0)
                continue;
            if (LId.find("struct.thread_info,") != LId.npos)
                continue;
#ifdef DEBUG
            Diag << "\n" << "LoadInst:  " << *L << "\n";
            Diag << FName << " : LId-" << ":  " << LId << "\n";
#endif
            // check is struct and global variables
            if ((LId[0] == 's' && LId[1] == 't' && LId[2] == 'r' && LId[3] == 'u' && LId[4] == 'c' && LId[5] == 't' && LId[6] == '.') || (LId[0] == 'v' && LId[1] == 'a' && LId[2] == 'r' && LId[3] == '.'))
            {
              std::string op_name_str;
              llvm::raw_string_ostream rso(op_name_str);
              rso << *(L->getPointerOperand());
              op_name_str = op_name_str.substr(0, op_name_str.find(" ="));
              if (idValueMap.count(LId) == 0 || std::strstr(idValueMap[LId].c_str(), "unknown")) {
                idValueMap[LId] = op_name_str;
                Diag << "[+] Found Id: " << LId
                     << " | Load pointer value: " << op_name_str << " | Type: "
                     << *(L->getPointerOperandType()->getContainedType(0))
                     << "\n";
                // Diag << "[+] Load pointer value: " << *(L->getPointerOperand()) << "\n";
              }
              if (LIdset.insert(LId).second)
                LIdInstMap[LId] = L;
            }
          }
          else if (CallInst *C = dyn_cast<CallInst>(&I)) {
              Type *svType = nullptr;
              Function *F = C->getCalledFunction();
              if (F == nullptr)
                continue;
              std::string n = F->getName().str();
              if (n.find("check_object_size")==n.npos && n.find("copy_overflow")==n.npos && n.find("copy_from_user")==n.npos && n.find("memcpy")==n.npos)
                continue;
              Value *targetOperand = nullptr;
              Type *ty = nullptr;
              if(C->getNumArgOperands() >= 1) {
                targetOperand = C->getArgOperand(0);
                targetOperand = targetOperand->stripPointerCasts();
#ifdef DEBUG
                Diag << "[+] Found Call: " << n << "\n";
                Diag << "inst: " << (*C) << "\n";
#endif
                ty = targetOperand->getType();
                if (ty == nullptr || !(ty->isPointerTy()))
                    continue;
                ty = ty->getContainedType(0);
                if (ty->isStructTy()) {
#ifdef DEBUG
                    Diag << "dst type: " << *(targetOperand->getType()) << "\n";
#endif
                    svType = ty;
                }
                else {
                    for(auto us=targetOperand->use_begin(), ue=targetOperand->use_end(); us != ue; us++) {
#ifdef DEBUG
                        Diag << "   use of dst_ptr: " << *(*us) << "\n";
#endif
                        if (LoadInst * us_li = dyn_cast<LoadInst>(*us)) {
                            Value *tmpLoadOperand = us_li->getPointerOperand();
                            for (Value::user_iterator it = tmpLoadOperand->user_begin(), ie = tmpLoadOperand->user_end();
                                it != ie; ++it) {
#ifdef DEBUG
                                Diag << "       user of dst_ptr: " << *(*it) << "\n";
#endif
                                if (StoreInst *tmpStoreOperand = dyn_cast<StoreInst>(*it)) {
                                    Value* ptr = tmpStoreOperand->getValueOperand();
                                    ptr = ptr->stripPointerCasts();
                                    ty = ptr->getType();
                                    if (ty == nullptr || !(ty->isPointerTy()))
                                        continue;
                                    ty = ty->getContainedType(0);
                                    if (ty->isStructTy()) {
#ifdef DEBUG
                                        Diag << "dst type: " << *(ptr->getType()) << "\n";
#endif
                                        svType = ty;
                                        break;
                                    }
                                    else {
                                        for (Value::user_iterator ptr_it = ptr->user_begin(), ptr_ie = ptr->user_end();
                                            ptr_it != ptr_ie; ++ptr_it) {
#ifdef DEBUG
                                            Diag << "           user of dst_ptr: " << *(*ptr_it) << "\n";
#endif
                                            if (BitCastInst *BC = dyn_cast<BitCastInst>(*ptr_it)) {
#ifdef DEBUG
                                                Diag << "BitCastInst " << *BC << "\n";
#endif
                                                ty = BC->getSrcTy();
                                                if (ty == nullptr || !(ty->isPointerTy()))
                                                    continue;
                                                ty = ty->getContainedType(0);
#ifdef DEBUG
                                                Diag << "srcType " << *(BC->getSrcTy()) << "\n";
#endif
                                                if (ty->isStructTy()) {
#ifdef DEBUG
                                                    Diag << "dst type: " << *(ty) << "\n";
#endif
                                                    svType = ty;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if (svType != nullptr)
                            break;
                    }
                }
            }
            if (svType != nullptr) {
#ifdef DEBUG
                Diag << "svType found! printTypeRecursive.\n";
#endif
                std::vector<std::string>tyVec;
                while (svType->isPointerTy()) {
                    svType = svType->getContainedType(0);
                }
                printTypeRecursive(svType, true, tyVec);
            }
          }
        }
      }
      //assert(GlobalCtx.Funcs.count(FName) == 0);
      if (LIdset.size() > 0)
      { // ensure LIdset not empty
#ifdef DEBUG
        Diag << "insert LIdset to LIdMap, LIdset.size() = " << LIdset.size() << "\n";
#endif
        LIdMap.insert({FName, LIdset});
        LInstMap.insert({FName, LIdInstMap});
      }
      if (SIdset.size() > 0)
      { // ensure LIdset not empty
#ifdef DEBUG
        Diag << "insert SIdset to SIdMap, SIdset.size() = " << SIdset.size() << "\n";
#endif
        SIdMap.insert({FName, SIdset});
        SInstMap.insert({FName, SIdInstMap});
      }
      GlobalCtx.Funcs[FName] = &F;
    }
  }
}

int main(int argc, char **argv)
{

#ifdef SET_STACK_SIZE
  struct rlimit rl;
  if (getrlimit(RLIMIT_STACK, &rl) == 0)
  {
    rl.rlim_cur = SET_STACK_SIZE;
    setrlimit(RLIMIT_STACK, &rl);
  }
#endif

  // Print a stack trace if we signal out.
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 9
  sys::PrintStackTraceOnErrorSignal();
#else
  sys::PrintStackTraceOnErrorSignal(StringRef());
#endif
  PrettyStackTraceProgram X(argc, argv);

  llvm_shutdown_obj Y; // Call llvm_shutdown() on exit.

  cl::ParseCommandLineOptions(argc, argv, "global analysis\n");
  SMDiagnostic Err;

  // Loading modules
  Diag << "Total: " << InputFilenames.size() << " file(s)\n\n";
  for (unsigned i = 0; i < InputFilenames.size(); ++i)
  {
    //Diag << InputFilenames[i] << "\n";
    // use separate LLVMContext to avoid type renaming
    LLVMContext *LLVMCtx = new LLVMContext();
    // parse IR, get module into llvm context
    std::unique_ptr<Module> M = parseIRFile(InputFilenames[i], Err, *LLVMCtx);
    if (M == NULL)
    {
      errs() << argv[0] << ": error loading file '" << InputFilenames[i] << "'\n";
      continue;
    }
    Module *Module = M.release();
    StringRef MName = StringRef(strdup(InputFilenames[i].data()));
    GlobalCtx.Modules.push_back(std::make_pair(Module, MName));
    GlobalCtx.ModuleMaps[Module] = InputFilenames[i];
    doBasicInitialization(Module);
  }
  //erase not syscall function name
  erase_notsysfunc();
  Diag << "\n end for Loading modules \n\n";

  // Main workflow
  CallGraphPass CGPass(&GlobalCtx);
  Diag << "\n start for CGPass.run(GlobalCtx.Modules) \n\n";
  CGPass.run(GlobalCtx.Modules);

  //dump-call-graph
  if (DumpCallees){
    CallMap = CGPass.dumpCallees();
    dumpCallMap();
    Diag << "Finish dumpCallMap\n";
  }

  // State Variable Analysis
  if (DoSVA)
  {
    Diag << "\n start for CGPass.dumpCallees() \n\n";
    CallMap = CGPass.dumpCallees();
    myCallerCountMap = CGPass.dumpCallerCountMap();
    myCalleeCountMap = CGPass.dumpCalleeCountMap();
    dumpCallMap();
    createsysIdMap();
    Diag << "sysfunc num=" << sysfunc.size() << "\n";
    dumpIdMap();
    dumpsysfunc();
    dumpsyscallee();
    dumpsysIdMap();
    sysIdCount();
    dumpdepcountjson();
    createdepmap();
    dumpdepmap();
    dumpdepjson();

    findSuspicionSvCandidates();
    Diag << "\n SuspicionSvCandidates Size: " << SuspicionSvCandidates.size() << "\n";
    LinuxSVA SVAPass(&GlobalCtx);
    Diag << "\n start for SVAPass.run(GlobalCtx.Modules) \n\n";
    SVAPass.run(GlobalCtx.Modules);
    for (auto &svCandidate : SvCandidates) {
        Diag << "svCandidate : " << svCandidate << "\n";
    }
    Diag << "\n [+] SvCandidates Total Num: " << SvCandidates.size() << "\n";
    Diag << "\n [+] SvConditionBranches Total: " << SvConditionBranches << "\n";
  }

  return 0;
}
