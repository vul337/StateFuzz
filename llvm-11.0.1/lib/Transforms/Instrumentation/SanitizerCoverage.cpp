//===-- SanitizerCoverage.cpp - coverage instrumentation for sanitizers ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Coverage instrumentation done on LLVM IR level, works with Sanitizers.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Instrumentation/SanitizerCoverage.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/EHPersonalities.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Mangler.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Support/JSON.h"
#include "Annotation.h"
#include <fstream>

using namespace llvm;
using namespace KIntAnnotation;

#define DEBUG_TYPE "sancov"
// #define DEBUG 1

static const char *const SanCovTracePCIndirName =
    "__sanitizer_cov_trace_pc_indir";
// we alse need to modify kcov.c in linux kernel
static const char *const SanCovTracePCWithSVRangesName = "__sanitizer_cov_trace_pcwithsvranges"; //added by nop
static const char *const SanCovTracePCName = "__sanitizer_cov_trace_pc";
static const char *const SanCovTraceCmp1 = "__sanitizer_cov_trace_cmp1";
static const char *const SanCovTraceCmp2 = "__sanitizer_cov_trace_cmp2";
static const char *const SanCovTraceCmp4 = "__sanitizer_cov_trace_cmp4";
static const char *const SanCovTraceCmp8 = "__sanitizer_cov_trace_cmp8";
static const char *const SanCovTraceConstCmp1 =
    "__sanitizer_cov_trace_const_cmp1";
static const char *const SanCovTraceConstCmp2 =
    "__sanitizer_cov_trace_const_cmp2";
static const char *const SanCovTraceConstCmp4 =
    "__sanitizer_cov_trace_const_cmp4";
static const char *const SanCovTraceConstCmp8 =
    "__sanitizer_cov_trace_const_cmp8";
static const char *const SanCovTraceDiv4 = "__sanitizer_cov_trace_div4";
static const char *const SanCovTraceDiv8 = "__sanitizer_cov_trace_div8";
static const char *const SanCovTraceGep = "__sanitizer_cov_trace_gep";
static const char *const SanCovTraceSwitchName = "__sanitizer_cov_trace_switch";
static const char *const SanCovModuleCtorTracePcGuardName =
    "sancov.module_ctor_trace_pc_guard";
static const char *const SanCovModuleCtor8bitCountersName =
    "sancov.module_ctor_8bit_counters";
static const char *const SanCovModuleCtorBoolFlagName =
    "sancov.module_ctor_bool_flag";
static const uint64_t SanCtorAndDtorPriority = 2;

static const char *const SanCovTracePCGuardName =
    "__sanitizer_cov_trace_pc_guard";
static const char *const SanCovTracePCGuardInitName =
    "__sanitizer_cov_trace_pc_guard_init";
static const char *const SanCov8bitCountersInitName =
    "__sanitizer_cov_8bit_counters_init";
static const char *const SanCovBoolFlagInitName =
    "__sanitizer_cov_bool_flag_init";
static const char *const SanCovPCsInitName = "__sanitizer_cov_pcs_init";

static const char *const SanCovGuardsSectionName = "sancov_guards";
static const char *const SanCovCountersSectionName = "sancov_cntrs";
static const char *const SanCovBoolFlagSectionName = "sancov_bools";
static const char *const SanCovPCsSectionName = "sancov_pcs";

static const char *const SanCovLowestStackName = "__sancov_lowest_stack";

static cl::opt<int> ClCoverageLevel(
    "sanitizer-coverage-level",
    cl::desc("Sanitizer Coverage. 0: none, 1: entry block, 2: all blocks, "
             "3: all blocks and critical edges"),
    cl::Hidden, cl::init(0));

static cl::opt<bool> ClTracePC("sanitizer-coverage-trace-pc",
                               cl::desc("Experimental pc tracing"), cl::Hidden,
                               cl::init(false));

static cl::opt<bool> ClTracePCGuard("sanitizer-coverage-trace-pc-guard",
                                    cl::desc("pc tracing with a guard"),
                                    cl::Hidden, cl::init(false));

// added by nop
static cl::opt<bool> ClTracePCWithSVRanges("sanitizer-coverage-trace-pcwithsvranges",
                               cl::desc("Experimental StateVariable variable Range Tracing"), cl::Hidden,
                               cl::init(false));
// added by nop
// If true, we create a global variable that contains PCs of all instrumented
// BBs, put this global into a named section, and pass this section's bounds
// to __sanitizer_cov_pcs_init.
// This way the coverage instrumentation does not need to acquire the PCs
// at run-time. Works with trace-pc-guard, inline-8bit-counters, and
// inline-bool-flag.
static cl::opt<bool> ClCreatePCTable("sanitizer-coverage-pc-table",
                                     cl::desc("create a static PC table"),
                                     cl::Hidden, cl::init(false));

static cl::opt<bool>
    ClInline8bitCounters("sanitizer-coverage-inline-8bit-counters",
                         cl::desc("increments 8-bit counter for every edge"),
                         cl::Hidden, cl::init(false));

static cl::opt<bool>
    ClInlineBoolFlag("sanitizer-coverage-inline-bool-flag",
                     cl::desc("sets a boolean flag for every edge"), cl::Hidden,
                     cl::init(false));

static cl::opt<bool>
    ClCMPTracing("sanitizer-coverage-trace-compares",
                 cl::desc("Tracing of CMP and similar instructions"),
                 cl::Hidden, cl::init(false));

static cl::opt<bool> ClDIVTracing("sanitizer-coverage-trace-divs",
                                  cl::desc("Tracing of DIV instructions"),
                                  cl::Hidden, cl::init(false));

static cl::opt<bool> ClGEPTracing("sanitizer-coverage-trace-geps",
                                  cl::desc("Tracing of GEP instructions"),
                                  cl::Hidden, cl::init(false));

static cl::opt<bool>
    ClPruneBlocks("sanitizer-coverage-prune-blocks",
                  cl::desc("Reduce the number of instrumented blocks"),
                  cl::Hidden, cl::init(true));

static cl::opt<bool> ClStackDepth("sanitizer-coverage-stack-depth",
                                  cl::desc("max stack depth tracing"),
                                  cl::Hidden, cl::init(false));

namespace {

SanitizerCoverageOptions getOptions(int LegacyCoverageLevel) {
  SanitizerCoverageOptions Res;
  switch (LegacyCoverageLevel) {
  case 0:
    Res.CoverageType = SanitizerCoverageOptions::SCK_None;
    break;
  case 1:
    Res.CoverageType = SanitizerCoverageOptions::SCK_Function;
    break;
  case 2:
    Res.CoverageType = SanitizerCoverageOptions::SCK_BB;
    break;
  case 3:
    Res.CoverageType = SanitizerCoverageOptions::SCK_Edge;
    break;
  case 4:
    Res.CoverageType = SanitizerCoverageOptions::SCK_Edge;
    Res.IndirectCalls = true;
    break;
  }
  return Res;
}

SanitizerCoverageOptions OverrideFromCL(SanitizerCoverageOptions Options) {
  // Sets CoverageType and IndirectCalls.
  SanitizerCoverageOptions CLOpts = getOptions(ClCoverageLevel);
  Options.CoverageType = std::max(Options.CoverageType, CLOpts.CoverageType);
  Options.TracePCWithSVRanges |= ClTracePCWithSVRanges; // added by nop
  Options.IndirectCalls |= CLOpts.IndirectCalls;
  Options.TraceCmp |= ClCMPTracing;
  Options.TraceDiv |= ClDIVTracing;
  Options.TraceGep |= ClGEPTracing;
  Options.TracePC |= ClTracePC;
  Options.TracePCGuard |= ClTracePCGuard;
  Options.Inline8bitCounters |= ClInline8bitCounters;
  Options.InlineBoolFlag |= ClInlineBoolFlag;
  Options.PCTable |= ClCreatePCTable;
  Options.NoPrune |= !ClPruneBlocks;
  Options.StackDepth |= ClStackDepth;
  if (!Options.TracePCGuard && !Options.TracePC &&
      !Options.Inline8bitCounters && !Options.StackDepth &&
      !Options.InlineBoolFlag)
    Options.TracePCGuard = true; // TracePCGuard is default.
  return Options;
}

using DomTreeCallback = function_ref<const DominatorTree *(Function &F)>;
using PostDomTreeCallback =
    function_ref<const PostDominatorTree *(Function &F)>;

class ModuleSanitizerCoverage {
public:
  ModuleSanitizerCoverage(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions(),
      const SpecialCaseList *Allowlist = nullptr,
      const SpecialCaseList *Blocklist = nullptr)
      : Options(OverrideFromCL(Options)), Allowlist(Allowlist),
        Blocklist(Blocklist) {}
  bool instrumentModule(Module &M, DomTreeCallback DTCallback,
                        PostDomTreeCallback PDTCallback);

private:
  void instrumentFunction(Function &F, DomTreeCallback DTCallback,
                          PostDomTreeCallback PDTCallback);
  void InjectCoverageForIndirectCalls(Function &F,
                                      ArrayRef<Instruction *> IndirCalls);
  void InjectTraceForCmp(Function &F, ArrayRef<Instruction *> CmpTraceTargets);
  void InjectTraceForDiv(Function &F,
                         ArrayRef<BinaryOperator *> DivTraceTargets);
  void InjectTraceForGep(Function &F,
                         ArrayRef<GetElementPtrInst *> GepTraceTargets);
  void InjectTraceForSwitch(Function &F,
                            ArrayRef<Instruction *> SwitchTraceTargets);
  bool InjectCoverage(Function &F, ArrayRef<BasicBlock *> AllBlocks,
                      bool IsLeafFunc = true);
  // added by nop
  bool InjectCoverageWithSVRanges(Function &F, ArrayRef<BasicBlock *> SVAllBlocks,
                      bool IsLeafFunc = true);
  void handleTypeRecursive(BasicBlock &BB, CallInst *C, Value *stPtr, Type *targetType, bool first, std::vector<int> &idxVec, std::vector<std::string> &tyVec);
  // added by nop
  GlobalVariable *CreateFunctionLocalArrayInSection(size_t NumElements,
                                                    Function &F, Type *Ty,
                                                    const char *Section);
  GlobalVariable *CreatePCArray(Function &F, ArrayRef<BasicBlock *> AllBlocks);
  void CreateFunctionLocalArrays(Function &F, ArrayRef<BasicBlock *> AllBlocks);
  void InjectCoverageAtBlock(Function &F, BasicBlock &BB, size_t Idx,
                             bool IsLeafFunc = true);
  // added by nop
  void InjectCoverageWithSVRangesAtBlock(Function &F, BasicBlock &BB, size_t Idx,
                             bool IsLeafFunc = true);
  // added by nop
  Function *CreateInitCallsForSections(Module &M, const char *CtorName,
                                       const char *InitFunctionName, Type *Ty,
                                       const char *Section);
  std::pair<Value *, Value *> CreateSecStartEnd(Module &M, const char *Section,
                                                Type *Ty);

  void SetNoSanitizeMetadata(Instruction *I) {
    I->setMetadata(I->getModule()->getMDKindID("nosanitize"),
                   MDNode::get(*C, None));
  }

  std::string getSectionName(const std::string &Section) const;
  std::string getSectionStart(const std::string &Section) const;
  std::string getSectionEnd(const std::string &Section) const;
  FunctionCallee SanCovTracePCWithSVRanges; //added by nop
  FunctionCallee SanCovTracePCIndir;
  FunctionCallee SanCovTracePC, SanCovTracePCGuard;
  FunctionCallee SanCovTraceCmpFunction[4];
  FunctionCallee SanCovTraceConstCmpFunction[4];
  FunctionCallee SanCovTraceDivFunction[2];
  FunctionCallee SanCovTraceGepFunction;
  FunctionCallee SanCovTraceSwitchFunction;
  GlobalVariable *SanCovLowestStack;
  Type *IntptrTy, *IntptrPtrTy, *Int64Ty, *Int64PtrTy, *Int32Ty, *Int32PtrTy,
      *Int16Ty, *Int8Ty, *Int8PtrTy, *Int1Ty, *Int1PtrTy;
  Module *CurModule;
  std::string CurModuleUniqueId;
  Triple TargetTriple;
  LLVMContext *C;
  const DataLayout *DL;

  GlobalVariable *FunctionGuardArray;  // for trace-pc-guard.
  GlobalVariable *Function8bitCounterArray;  // for inline-8bit-counters.
  GlobalVariable *FunctionBoolArray;         // for inline-bool-flag.
  GlobalVariable *FunctionPCsArray;  // for pc-table.
  SmallVector<GlobalValue *, 20> GlobalsToAppendToUsed;
  SmallVector<GlobalValue *, 20> GlobalsToAppendToCompilerUsed;

  SanitizerCoverageOptions Options;

  const SpecialCaseList *Allowlist;
  const SpecialCaseList *Blocklist;
};

class ModuleSanitizerCoverageLegacyPass : public ModulePass {
public:
  ModuleSanitizerCoverageLegacyPass(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions(),
      const std::vector<std::string> &AllowlistFiles =
          std::vector<std::string>(),
      const std::vector<std::string> &BlocklistFiles =
          std::vector<std::string>())
      : ModulePass(ID), Options(Options) {
    if (AllowlistFiles.size() > 0)
      Allowlist = SpecialCaseList::createOrDie(AllowlistFiles,
                                               *vfs::getRealFileSystem());
    if (BlocklistFiles.size() > 0)
      Blocklist = SpecialCaseList::createOrDie(BlocklistFiles,
                                               *vfs::getRealFileSystem());
    initializeModuleSanitizerCoverageLegacyPassPass(
        *PassRegistry::getPassRegistry());
  }
  bool runOnModule(Module &M) override {
    ModuleSanitizerCoverage ModuleSancov(Options, Allowlist.get(),
                                         Blocklist.get());
    auto DTCallback = [this](Function &F) -> const DominatorTree * {
      return &this->getAnalysis<DominatorTreeWrapperPass>(F).getDomTree();
    };
    auto PDTCallback = [this](Function &F) -> const PostDominatorTree * {
      return &this->getAnalysis<PostDominatorTreeWrapperPass>(F)
                  .getPostDomTree();
    };
    return ModuleSancov.instrumentModule(M, DTCallback, PDTCallback);
  }

  static char ID; // Pass identification, replacement for typeid
  StringRef getPassName() const override { return "ModuleSanitizerCoverage"; }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<PostDominatorTreeWrapperPass>();
  }

private:
  SanitizerCoverageOptions Options;

  std::unique_ptr<SpecialCaseList> Allowlist;
  std::unique_ptr<SpecialCaseList> Blocklist;
};

} // namespace

PreservedAnalyses ModuleSanitizerCoveragePass::run(Module &M,
                                                   ModuleAnalysisManager &MAM) {
  ModuleSanitizerCoverage ModuleSancov(Options, Allowlist.get(),
                                       Blocklist.get());
  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  auto DTCallback = [&FAM](Function &F) -> const DominatorTree * {
    return &FAM.getResult<DominatorTreeAnalysis>(F);
  };
  auto PDTCallback = [&FAM](Function &F) -> const PostDominatorTree * {
    return &FAM.getResult<PostDominatorTreeAnalysis>(F);
  };
  if (ModuleSancov.instrumentModule(M, DTCallback, PDTCallback))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

std::pair<Value *, Value *>
ModuleSanitizerCoverage::CreateSecStartEnd(Module &M, const char *Section,
                                           Type *Ty) {
  GlobalVariable *SecStart =
      new GlobalVariable(M, Ty, false, GlobalVariable::ExternalLinkage, nullptr,
                         getSectionStart(Section));
  SecStart->setVisibility(GlobalValue::HiddenVisibility);
  GlobalVariable *SecEnd =
      new GlobalVariable(M, Ty, false, GlobalVariable::ExternalLinkage,
                         nullptr, getSectionEnd(Section));
  SecEnd->setVisibility(GlobalValue::HiddenVisibility);
  IRBuilder<> IRB(M.getContext());
  Value *SecEndPtr = IRB.CreatePointerCast(SecEnd, Ty);
  if (!TargetTriple.isOSBinFormatCOFF())
    return std::make_pair(IRB.CreatePointerCast(SecStart, Ty), SecEndPtr);

  // Account for the fact that on windows-msvc __start_* symbols actually
  // point to a uint64_t before the start of the array.
  auto SecStartI8Ptr = IRB.CreatePointerCast(SecStart, Int8PtrTy);
  auto GEP = IRB.CreateGEP(Int8Ty, SecStartI8Ptr,
                           ConstantInt::get(IntptrTy, sizeof(uint64_t)));
  return std::make_pair(IRB.CreatePointerCast(GEP, Ty), SecEndPtr);
}

Function *ModuleSanitizerCoverage::CreateInitCallsForSections(
    Module &M, const char *CtorName, const char *InitFunctionName, Type *Ty,
    const char *Section) {
  auto SecStartEnd = CreateSecStartEnd(M, Section, Ty);
  auto SecStart = SecStartEnd.first;
  auto SecEnd = SecStartEnd.second;
  Function *CtorFunc;
  std::tie(CtorFunc, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, CtorName, InitFunctionName, {Ty, Ty}, {SecStart, SecEnd});
  assert(CtorFunc->getName() == CtorName);

  if (TargetTriple.supportsCOMDAT()) {
    // Use comdat to dedup CtorFunc.
    CtorFunc->setComdat(M.getOrInsertComdat(CtorName));
    appendToGlobalCtors(M, CtorFunc, SanCtorAndDtorPriority, CtorFunc);
  } else {
    appendToGlobalCtors(M, CtorFunc, SanCtorAndDtorPriority);
  }

  if (TargetTriple.isOSBinFormatCOFF()) {
    // In COFF files, if the contructors are set as COMDAT (they are because
    // COFF supports COMDAT) and the linker flag /OPT:REF (strip unreferenced
    // functions and data) is used, the constructors get stripped. To prevent
    // this, give the constructors weak ODR linkage and ensure the linker knows
    // to include the sancov constructor. This way the linker can deduplicate
    // the constructors but always leave one copy.
    CtorFunc->setLinkage(GlobalValue::WeakODRLinkage);
    appendToUsed(M, CtorFunc);
  }
  return CtorFunc;
}

// added by nop

// use Module pass to modify the origin program
// {sv_name: no}
std::map<std::string, int> SVList = {};
std::set<std::pair<std::string, std::string>> inst_points;
// {"line:65:27:W": true}
std::map<std::string, bool> inst_points_log;
// Value *sv_trace_func_ptr;

void getDeclareprintk(Function &F) {
    Function *func_printk = F.getParent()->getFunction("printk");
    if (!func_printk) {
        FunctionType *FT = FunctionType::get(Type::getInt8PtrTy(F.getContext()), true);
        Function::Create(FT, Function::ExternalLinkage, "printk", F.getParent());
    }
}

int checkSV(std::string s) {
    // return true;
    if (s.length() <= 1)
        return -1;
    if (s.find("lvar.") == 0)
        return -1;
    // todo check type, just handle int type
    if (s.find("var.") == 0)
    {
        // cut var.xx.xxx.xxxx.name
        s = "var" + s.substr(s.rfind("."));
    }
    if (SVList.count(s) == 0)
        return -1;
    return SVList[s];
}

void getSVList() {
    std::ifstream sv_file;
    std::string line;
    std::map<std::string, int> sv_str_map_consistent;

    sv_file.open("/tmp/sv_list.txt");
    if (!sv_file.is_open()) {
        // cout << "Error opening ioctl_top_function_file";
        llvm::outs() << "[!] open /tmp/sv_list.txt error!\n";
        exit(1);
    }
    sv_str_map_consistent.clear();
    int num = 0;
    while (!sv_file.eof()) {
        getline(sv_file, line);
        // llvm::outs() << "line: " << line << "\n";
        sv_str_map_consistent[line] = num;
        num++;
    }
    sv_file.close();
    SVList = sv_str_map_consistent;
#ifdef DEBUG
    llvm::outs() << "[+] sv_str initialized\n";
#endif
    return;
}

std::set<std::pair<std::string, std::string>> 
  getInstrumentPoints(Module &M) {
    std::ifstream sv_file;
    std::string line;
    std::set<std::pair<std::string, std::string>> tmp_set;

    sv_file.open("/tmp/instrument_points.json");
    if (!sv_file.is_open()) {
        // cout << "Error opening ioctl_top_function_file";
        llvm::outs() << "[!] open /tmp/instrument_points.json error!\n";
        exit(1);
    }

    getline(sv_file, line);
    // all in 1 line
    // llvm::outs() << "line: " << line << "\n";
    sv_file.close();

    if (line.length() == 0) {
        llvm::outs() << "[!] weired instrument_points.json input\n";
        exit(1);
    }

    Expected<json::Value> IE = json::parse(line);
    assert(IE && IE->kind() == json::Value::Object);
    if (json::Object *O = IE->getAsObject()) {
        llvm::outs() << "json parsing\n";
        for (json::Object::iterator oit=O->begin(), oie=O->end();
          oit!=oie; oit++) {
            // if (oit->first.str() != M.getName())
            if (oit->first.str().find(M.getName().str()) == oit->first.str().npos &&
              M.getName().str().find(oit->first.str()) == M.getName().str().npos)
                continue;
            llvm::outs() << "[+] in file " << oit->first << ":\n";
            if (json::Array *A = oit->second.getAsArray()) {
                for (json::Array::iterator ait=A->begin(), aie=A->end();
                  ait!=aie; ait++) {
                    if (json::Object *sub_O = ait->getAsObject()) {
                        for (json::Object::iterator sub_oit=sub_O->begin(), sub_oie=sub_O->end();
                          sub_oit!=sub_oie; sub_oit++) {
                            // instrument_point  -----> sv_name
                            llvm::outs() << sub_oit->first << "---->" 
                              << sub_oit->second.getAsString()->str() << "\n";
                            tmp_set.insert(std::make_pair(sub_oit->first.str(), 
                              sub_oit->second.getAsString()->str()));
                        }
                    }
                }
            }
            else {
                llvm::outs() << "[!] json value is not array_type!\n";
                exit(1);
            }
        }
    //   if (Object *Opts = O->getObject("options"))
    //     if (Optional<StringRef> Font = Opts->getString("font"))
    //       assert(Opts->at("font").kind() == Value::String);
    }
#ifdef DEBUG
    llvm::outs() << "[+] getInstrumentPoints initialized\n";
#endif
    return tmp_set;
}

void getSVTraceFunc(Module *M) {
    Function *sv_trace_func = M->getFunction("printk");
    if (!sv_trace_func) {
        FunctionType *FT = FunctionType::get(Type::getInt8PtrTy(M->getContext()), true);
        Function::Create(FT, Function::ExternalLinkage, "printk", M);
    }
}

bool ModuleSanitizerCoverage::instrumentModule(
    Module &M, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {
  if (Options.CoverageType == SanitizerCoverageOptions::SCK_None)
    return false;
  if (Allowlist &&
      !Allowlist->inSection("coverage", "src", M.getSourceFileName()))
    return false;
  if (Blocklist &&
      Blocklist->inSection("coverage", "src", M.getSourceFileName()))
    return false;
  C = &(M.getContext());
  DL = &M.getDataLayout();
  CurModule = &M;
  CurModuleUniqueId = getUniqueModuleId(CurModule);
  TargetTriple = Triple(M.getTargetTriple());
  FunctionGuardArray = nullptr;
  Function8bitCounterArray = nullptr;
  FunctionBoolArray = nullptr;
  FunctionPCsArray = nullptr;
  IntptrTy = Type::getIntNTy(*C, DL->getPointerSizeInBits());
  IntptrPtrTy = PointerType::getUnqual(IntptrTy);
  Type *VoidTy = Type::getVoidTy(*C);
  IRBuilder<> IRB(*C);
  Int64PtrTy = PointerType::getUnqual(IRB.getInt64Ty());
  Int32PtrTy = PointerType::getUnqual(IRB.getInt32Ty());
  Int8PtrTy = PointerType::getUnqual(IRB.getInt8Ty());
  Int1PtrTy = PointerType::getUnqual(IRB.getInt1Ty());
  Int64Ty = IRB.getInt64Ty();
  Int32Ty = IRB.getInt32Ty();
  Int16Ty = IRB.getInt16Ty();
  Int8Ty = IRB.getInt8Ty();
  Int1Ty = IRB.getInt1Ty();

  SanCovTracePCIndir =
      M.getOrInsertFunction(SanCovTracePCIndirName, VoidTy, IntptrTy);
  // Make sure smaller parameters are zero-extended to i64 as required by the
  // x86_64 ABI.
  AttributeList SanCovTraceCmpZeroExtAL;
  if (TargetTriple.getArch() == Triple::x86_64) {
    SanCovTraceCmpZeroExtAL =
        SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 0, Attribute::ZExt);
    SanCovTraceCmpZeroExtAL =
        SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 1, Attribute::ZExt);
  }

  // added by nop
  getSVList();
  llvm::outs() << "Current Module: " << M.getName() << "\n";
  inst_points = getInstrumentPoints(M);

  // todo
  SanCovTracePCWithSVRanges = M.getOrInsertFunction(SanCovTracePCWithSVRangesName, VoidTy, Int32Ty, Int32Ty, Int32Ty); // arg is int,int,int
  // added by nop

  SanCovTraceCmpFunction[0] =
      M.getOrInsertFunction(SanCovTraceCmp1, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt8Ty(), IRB.getInt8Ty());
  SanCovTraceCmpFunction[1] =
      M.getOrInsertFunction(SanCovTraceCmp2, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt16Ty(), IRB.getInt16Ty());
  SanCovTraceCmpFunction[2] =
      M.getOrInsertFunction(SanCovTraceCmp4, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt32Ty(), IRB.getInt32Ty());
  SanCovTraceCmpFunction[3] =
      M.getOrInsertFunction(SanCovTraceCmp8, VoidTy, Int64Ty, Int64Ty);

  SanCovTraceConstCmpFunction[0] = M.getOrInsertFunction(
      SanCovTraceConstCmp1, SanCovTraceCmpZeroExtAL, VoidTy, Int8Ty, Int8Ty);
  SanCovTraceConstCmpFunction[1] = M.getOrInsertFunction(
      SanCovTraceConstCmp2, SanCovTraceCmpZeroExtAL, VoidTy, Int16Ty, Int16Ty);
  SanCovTraceConstCmpFunction[2] = M.getOrInsertFunction(
      SanCovTraceConstCmp4, SanCovTraceCmpZeroExtAL, VoidTy, Int32Ty, Int32Ty);
  SanCovTraceConstCmpFunction[3] =
      M.getOrInsertFunction(SanCovTraceConstCmp8, VoidTy, Int64Ty, Int64Ty);

  {
    AttributeList AL;
    if (TargetTriple.getArch() == Triple::x86_64)
      AL = AL.addParamAttribute(*C, 0, Attribute::ZExt);
    SanCovTraceDivFunction[0] =
        M.getOrInsertFunction(SanCovTraceDiv4, AL, VoidTy, IRB.getInt32Ty());
  }
  SanCovTraceDivFunction[1] =
      M.getOrInsertFunction(SanCovTraceDiv8, VoidTy, Int64Ty);
  SanCovTraceGepFunction =
      M.getOrInsertFunction(SanCovTraceGep, VoidTy, IntptrTy);
  SanCovTraceSwitchFunction =
      M.getOrInsertFunction(SanCovTraceSwitchName, VoidTy, Int64Ty, Int64PtrTy);

  Constant *SanCovLowestStackConstant =
      M.getOrInsertGlobal(SanCovLowestStackName, IntptrTy);
  SanCovLowestStack = dyn_cast<GlobalVariable>(SanCovLowestStackConstant);
  if (!SanCovLowestStack) {
    C->emitError(StringRef("'") + SanCovLowestStackName +
                 "' should not be declared by the user");
    return true;
  }
  SanCovLowestStack->setThreadLocalMode(
      GlobalValue::ThreadLocalMode::InitialExecTLSModel);
  if (Options.StackDepth && !SanCovLowestStack->isDeclaration())
    SanCovLowestStack->setInitializer(Constant::getAllOnesValue(IntptrTy));

  SanCovTracePC = M.getOrInsertFunction(SanCovTracePCName, VoidTy);
  SanCovTracePCGuard =
      M.getOrInsertFunction(SanCovTracePCGuardName, VoidTy, Int32PtrTy);

  for (auto &F : M)
    instrumentFunction(F, DTCallback, PDTCallback);

  Function *Ctor = nullptr;

  if (FunctionGuardArray)
    Ctor = CreateInitCallsForSections(M, SanCovModuleCtorTracePcGuardName,
                                      SanCovTracePCGuardInitName, Int32PtrTy,
                                      SanCovGuardsSectionName);
  if (Function8bitCounterArray)
    Ctor = CreateInitCallsForSections(M, SanCovModuleCtor8bitCountersName,
                                      SanCov8bitCountersInitName, Int8PtrTy,
                                      SanCovCountersSectionName);
  if (FunctionBoolArray) {
    Ctor = CreateInitCallsForSections(M, SanCovModuleCtorBoolFlagName,
                                      SanCovBoolFlagInitName, Int1PtrTy,
                                      SanCovBoolFlagSectionName);
  }
  if (Ctor && Options.PCTable) {
    auto SecStartEnd = CreateSecStartEnd(M, SanCovPCsSectionName, IntptrPtrTy);
    FunctionCallee InitFunction = declareSanitizerInitFunction(
        M, SanCovPCsInitName, {IntptrPtrTy, IntptrPtrTy});
    IRBuilder<> IRBCtor(Ctor->getEntryBlock().getTerminator());
    IRBCtor.CreateCall(InitFunction, {SecStartEnd.first, SecStartEnd.second});
  }
  // We don't reference these arrays directly in any of our runtime functions,
  // so we need to prevent them from being dead stripped.
  if (TargetTriple.isOSBinFormatMachO())
    appendToUsed(M, GlobalsToAppendToUsed);
  appendToCompilerUsed(M, GlobalsToAppendToCompilerUsed);
  return true;
}

// True if block has successors and it dominates all of them.
static bool isFullDominator(const BasicBlock *BB, const DominatorTree *DT) {
  if (succ_begin(BB) == succ_end(BB))
    return false;

  for (const BasicBlock *SUCC : make_range(succ_begin(BB), succ_end(BB))) {
    if (!DT->dominates(BB, SUCC))
      return false;
  }

  return true;
}

// True if block has predecessors and it postdominates all of them.
static bool isFullPostDominator(const BasicBlock *BB,
                                const PostDominatorTree *PDT) {
  if (pred_begin(BB) == pred_end(BB))
    return false;

  for (const BasicBlock *PRED : make_range(pred_begin(BB), pred_end(BB))) {
    if (!PDT->dominates(BB, PRED))
      return false;
  }

  return true;
}

static bool shouldInstrumentBlock(const Function &F, const BasicBlock *BB,
                                  const DominatorTree *DT,
                                  const PostDominatorTree *PDT,
                                  const SanitizerCoverageOptions &Options) {
  // Don't insert coverage for blocks containing nothing but unreachable: we
  // will never call __sanitizer_cov() for them, so counting them in
  // NumberOfInstrumentedBlocks() might complicate calculation of code coverage
  // percentage. Also, unreachable instructions frequently have no debug
  // locations.
  if (isa<UnreachableInst>(BB->getFirstNonPHIOrDbgOrLifetime()))
    return false;

  // Don't insert coverage into blocks without a valid insertion point
  // (catchswitch blocks).
  if (BB->getFirstInsertionPt() == BB->end())
    return false;

  if (Options.NoPrune || &F.getEntryBlock() == BB)
    return true;

  if (Options.CoverageType == SanitizerCoverageOptions::SCK_Function &&
      &F.getEntryBlock() != BB)
    return false;

  // Do not instrument full dominators, or full post-dominators with multiple
  // predecessors.
  return !isFullDominator(BB, DT)
    && !(isFullPostDominator(BB, PDT) && !BB->getSinglePredecessor());
}


// Returns true iff From->To is a backedge.
// A twist here is that we treat From->To as a backedge if
//   * To dominates From or
//   * To->UniqueSuccessor dominates From
static bool IsBackEdge(BasicBlock *From, BasicBlock *To,
                       const DominatorTree *DT) {
  if (DT->dominates(To, From))
    return true;
  if (auto Next = To->getUniqueSuccessor())
    if (DT->dominates(Next, From))
      return true;
  return false;
}

// Prunes uninteresting Cmp instrumentation:
//   * CMP instructions that feed into loop backedge branch.
//
// Note that Cmp pruning is controlled by the same flag as the
// BB pruning.
static bool IsInterestingCmp(ICmpInst *CMP, const DominatorTree *DT,
                             const SanitizerCoverageOptions &Options) {
  if (!Options.NoPrune)
    if (CMP->hasOneUse())
      if (auto BR = dyn_cast<BranchInst>(CMP->user_back()))
        for (BasicBlock *B : BR->successors())
          if (IsBackEdge(BR->getParent(), B, DT))
            return false;
  return true;
}

void ModuleSanitizerCoverage::instrumentFunction(
    Function &F, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {
  llvm::outs() << "runOnFunction: " << F.getName().str() << " in " << F.getParent()->getName().str() << "\n";
//   if (F.getParent()->getName().str().find("drivers/") == F.getParent()->getName().str().npos
//     && F.getParent()->getName().str().find("fs/") == F.getParent()->getName().str().npos
//   ) {
//     llvm::outs() << F.getName().str() << " in " << F.getParent()->getName().str() << ", not in drivers/ , skip\n";
//     return false;
//   }
  if (F.empty()) {
    return;
  }
  if (F.getName().find(".module_ctor") != std::string::npos)
    return; // Should not instrument sanitizer init functions.
  if (F.getName().startswith("__sanitizer_"))
    return; // Don't instrument __sanitizer_* callbacks.
  // Don't touch available_externally functions, their actual body is elewhere.
  if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage)
    return;
  // Don't instrument MSVC CRT configuration helpers. They may run before normal
  // initialization.
  if (F.getName() == "__local_stdio_printf_options" ||
      F.getName() == "__local_stdio_scanf_options")
    return;
  if (isa<UnreachableInst>(F.getEntryBlock().getTerminator()))
    return;
  // Don't instrument functions using SEH for now. Splitting basic blocks like
  // we do for coverage breaks WinEHPrepare.
  // FIXME: Remove this when SEH no longer uses landingpad pattern matching.
  if (F.hasPersonalityFn() &&
      isAsynchronousEHPersonality(classifyEHPersonality(F.getPersonalityFn())))
    return;
  if (Allowlist && !Allowlist->inSection("coverage", "fun", F.getName()))
    return;
  if (Blocklist && Blocklist->inSection("coverage", "fun", F.getName()))
    return;
  if (Options.CoverageType >= SanitizerCoverageOptions::SCK_Edge)
    SplitAllCriticalEdges(F, CriticalEdgeSplittingOptions().setIgnoreUnreachableDests());
  SmallVector<Instruction *, 8> IndirCalls;
  SmallVector<BasicBlock *, 16> BlocksToInstrument;
  SmallVector<BasicBlock *, 16> SVBlocksToInstrument;
  SmallVector<Instruction *, 8> CmpTraceTargets;
  SmallVector<Instruction *, 8> SwitchTraceTargets;
  SmallVector<BinaryOperator *, 8> DivTraceTargets;
  SmallVector<GetElementPtrInst *, 8> GepTraceTargets;

  const DominatorTree *DT = DTCallback(F);
  const PostDominatorTree *PDT = PDTCallback(F);
  bool IsLeafFunc = true;

  for (auto &BB : F) {
    if (shouldInstrumentBlock(F, &BB, DT, PDT, Options))
      BlocksToInstrument.push_back(&BB);
    if (F.getParent()->getName().str().find("/drivers/") != F.getParent()->getName().str().npos
        || F.getParent()->getName().str().find("/fs/") != F.getParent()->getName().str().npos
        || F.getParent()->getName().str().find("/block/") != F.getParent()->getName().str().npos
        || F.getParent()->getName().str().find("/net/") != F.getParent()->getName().str().npos
        || F.getParent()->getName().str().find("/sound/") != F.getParent()->getName().str().npos
        ) {
        SVBlocksToInstrument.push_back(&BB);
    } else {
        if (shouldInstrumentBlock(F, &BB, DT, PDT, Options))
            SVBlocksToInstrument.push_back(&BB);
    }

    for (auto &Inst : BB) {
      if (Options.IndirectCalls) {
        CallBase *CB = dyn_cast<CallBase>(&Inst);
        if (CB && !CB->getCalledFunction())
          IndirCalls.push_back(&Inst);
      }
      if (Options.TraceCmp) {
        if (F.getParent()->getName().str().find("drivers/") != F.getParent()->getName().str().npos
        || F.getParent()->getName().str().find("sound/") != F.getParent()->getName().str().npos) {
        // || F.getParent()->getName().str().find("net/") != F.getParent()->getName().str().npos)
        // || F.getParent()->getName().str().find("fs/") != F.getParent()->getName().str().npos) {
          if (ICmpInst *CMP = dyn_cast<ICmpInst>(&Inst))
            if (IsInterestingCmp(CMP, DT, Options))
              CmpTraceTargets.push_back(&Inst);
          if (isa<SwitchInst>(&Inst))
            SwitchTraceTargets.push_back(&Inst);
        }
      }
      if (Options.TraceDiv)
        if (BinaryOperator *BO = dyn_cast<BinaryOperator>(&Inst))
          if (BO->getOpcode() == Instruction::SDiv ||
              BO->getOpcode() == Instruction::UDiv)
            DivTraceTargets.push_back(BO);
      if (Options.TraceGep)
        if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(&Inst))
          GepTraceTargets.push_back(GEP);
      if (Options.StackDepth)
        if (isa<InvokeInst>(Inst) ||
            (isa<CallInst>(Inst) && !isa<IntrinsicInst>(Inst)))
          IsLeafFunc = false;
    }
  }

  // modified by nop
  // if trace state variable ranges
  InjectCoverage(F, BlocksToInstrument, IsLeafFunc);
  if (Options.TracePCWithSVRanges)
    InjectCoverageWithSVRanges(F, SVBlocksToInstrument, IsLeafFunc);

  // modified by nop

  InjectCoverageForIndirectCalls(F, IndirCalls);
  InjectTraceForCmp(F, CmpTraceTargets);
  InjectTraceForSwitch(F, SwitchTraceTargets);
  InjectTraceForDiv(F, DivTraceTargets);
  InjectTraceForGep(F, GepTraceTargets);
}

GlobalVariable *ModuleSanitizerCoverage::CreateFunctionLocalArrayInSection(
    size_t NumElements, Function &F, Type *Ty, const char *Section) {
  ArrayType *ArrayTy = ArrayType::get(Ty, NumElements);
  auto Array = new GlobalVariable(
      *CurModule, ArrayTy, false, GlobalVariable::PrivateLinkage,
      Constant::getNullValue(ArrayTy), "__sancov_gen_");

  if (TargetTriple.supportsCOMDAT() && !F.isInterposable())
    if (auto Comdat =
            GetOrCreateFunctionComdat(F, TargetTriple, CurModuleUniqueId))
      Array->setComdat(Comdat);
  Array->setSection(getSectionName(Section));
  Array->setAlignment(Align(DL->getTypeStoreSize(Ty).getFixedSize()));
  GlobalsToAppendToUsed.push_back(Array);
  GlobalsToAppendToCompilerUsed.push_back(Array);
  MDNode *MD = MDNode::get(F.getContext(), ValueAsMetadata::get(&F));
  Array->addMetadata(LLVMContext::MD_associated, *MD);

  return Array;
}

GlobalVariable *
ModuleSanitizerCoverage::CreatePCArray(Function &F,
                                       ArrayRef<BasicBlock *> AllBlocks) {
  size_t N = AllBlocks.size();
  assert(N);
  SmallVector<Constant *, 32> PCs;
  IRBuilder<> IRB(&*F.getEntryBlock().getFirstInsertionPt());
  for (size_t i = 0; i < N; i++) {
    if (&F.getEntryBlock() == AllBlocks[i]) {
      PCs.push_back((Constant *)IRB.CreatePointerCast(&F, IntptrPtrTy));
      PCs.push_back((Constant *)IRB.CreateIntToPtr(
          ConstantInt::get(IntptrTy, 1), IntptrPtrTy));
    } else {
      PCs.push_back((Constant *)IRB.CreatePointerCast(
          BlockAddress::get(AllBlocks[i]), IntptrPtrTy));
      PCs.push_back((Constant *)IRB.CreateIntToPtr(
          ConstantInt::get(IntptrTy, 0), IntptrPtrTy));
    }
  }
  auto *PCArray = CreateFunctionLocalArrayInSection(N * 2, F, IntptrPtrTy,
                                                    SanCovPCsSectionName);
  PCArray->setInitializer(
      ConstantArray::get(ArrayType::get(IntptrPtrTy, N * 2), PCs));
  PCArray->setConstant(true);

  return PCArray;
}

void ModuleSanitizerCoverage::CreateFunctionLocalArrays(
    Function &F, ArrayRef<BasicBlock *> AllBlocks) {
  if (Options.TracePCGuard)
    FunctionGuardArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size(), F, Int32Ty, SanCovGuardsSectionName);

  if (Options.Inline8bitCounters)
    Function8bitCounterArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size(), F, Int8Ty, SanCovCountersSectionName);
  if (Options.InlineBoolFlag)
    FunctionBoolArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size(), F, Int1Ty, SanCovBoolFlagSectionName);

  if (Options.PCTable)
    FunctionPCsArray = CreatePCArray(F, AllBlocks);
}

bool ModuleSanitizerCoverage::InjectCoverage(Function &F,
                                             ArrayRef<BasicBlock *> AllBlocks,
                                             bool IsLeafFunc) {
  if (AllBlocks.empty()) return false;
//   if (F.getParent()->getName().str().find("drivers/") == F.getParent()->getName().str().npos) {
//     llvm::outs() << F.getName().str() << " in " << F.getParent()->getName().str() << ", not in drivers/ , skip InjectPCCoverage\n";
//     return false;
//   }
  CreateFunctionLocalArrays(F, AllBlocks);
  for (size_t i = 0, N = AllBlocks.size(); i < N; i++)
    InjectCoverageAtBlock(F, *AllBlocks[i], i, IsLeafFunc);
  return true;
}

// On every indirect call we call a run-time function
// __sanitizer_cov_indir_call* with two parameters:
//   - callee address,
//   - global cache array that contains CacheSize pointers (zero-initialized).
//     The cache is used to speed up recording the caller-callee pairs.
// The address of the caller is passed implicitly via caller PC.
// CacheSize is encoded in the name of the run-time function.
void ModuleSanitizerCoverage::InjectCoverageForIndirectCalls(
    Function &F, ArrayRef<Instruction *> IndirCalls) {
  if (IndirCalls.empty())
    return;
  assert(Options.TracePC || Options.TracePCGuard ||
         Options.Inline8bitCounters || Options.InlineBoolFlag);
  for (auto I : IndirCalls) {
    IRBuilder<> IRB(I);
    CallBase &CB = cast<CallBase>(*I);
    Value *Callee = CB.getCalledOperand();
    if (isa<InlineAsm>(Callee))
      continue;
    IRB.CreateCall(SanCovTracePCIndir, IRB.CreatePointerCast(Callee, IntptrTy));
  }
}

// For every switch statement we insert a call:
// __sanitizer_cov_trace_switch(CondValue,
//      {NumCases, ValueSizeInBits, Case0Value, Case1Value, Case2Value, ... })

void ModuleSanitizerCoverage::InjectTraceForSwitch(
    Function &F, ArrayRef<Instruction *> SwitchTraceTargets) {
    for (auto I : SwitchTraceTargets) {
    if (
      F.getParent()->getName().str().find("drivers/") == F.getParent()->getName().str().npos
      && F.getParent()->getName().str().find("sound/") == F.getParent()->getName().str().npos
    ) {
      return;
    }
    if (SwitchInst *SI = dyn_cast<SwitchInst>(I)) {
      IRBuilder<> IRB(I);
      SmallVector<Constant *, 16> Initializers;
      Value *Cond = SI->getCondition();
      if (Cond->getType()->getScalarSizeInBits() >
          Int64Ty->getScalarSizeInBits())
        continue;
      Initializers.push_back(ConstantInt::get(Int64Ty, SI->getNumCases()));
      Initializers.push_back(
          ConstantInt::get(Int64Ty, Cond->getType()->getScalarSizeInBits()));
      if (Cond->getType()->getScalarSizeInBits() <
          Int64Ty->getScalarSizeInBits())
        Cond = IRB.CreateIntCast(Cond, Int64Ty, false);
      for (auto It : SI->cases()) {
        Constant *C = It.getCaseValue();
        if (C->getType()->getScalarSizeInBits() <
            Int64Ty->getScalarSizeInBits())
          C = ConstantExpr::getCast(CastInst::ZExt, It.getCaseValue(), Int64Ty);
        Initializers.push_back(C);
      }
      llvm::sort(Initializers.begin() + 2, Initializers.end(),
                 [](const Constant *A, const Constant *B) {
                   return cast<ConstantInt>(A)->getLimitedValue() <
                          cast<ConstantInt>(B)->getLimitedValue();
                 });
      ArrayType *ArrayOfInt64Ty = ArrayType::get(Int64Ty, Initializers.size());
      GlobalVariable *GV = new GlobalVariable(
          *CurModule, ArrayOfInt64Ty, false, GlobalVariable::InternalLinkage,
          ConstantArray::get(ArrayOfInt64Ty, Initializers),
          "__sancov_gen_cov_switch_values");
      IRB.CreateCall(SanCovTraceSwitchFunction,
                     {Cond, IRB.CreatePointerCast(GV, Int64PtrTy)});
    }
  }
}

void ModuleSanitizerCoverage::InjectTraceForDiv(
    Function &, ArrayRef<BinaryOperator *> DivTraceTargets) {
  for (auto BO : DivTraceTargets) {
    IRBuilder<> IRB(BO);
    Value *A1 = BO->getOperand(1);
    if (isa<ConstantInt>(A1)) continue;
    if (!A1->getType()->isIntegerTy())
      continue;
    uint64_t TypeSize = DL->getTypeStoreSizeInBits(A1->getType());
    int CallbackIdx = TypeSize == 32 ? 0 :
        TypeSize == 64 ? 1 : -1;
    if (CallbackIdx < 0) continue;
    auto Ty = Type::getIntNTy(*C, TypeSize);
    IRB.CreateCall(SanCovTraceDivFunction[CallbackIdx],
                   {IRB.CreateIntCast(A1, Ty, true)});
  }
}

void ModuleSanitizerCoverage::InjectTraceForGep(
    Function &, ArrayRef<GetElementPtrInst *> GepTraceTargets) {
  for (auto GEP : GepTraceTargets) {
    IRBuilder<> IRB(GEP);
    for (auto I = GEP->idx_begin(); I != GEP->idx_end(); ++I)
      if (!isa<ConstantInt>(*I) && (*I)->getType()->isIntegerTy())
        IRB.CreateCall(SanCovTraceGepFunction,
                       {IRB.CreateIntCast(*I, IntptrTy, true)});
  }
}

void ModuleSanitizerCoverage::InjectTraceForCmp(
    Function &F, ArrayRef<Instruction *> CmpTraceTargets) {
  if (
    F.getParent()->getName().str().find("drivers/") == F.getParent()->getName().str().npos
    && F.getParent()->getName().str().find("sound/") == F.getParent()->getName().str().npos
  ) {
    return;
  }
  for (auto I : CmpTraceTargets) {
    if (ICmpInst *ICMP = dyn_cast<ICmpInst>(I)) {
      IRBuilder<> IRB(ICMP);
      Value *A0 = ICMP->getOperand(0);
      Value *A1 = ICMP->getOperand(1);
      if (!A0->getType()->isIntegerTy())
        continue;
      uint64_t TypeSize = DL->getTypeStoreSizeInBits(A0->getType());
      int CallbackIdx = TypeSize == 8 ? 0 :
                        TypeSize == 16 ? 1 :
                        TypeSize == 32 ? 2 :
                        TypeSize == 64 ? 3 : -1;
      if (CallbackIdx < 0) continue;
      // __sanitizer_cov_trace_cmp((type_size << 32) | predicate, A0, A1);
      auto CallbackFunc = SanCovTraceCmpFunction[CallbackIdx];
      bool FirstIsConst = isa<ConstantInt>(A0);
      bool SecondIsConst = isa<ConstantInt>(A1);
      // If both are const, then we don't need such a comparison.
      if (FirstIsConst && SecondIsConst) continue;
      // If only one is const, then make it the first callback argument.
      if (FirstIsConst || SecondIsConst) {
        CallbackFunc = SanCovTraceConstCmpFunction[CallbackIdx];
        if (SecondIsConst)
          std::swap(A0, A1);
      }

      auto Ty = Type::getIntNTy(*C, TypeSize);
      IRB.CreateCall(CallbackFunc, {IRB.CreateIntCast(A0, Ty, true),
              IRB.CreateIntCast(A1, Ty, true)});
    }
  }
}

// added by nop
// just instrument drivers dir
bool ModuleSanitizerCoverage::InjectCoverageWithSVRanges(Function &F,
                                             ArrayRef<BasicBlock *> SVAllBlocks,
                                             bool IsLeafFunc) {
  if (SVAllBlocks.empty()) return false;
  llvm::outs() << "InjectCoverageWithSVRanges: " << F.getName().str() << " in " << F.getParent()->getName().str() << "\n";
//   if (F.getParent()->getName().str().find("drivers/") == F.getParent()->getName().str().npos) {
//     llvm::outs() << F.getName().str() << " in " << F.getParent()->getName().str() << ", not in drivers/ , skip\n";
//     return false;
//   }
  CreateFunctionLocalArrays(F, SVAllBlocks);
  for (size_t i = 0, N = SVAllBlocks.size(); i < N; i++)
    InjectCoverageWithSVRangesAtBlock(F, *SVAllBlocks[i], i, IsLeafFunc);
  return true;
}
// added by nop

void ModuleSanitizerCoverage::handleTypeRecursive(BasicBlock &BB, CallInst *C, Value *stPtr, Type *targetType, bool first, std::vector<int> &idxVec, std::vector<std::string> &tyVec) {
    bool hasStructElement;
    std::string type_str;
    llvm::raw_string_ostream rso(type_str);
    targetType->print(rso);
    std::vector<std::string>::iterator tyVec_iter;
    tyVec_iter = std::find(tyVec.begin(), tyVec.end(), rso.str());
    if ( tyVec_iter != tyVec.end()) {
        llvm::outs() << "Dup when handleTypeRecursive for type " << rso.str() << "\n";
        return;
    } else {
        llvm::outs() << "handleTypeRecursive for type " << rso.str() << "\n";
    }

    hasStructElement = false;
    if (!first && targetType->isPointerTy()) {
#ifdef DEBUG
        llvm::outs() << "!first && targetType->isPointerTy(), return\n";
#endif
      return;
    }
    if (targetType->isPointerTy()) {
#ifdef DEBUG
        llvm::outs() << "strip pointer\n";
#endif
        handleTypeRecursive(BB, C, stPtr, targetType->getContainedType(0), false, idxVec, tyVec);
    }
    if(targetType->isStructTy()) {
        StructType * STy = dyn_cast<StructType>(targetType);
        if (STy == nullptr || (STy->isLiteral()) || !(STy->hasName()) || targetType->getStructName().empty()) {
#ifdef DEBUG
                llvm::outs() << "STy == nullptr || !(STy->isLiteral()) || !(STy->hasName()) || targetType->getStructName().empty()\n";
                llvm::outs() <<  (STy == nullptr) << " || " << (STy->isLiteral()) << " || " << !(STy->hasName()) << " || " << targetType->getStructName().empty() << "\n";
#endif
            return;
        }
        std::string src_st_name = targetType->getStructName().str();
        if(src_st_name.find(".anon") != std::string::npos) {
            // OK, this is anonymous struct or union.
            llvm::outs() << *targetType << "\n";
            for(unsigned int curr_no=0; curr_no<targetType->getStructNumElements(); curr_no++) {
                // print by adding space
#ifdef DEBUG
                llvm::outs() << "getStructNumElements: \n";
                llvm::outs() << *(targetType->getStructElementType(curr_no)) << "\n";
#endif
                idxVec.push_back(int(curr_no));
                handleTypeRecursive(BB, C, stPtr, targetType->getStructElementType(curr_no), false, idxVec, tyVec);
                idxVec.pop_back();
            }
        }
        else {
            // for regular structure, we also print it's elements' types recursively
            llvm::outs() << *targetType << "\n";
            for(unsigned int curr_no=0; curr_no<targetType->getStructNumElements(); curr_no++) {
                // print by adding space
#ifdef DEBUG
                llvm::outs() << "getStructNumElements: \n";
                llvm::outs() << *(targetType->getStructElementType(curr_no)) << "\n";
#endif
                if (targetType->getStructElementType(curr_no)->isStructTy() || 
                  isa<ArrayType>(targetType->getStructElementType(curr_no))) {
                    hasStructElement = true;
                    break;
                }
            }
            if (hasStructElement)
            {
                for (unsigned int curr_no = 0;
                     curr_no < targetType->getStructNumElements();
                     curr_no++) {
                    // print by adding space
                    if (targetType->getStructElementType(curr_no)
                            ->isStructTy()) {
                        idxVec.push_back(int(curr_no));
                        handleTypeRecursive(BB, C, stPtr, targetType->getStructElementType(curr_no), false, idxVec, tyVec);
                        idxVec.pop_back();
                    }
                }
            }
        }
        // Regular structure, print normally.
        llvm::outs() << *targetType << "\n";
        IRBuilder<> IRB(C);
        IRB.SetCurrentDebugLocation(C->getDebugLoc());
        IRB.SetInsertPoint(&BB, ++IRB.GetInsertPoint());
        for (unsigned int curr_no = 0;
            curr_no < targetType->getStructNumElements(); curr_no++) {
            if (targetType->getStructElementType(curr_no)->isStructTy())
                continue;
            std::string SId;
            SId = src_st_name + ",0," + std::to_string(curr_no);
            llvm::outs() << "[+] Found Id: " << SId << ", Type: " << *(targetType->getStructElementType(curr_no)) << "\n";
            int sv_no = checkSV(SId);
            if (sv_no >= 0 && targetType->getStructElementType(curr_no)->isIntegerTy())
            {
                // 0 read, 1 write
                // Instrument GEP for field
                std::vector<Value*> element_index(2);
                Value *p = stPtr;
                for(std::vector<int>::iterator iter=idxVec.begin();iter!=idxVec.end();++iter)
                {
                    element_index.clear();
                    element_index.push_back(ConstantInt::get(Int32Ty, 0));
#ifdef DEBUG
                    llvm::outs() << "idx: " << (*iter) << "\n";
#endif
                    int idx = (*iter);
                    element_index.push_back(ConstantInt::get(Int32Ty, idx));
#ifdef DEBUG
                    llvm::outs() << "ready to createGEP, ptr: " << (*p) 
                        << ", element_index: "<< *element_index[0] << " " << *element_index[1] << "\n";
#endif
                    p = IRB.CreateInBoundsGEP(p, element_index);
                }
                element_index.clear();
                element_index.push_back(ConstantInt::get(Int32Ty, 0));
                element_index.push_back(ConstantInt::get(Int32Ty, curr_no));
#ifdef DEBUG
                llvm::outs() << "ready to createGEP, ptr: " << (*p) 
                        << ", element_index: "<< *element_index[0] << " " << *element_index[1] << "\n";
#endif
                Value *gepPtr = IRB.CreateInBoundsGEP(p, element_index);
                llvm::outs() << "CreateInBoundsGEP Done!\n";
                // IRB.CreateLoad(gepPtr);
                Value *gepRes = IRB.CreateLoad(gepPtr);
                if (LoadInst *myLI = dyn_cast<LoadInst>(gepRes)) {
                    LLVMContext& C = myLI->getContext();
                    MDNode* N = MDNode::get(C, MDString::get(C, "Instrumented Inst"));
                    myLI->setMetadata("my.md.inst", N);
                }
                Value *gep_int32 = IRB.CreateIntCast(gepRes, Int32Ty, false);
                Value *Args[] = { ConstantInt::get(Int32Ty, sv_no), gep_int32, ConstantInt::get(Int32Ty, 1) };
                IRB.CreateCall(SanCovTracePCWithSVRanges, Args);
                llvm::outs() << "In memcpy-like case, checkSV pass, Instrumented, SvNo: " << sv_no << "\n";
            }
        }
        llvm::outs() << "End memcpy call\n";
        tyVec.push_back(rso.str());
    }
}


// added by nop
void ModuleSanitizerCoverage::InjectCoverageWithSVRangesAtBlock(Function &F, BasicBlock &BB,
                                                    size_t Idx,
                                                    bool IsLeafFunc) {
  BasicBlock::iterator IP = BB.getFirstInsertionPt();
  bool IsEntryBB = &BB == &F.getEntryBlock();

  DebugLoc EntryLoc;
  if (IsEntryBB) {
    if (auto SP = F.getSubprogram())
      EntryLoc = DebugLoc::get(SP->getScopeLine(), 0, SP);
    // Keep static allocas and llvm.localescape calls in the entry block.  Even
    // if we aren't splitting the block, it's nice for allocas to be before
    // calls.
    IP = PrepareToSplitEntryBlock(BB, IP);
  } else {
    EntryLoc = IP->getDebugLoc();
  }

  
  int inst_flag = 0;
  std::string function_name = F.getName().str();
  if (Options.TracePCWithSVRanges) {

    for (auto &I : BB) {
#ifdef DEBUG
        llvm::outs() << "[debug] Current Inst: " << I << "\n";
#endif

        if (StoreInst *si = dyn_cast<StoreInst>(&I)) {
            llvm::outs() << "Current Inst: " << *si << "\n";
            if (!(si->getValueOperand()->getType()->isIntegerTy()))
                continue;
            // get StoreID
            std::string Sid = getStoreId(si);
            llvm::outs() << "Sid: " << Sid << "\n";
            int sv_no = checkSV(Sid);
            if (sv_no >= 0)
            {
                IRBuilder<> IRB(si);
                // std::string function_string = "SV.no: %d, SV Value: %d, type: %d\n";
                // sv_trace_func_ptr = IRB.CreateGlobalStringPtr(function_string);
                IRB.SetCurrentDebugLocation(si->getDebugLoc());
                IRB.SetInsertPoint(&BB, ++IRB.GetInsertPoint());
                Value * sValue = si->getValueOperand();
                Value *sValue_int32 = IRB.CreateIntCast(sValue, Int32Ty, false);
                // 0 read, 1 write
                Value *Args[] = { ConstantInt::get(Int32Ty, sv_no), sValue_int32, ConstantInt::get(Int32Ty, 1)};
                IRB.CreateCall(SanCovTracePCWithSVRanges, Args);
                inst_flag++;
                llvm::outs() << "checkSV pass, Instrumented, SvNo: " << sv_no << "\n";
                if (const DebugLoc Loc = I.getDebugLoc()) { 
                    unsigned Line = Loc.getLine();
                    unsigned Col = Loc.getCol();
                    std::string line_loc = "line:" + std::to_string(Line) + ":" + std::to_string(Col) + ":";
                    llvm::outs() << "Instrumented at : " << line_loc <<"\n";
                }
            } 
            else {
                // check alias
                // Here I is an LLVM instruction
                if (const DebugLoc Loc = I.getDebugLoc()) { 
                    unsigned Line = Loc.getLine();
                    unsigned Col = Loc.getCol();
                    std::string line_loc = "line:" + std::to_string(Line) + ":" + std::to_string(Col) + ":";
                    llvm::outs() << "checkSV: " << line_loc <<"\n";
                    for (std::set<std::pair<std::string, std::string>>::iterator
                      pair_it=inst_points.begin(),pair_ie=inst_points.end();
                      pair_it!=pair_ie;pair_it++) {
                        // line match
                        if (pair_it->first.find(line_loc) != pair_it->first.npos) {
                            if (inst_points_log.count(pair_it->first) == 0)
                            {
                                sv_no = checkSV(pair_it->second);
                                if (sv_no < 0)
                                    break;
                                Value * sValue = si->getValueOperand();
                                // 0 read, 1 write
                                IRBuilder<> IRB(si);
                                // std::string function_string = "SV.no: %d, SV Value: %d, type: %d\n";
                                // sv_trace_func_ptr = IRB.CreateGlobalStringPtr(function_string);
                                IRB.SetCurrentDebugLocation(si->getDebugLoc());
                                IRB.SetInsertPoint(&BB, ++IRB.GetInsertPoint());
                                Value *sValue_int32 = IRB.CreateIntCast(sValue, Int32Ty, false);
                                Value *Args[] = { ConstantInt::get(Int32Ty, sv_no), sValue_int32, ConstantInt::get(Int32Ty, 1) };
                                IRB.CreateCall(SanCovTracePCWithSVRanges, Args);
                                inst_flag++;
                                inst_points_log.insert(std::make_pair(pair_it->first, true));
                                llvm::outs() << "alias Instrumented: " << pair_it->first << ", SvNo: " << sv_no << "\n";
                                llvm::outs() << "Instrumented at : " << line_loc <<"\n";
                                break;
                            }
                        }
                    }
                }
            }
        }
        else if (CallInst *C = dyn_cast<CallInst>(&I)) {
            Type *svType = nullptr;
            Value *stPtr = nullptr;
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
                Value *tmp = C->getArgOperand(0);
                targetOperand = targetOperand->stripPointerCasts();
                llvm::outs() << "[+] Found Call: " << n << "\n";
                llvm::outs() << "isnt: " << (*C) << "\n";
                ty = targetOperand->getType();
                if (ty == nullptr || !(ty->isPointerTy()))
                    continue;
                ty = ty->getContainedType(0);
                if (ty->isStructTy()) {
                    llvm::outs() << "dst type: " << *(targetOperand->getType()) << "\n";
                    svType = ty;
                    for (Value::user_iterator tmp_it = tmp->user_begin(), tmp_ie = tmp->user_end();
                        tmp_it != tmp_ie; ++tmp_it) {
#ifdef DEBUG
                        llvm::outs() << "   user of tmp: " << *(*tmp_it) << "\n";
#endif
                        if (BitCastInst *BC = dyn_cast<BitCastInst>(*tmp_it)) {
#ifdef DEBUG
                            llvm::outs() << "BitCastInst " << *BC << "\n";
#endif
                            stPtr = (*tmp_it)->getOperand(0);
                            break;
                        }
                    }
                    if (stPtr == nullptr) {
                        for(auto tmp_us=tmp->use_begin(), tmp_ue=tmp->use_end(); tmp_us != tmp_ue; tmp_us++) {
#ifdef DEBUG
                            llvm::outs() << "   use of tmp: " << *(*tmp_us) << "\n";
#endif
                            if (BitCastInst *BC = dyn_cast<BitCastInst>(*tmp_us)) {
#ifdef DEBUG
                                llvm::outs() << "BitCastInst " << *BC << "\n";
#endif
                                stPtr = BC->getOperand(0);
                                svType = BC->getSrcTy();
                                llvm::outs() << "dst type: " << *(svType) << "\n";
                                break;
                            }
                        }
                    }
                }
                else {
                    for(auto us=targetOperand->use_begin(), ue=targetOperand->use_end(); us != ue; us++) {
#ifdef DEBUG
                        llvm::outs() << "   use of dst_ptr: " << *(*us) << "\n";
#endif
                        if (LoadInst * us_li = dyn_cast<LoadInst>(*us)) {
                            Value *tmpLoadOperand = us_li->getPointerOperand();
                            for (Value::user_iterator it = tmpLoadOperand->user_begin(), ie = tmpLoadOperand->user_end();
                                it != ie; ++it) {
#ifdef DEBUG
                                llvm::outs() << "       user of dst_ptr: " << *(*it) << "\n";
#endif
                                if (StoreInst *tmpStoreOperand = dyn_cast<StoreInst>(*it)) {
                                    Value *ptr = tmpStoreOperand->getValueOperand();
                                    Value *tmp2 = tmpStoreOperand->getValueOperand();
                                    ptr = ptr->stripPointerCasts();
                                    ty = ptr->getType();
                                    if (ty == nullptr || !(ty->isPointerTy()))
                                        continue;
                                    ty = ty->getContainedType(0);
                                    if (ty->isStructTy()) {
                                        llvm::outs() << "dst type: " << *(ty) << "\n";
                                        svType = ty;
                                        for (Value::user_iterator tmp_it = tmp2->user_begin(), tmp_ie = tmp2->user_end();
                                            tmp_it != tmp_ie; ++tmp_it) {
#ifdef DEBUG
                                            llvm::outs() << "   user of tmp: " << *(*tmp_it) << "\n";
#endif
                                            if (BitCastInst *BC = dyn_cast<BitCastInst>(*tmp_it)) {
#ifdef DEBUG
                                                llvm::outs() << "BitCastInst " << *BC << "\n";
#endif
                                                stPtr = (*tmp_it)->getOperand(0);
                                                svType = BC->getSrcTy();
                                                llvm::outs() << "dst type: " << *(svType) << "\n";
                                                break;
                                            }
                                        }
                                        if (stPtr == nullptr) {
                                            for(auto tmp_us=tmp2->use_begin(), tmp_ue=tmp2->use_end(); tmp_us != tmp_ue; tmp_us++) {
#ifdef DEBUG
                                            llvm::outs() << "   use of tmp: " << *(*tmp_us) << "\n";
#endif
                                            if (BitCastInst *BC = dyn_cast<BitCastInst>(*tmp_us)) {
#ifdef DEBUG
                                                llvm::outs() << "BitCastInst " << *BC << "\n";
#endif
                                                    stPtr = BC->getOperand(0);
                                                    svType = BC->getSrcTy();
                                                    llvm::outs() << "dst type: " << *(svType) << "\n";
                                                    break;
                                                }
                                            }
                                        }
                                        break;
                                    }
                                    else {
                                        for (Value::user_iterator ptr_it = ptr->user_begin(), ptr_ie = ptr->user_end();
                                            ptr_it != ptr_ie; ++ptr_it) {
#ifdef DEBUG
                                            llvm::outs() << "           user of dst_ptr: " << *(*ptr_it) << "\n";
#endif
                                            if (BitCastInst *BC = dyn_cast<BitCastInst>(*ptr_it)) {
#ifdef DEBUG
                                                llvm::outs() << "BitCastInst " << *BC << "\n";
#endif
                                                stPtr = (*ptr_it)->getOperand(0);
                                                ty = BC->getSrcTy();
                                                if (ty == nullptr || !(ty->isPointerTy()))
                                                    continue;
                                                ty = ty->getContainedType(0);
#ifdef DEBUG
                                                llvm::outs() << "srcType " << *(BC->getSrcTy()) << "\n";
#endif
                                                if (ty->isStructTy()) {
                                                    llvm::outs() << "dst type: " << *(ty) << "\n";
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
            if (svType != nullptr && stPtr != nullptr) {
                std::vector<int>idxVec;
                std::vector<std::string>tyVec;
                idxVec.clear();
                handleTypeRecursive(BB, C, stPtr, svType, true, idxVec, tyVec);
                if (const DebugLoc Loc = I.getDebugLoc()) { 
                    unsigned Line = Loc.getLine();
                    unsigned Col = Loc.getCol();
                    inst_flag++;
                    std::string line_loc = "line:" + std::to_string(Line) + ":" + std::to_string(Col) + ":";
                    llvm::outs() << "Instrumented at : " << line_loc <<"\n";
                }
            }
        }
    }
  }
  if (inst_flag)
        llvm::outs() << "Instrumented " << inst_flag << " in " << function_name << "\n";
  return;
}
// added by nop

void ModuleSanitizerCoverage::InjectCoverageAtBlock(Function &F, BasicBlock &BB,
                                                    size_t Idx,
                                                    bool IsLeafFunc) {
  BasicBlock::iterator IP = BB.getFirstInsertionPt();
  bool IsEntryBB = &BB == &F.getEntryBlock();
  DebugLoc EntryLoc;
  if (IsEntryBB) {
    if (auto SP = F.getSubprogram())
      EntryLoc = DebugLoc::get(SP->getScopeLine(), 0, SP);
    // Keep static allocas and llvm.localescape calls in the entry block.  Even
    // if we aren't splitting the block, it's nice for allocas to be before
    // calls.
    IP = PrepareToSplitEntryBlock(BB, IP);
  } else {
    EntryLoc = IP->getDebugLoc();
  }

  IRBuilder<> IRB(&*IP);
  IRB.SetCurrentDebugLocation(EntryLoc);
  if (Options.TracePC) {
    IRB.CreateCall(SanCovTracePC)
        ->setCannotMerge(); // gets the PC using GET_CALLER_PC.
  }
  if (Options.TracePCGuard) {
    auto GuardPtr = IRB.CreateIntToPtr(
        IRB.CreateAdd(IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                      ConstantInt::get(IntptrTy, Idx * 4)),
        Int32PtrTy);
    IRB.CreateCall(SanCovTracePCGuard, GuardPtr)->setCannotMerge();
  }
  if (Options.Inline8bitCounters) {
    auto CounterPtr = IRB.CreateGEP(
        Function8bitCounterArray->getValueType(), Function8bitCounterArray,
        {ConstantInt::get(IntptrTy, 0), ConstantInt::get(IntptrTy, Idx)});
    auto Load = IRB.CreateLoad(Int8Ty, CounterPtr);
    auto Inc = IRB.CreateAdd(Load, ConstantInt::get(Int8Ty, 1));
    auto Store = IRB.CreateStore(Inc, CounterPtr);
    SetNoSanitizeMetadata(Load);
    SetNoSanitizeMetadata(Store);
  }
  if (Options.InlineBoolFlag) {
    auto FlagPtr = IRB.CreateGEP(
        FunctionBoolArray->getValueType(), FunctionBoolArray,
        {ConstantInt::get(IntptrTy, 0), ConstantInt::get(IntptrTy, Idx)});
    auto Load = IRB.CreateLoad(Int1Ty, FlagPtr);
    auto ThenTerm =
        SplitBlockAndInsertIfThen(IRB.CreateIsNull(Load), &*IP, false);
    IRBuilder<> ThenIRB(ThenTerm);
    auto Store = ThenIRB.CreateStore(ConstantInt::getTrue(Int1Ty), FlagPtr);
    SetNoSanitizeMetadata(Load);
    SetNoSanitizeMetadata(Store);
  }
  if (Options.StackDepth && IsEntryBB && !IsLeafFunc) {
    // Check stack depth.  If it's the deepest so far, record it.
    Module *M = F.getParent();
    Function *GetFrameAddr = Intrinsic::getDeclaration(
        M, Intrinsic::frameaddress,
        IRB.getInt8PtrTy(M->getDataLayout().getAllocaAddrSpace()));
    auto FrameAddrPtr =
        IRB.CreateCall(GetFrameAddr, {Constant::getNullValue(Int32Ty)});
    auto FrameAddrInt = IRB.CreatePtrToInt(FrameAddrPtr, IntptrTy);
    auto LowestStack = IRB.CreateLoad(IntptrTy, SanCovLowestStack);
    auto IsStackLower = IRB.CreateICmpULT(FrameAddrInt, LowestStack);
    auto ThenTerm = SplitBlockAndInsertIfThen(IsStackLower, &*IP, false);
    IRBuilder<> ThenIRB(ThenTerm);
    auto Store = ThenIRB.CreateStore(FrameAddrInt, SanCovLowestStack);
    SetNoSanitizeMetadata(LowestStack);
    SetNoSanitizeMetadata(Store);
  }
}

std::string
ModuleSanitizerCoverage::getSectionName(const std::string &Section) const {
  if (TargetTriple.isOSBinFormatCOFF()) {
    if (Section == SanCovCountersSectionName)
      return ".SCOV$CM";
    if (Section == SanCovBoolFlagSectionName)
      return ".SCOV$BM";
    if (Section == SanCovPCsSectionName)
      return ".SCOVP$M";
    return ".SCOV$GM"; // For SanCovGuardsSectionName.
  }
  if (TargetTriple.isOSBinFormatMachO())
    return "__DATA,__" + Section;
  return "__" + Section;
}

std::string
ModuleSanitizerCoverage::getSectionStart(const std::string &Section) const {
  if (TargetTriple.isOSBinFormatMachO())
    return "\1section$start$__DATA$__" + Section;
  return "__start___" + Section;
}

std::string
ModuleSanitizerCoverage::getSectionEnd(const std::string &Section) const {
  if (TargetTriple.isOSBinFormatMachO())
    return "\1section$end$__DATA$__" + Section;
  return "__stop___" + Section;
}

char ModuleSanitizerCoverageLegacyPass::ID = 0;
INITIALIZE_PASS_BEGIN(ModuleSanitizerCoverageLegacyPass, "sancov",
                      "Pass for instrumenting coverage on functions", false,
                      false)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTreeWrapperPass)
INITIALIZE_PASS_END(ModuleSanitizerCoverageLegacyPass, "sancov",
                    "Pass for instrumenting coverage on functions", false,
                    false)
ModulePass *llvm::createModuleSanitizerCoverageLegacyPassPass(
    const SanitizerCoverageOptions &Options,
    const std::vector<std::string> &AllowlistFiles,
    const std::vector<std::string> &BlocklistFiles) {
  return new ModuleSanitizerCoverageLegacyPass(Options, AllowlistFiles,
                                               BlocklistFiles);
}


