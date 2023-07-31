/*
checkCondition -> dumpStateRange
    -> MemRegion_str_tuple handleCommonSymbolExpr(const SymbolRef sym, PrimRangeSet range_set, CheckerContext &checkerContext);
        -> qualType_str_pair handleRegion(const MemRegion *R, PrimRangeSet range_set, CheckerContext &checkerContext, QualType T);
        -> void dumpRange(const MemRegion *R, std::string sym_type, PrimRangeSet range_set, CheckerContext &checkerContext);

handleFieldRegion need type info of superRegion to find field type declare.

*/
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/RangedConstraintManager.h"
#include <sstream>
#include <iostream>
#include <fstream>
#include <z3++.h>

// #define DEBUG

using namespace z3;
using namespace clang;
using namespace ento;
using namespace std;

// const string set
// std::set<std::string> sv_str_set = {"struct._HISEE_MODULE_DATA,0,2", "struct._HISEE_MODULE_DATA,0,9", "struct.hwaa_package_info_t,0,1", "var.wakeup_is_start"};
typedef std::pair<std::string, std::string> name_type_pair;
typedef std::pair<const ValueDecl *, int> valueDecl_no_pair;
typedef std::pair<QualType, std::string> qualType_str_pair;
typedef std::tuple<const MemRegion *, std::string, QualType> MemRegion_str_tuple;
typedef llvm::ImmutableSet<Range, RangeTrait> PrimRangeSet;
// tuple< opcode, rhs, range_set>
typedef std::tuple<StringRef, std::string, std::set<std::pair<std::string, std::string>>> cacheKey;
// pair <name, type>
std::vector<name_type_pair> type_vector;
// std::mutex type_vector_mutex;

std::set<std::string> sv_str_set;
std::set<std::string> sv_struct_str_set;
std::set<std::string> out_str_set;
std::set<std::string> sv_set_in_one_check;
std::set<std::set<std::string>> sv_set_in_all_checks;
std::map<cacheKey, std::set<std::pair<int, int>>> cacheSymIntExpr;

namespace {
class SymStateVariableValueAnalysisChecker : public Checker< check::BranchCondition > {
//   mutable std::unique_ptr<BuiltinBug> BT;
//   void reportBug(const char *Msg, ProgramStateRef StateZero, CheckerContext &C,
//                  std::unique_ptr<BugReporterVisitor> Visitor = nullptr) const;
public:
    SymStateVariableValueAnalysisChecker();
    ~SymStateVariableValueAnalysisChecker() {
        for (auto s : sv_set_in_all_checks) {
            llvm::outs() << "\n [+] sv_in_one_check:  ";
            for (auto my_sv : s) {
                llvm::outs() << my_sv << "; ";
            }
            llvm::outs() << "\n";
        }
    }
    void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};
} // end anonymous namespace


SymStateVariableValueAnalysisChecker::SymStateVariableValueAnalysisChecker(void) {
    ifstream sv_file;
    std::string line;
    std::string struct_name;
    std::set<std::string> sv_str_set_consistent;
    std::set<std::string> sv_struct_str_set_consistent;

    sv_file.open("/tmp/sv_list.txt");
    if (!sv_file.is_open()) {
        // cout << "Error opening ioctl_top_function_file";
        llvm::outs() << "[!] open /tmp/sv_list.txt error!\n";
        exit(1);
    }
    sv_str_set_consistent.clear();
    while (!sv_file.eof()) {
        getline(sv_file, line);
        // llvm::outs() << "line: " << line << "\n";
        if (line.find_first_of("struct.") == line.npos) {
            if (sv_struct_str_set_consistent.count(line) == 0) {
                sv_struct_str_set_consistent.insert(line);
            }
        }

        if (line.find_first_of("struct.") != line.npos && line.find_first_of(",") != line.npos) {
            struct_name = line.substr(line.find_first_of("struct.") + 7, line.find_first_of(",") - line.find_first_of("struct.") - 7);
            if (sv_struct_str_set_consistent.count(struct_name) == 0) {
                sv_struct_str_set_consistent.insert(struct_name);
            }
        }
        sv_struct_str_set_consistent.insert(line);
    }
    sv_file.close();
    sv_struct_str_set = sv_struct_str_set_consistent;
#ifdef DEBUG
    llvm::outs() << "[+] sv_str initialized\n";
#endif
    return;
}


void addSymIntConstraint(solver s, expr x, expr y, BinaryOperator::Opcode op, llvm::APSInt& v, int upper, int lower);
bool walkExpr(const Expr *E, CheckerContext &checkerContext);
bool walkBinaryOperator(const BinaryOperator *B, CheckerContext &checkerContext);
bool walkUnaryOperator(const UnaryOperator *U, CheckerContext &checkerContext);
bool walkImplicitCastExpr(const ImplicitCastExpr *I, CheckerContext &checkerContext);
bool walkMemberExpr(const MemberExpr *M, CheckerContext &checkerContext);
bool walkDeclRefExpr(const DeclRefExpr *D, CheckerContext &checkerContext);
bool walkIntegerLiteral(const IntegerLiteral *I, CheckerContext &checkerContext);
bool walkCStyleCastExpr(const CStyleCastExpr *C, CheckerContext &checkerContext);
bool walkParenExpr(const ParenExpr *P, CheckerContext &checkerContext);
bool walkCallExpr(const CallExpr *C, CheckerContext &checkerContext);
bool walkStringLiteral(const StringLiteral *S, CheckerContext &checkerContext);
// todo
// void UnaryExprOrTypeTraitExpr
// void ArraySubscriptExpr
// void 
std::string findMemberDeclNo(const ValueDecl *VD, CheckerContext &checkerContext);
qualType_str_pair handleRegion(const MemRegion *R, PrimRangeSet range_set, CheckerContext &checkerContext, QualType T);
qualType_str_pair handleVarRegion(const VarRegion *VR, PrimRangeSet range_set, CheckerContext &checkerContext);
qualType_str_pair handleFieldRegion(const FieldRegion *FR, PrimRangeSet range_set, CheckerContext &checkerContext);
qualType_str_pair handleElementRegion(const ElementRegion *ER, PrimRangeSet range_set, CheckerContext &checkerContext);
qualType_str_pair handleSymbolicRegion(const SymbolicRegion *SR, PrimRangeSet range_set, CheckerContext &checkerContext);
MemRegion_str_tuple handleCommonSymbolExpr(const SymbolRef sym, PrimRangeSet range_set, CheckerContext &checkerContext);
MemRegion_str_tuple handleSymbolRegionValue(const SymbolRegionValue *SR, PrimRangeSet range_set, CheckerContext &checkerContext);
MemRegion_str_tuple handleSymbolDerived(const SymbolDerived *SD, PrimRangeSet range_set, CheckerContext &checkerContext);
MemRegion_str_tuple handleSymbolMetadata(const SymbolMetadata *SM, PrimRangeSet range_set, CheckerContext &checkerContext);
MemRegion_str_tuple handleSymbolExtent(const SymbolExtent *SE, PrimRangeSet range_set, CheckerContext &checkerContext);
MemRegion_str_tuple handleSymbolConjured(const SymbolConjured *SC, PrimRangeSet range_set, CheckerContext &checkerContext);
MemRegion_str_tuple handleSymbolCast(const SymbolCast *SCAST, PrimRangeSet range_set, CheckerContext &checkerContext);
MemRegion_str_tuple handleSymSymExpr(const SymSymExpr *SSE, PrimRangeSet range_set, CheckerContext &checkerContext);
MemRegion_str_tuple handleSymIntExpr(const SymIntExpr *SIE, PrimRangeSet range_set, CheckerContext &checkerContext);
MemRegion_str_tuple handleIntSymExpr(const IntSymExpr *ISE, PrimRangeSet range_set, CheckerContext &checkerContext);
void dumpRange(const MemRegion *R, std::string sym_type, PrimRangeSet range_set, CheckerContext &checkerContext);
void dumpStateRange(ProgramStateRef state, CheckerContext &checkerContext);


void addSymIntConstraint(solver s, expr x, expr y, BinaryOperator::Opcode op, int v_int, int upper, int lower) {
    int m;
    switch (op) {
        case BO_And:
            s.add((x & y)>=lower);
            s.add((x & y)<=upper);
            s.add(y == v_int);
            break;
        case BO_Or:
            s.add((x | y)>=lower);
            s.add((x | y)<=upper);
            s.add(y == v_int);
            break;
        case BO_Xor:
            s.add((x ^ y)>=lower);
            s.add((x ^ y)<=upper);
            s.add(y == v_int);
            break;
        case BO_Div:
            s.add((x / y)>=lower);
            s.add((x / y)<=upper);
            s.add(y == v_int);
            break;
        case BO_Mul:
            s.add((x * y)>=lower);
            s.add((x * y)<=upper);
            s.add(y == v_int);
            break;
        case BO_Add:
            s.add((x + y)>=lower);
            s.add((x + y)<=upper);
            s.add(y == v_int);
            break;
        case BO_Sub:
            s.add((x - y)>=lower);
            s.add((x - y)<=upper);
            s.add(y == v_int);
            break;
        case BO_Rem:
            s.add((x % y)>=lower);
            s.add((x % y)<=upper);
            s.add(y == v_int);
            break;
        case BO_Shl:
            m = 1;
            if (v_int <= 32)
                for (int i=0; i<v_int; i++) {
                    m *= 2;
                }
            else
                return;
            s.add((x * m)>=lower);
            break;
        case BO_Shr:
            m = 1;
            if (v_int <= 32)
                for (int i=0; i<v_int; i++) {
                    m *= 2;
                }
            else
                return;
            s.add((x / m)>=lower);
            break;
        default:
#ifdef DEBUG
            llvm::outs() << "[!] Other BinaryOperator Type in addSymIntConstraint\n";
#endif
            break;
    }
    return;
}

bool walkExpr(const Expr *E, CheckerContext &checkerContext) {
  if (const BinaryOperator *BE = dyn_cast<BinaryOperator>(E)) {
    return walkBinaryOperator(BE, checkerContext);
  } else if (const UnaryOperator *UE = dyn_cast<UnaryOperator>(E)) {
    return walkUnaryOperator(UE, checkerContext);
  } else if (const ImplicitCastExpr *IE = dyn_cast<ImplicitCastExpr>(E)) {
    return walkImplicitCastExpr(IE, checkerContext);
  } else if (const MemberExpr *ME = dyn_cast<MemberExpr>(E)) {
    return walkMemberExpr(ME, checkerContext);
  } else if (const DeclRefExpr *DE = dyn_cast<DeclRefExpr>(E)) {
    return walkDeclRefExpr(DE, checkerContext);
  } else if (const IntegerLiteral *LE = dyn_cast<IntegerLiteral>(E)) {
    return walkIntegerLiteral(LE, checkerContext);
  } else if (const CStyleCastExpr *CE = dyn_cast<CStyleCastExpr>(E)) {
    return walkCStyleCastExpr(CE, checkerContext);
  } else if (const ParenExpr *PE = dyn_cast<ParenExpr>(E)) {
    return walkParenExpr(PE, checkerContext);
  } else if (const CallExpr *CE = dyn_cast<CallExpr>(E)) {
    return walkCallExpr(CE, checkerContext);
  } else if (const StringLiteral *SE = dyn_cast<StringLiteral>(E)) {
    return walkStringLiteral(SE, checkerContext);
  }
  else {
    llvm::outs() << "\n[!] walkExpr find no matching type!\n";
    llvm::outs() << E->getStmtClassName() << "\n"; 
  }
  return false;
}

bool walkBinaryOperator(const BinaryOperator *B, CheckerContext &checkerContext) {
    bool a=false, b=false;
    Expr *BRHS = B->getRHS();
    if (!BRHS) {
        llvm::outs() << "\n[!] BinaryOperator getRHS error!\n";
    }
    else
        a = walkExpr(BRHS, checkerContext);
    Expr *BLHS = B->getLHS();
    if (!BLHS) {
        llvm::outs() << "\n[!] BinaryOperator getLHS error!\n";
    }
    else
        b = walkExpr(BLHS, checkerContext);
    return a | b;
}

bool walkUnaryOperator(const UnaryOperator *U, CheckerContext &checkerContext) {
    Expr *SU = U->getSubExpr();
    if (!SU) {
        llvm::outs() << "\n[!] UnaryOperator getSubExpr error!\n";
        return false;
    }
    return walkExpr(SU, checkerContext);
}

bool walkImplicitCastExpr(const ImplicitCastExpr *I, CheckerContext &checkerContext) {
    bool res = false;
    for (ImplicitCastExpr::const_child_iterator iter = I->child_begin(),
      iter_end = I->child_end(); iter != iter_end; ++iter) {
        if (const Expr *E = dyn_cast<Expr>(*iter)) {
            res |= walkExpr(E, checkerContext);
        }
        else {
            llvm::outs() << "\n[!] ImplicitCastExpr Iter Error!\n";
        }
    }
    return res;
}

bool walkIntegerLiteral(const IntegerLiteral *I, CheckerContext &checkerContext) {
    return false;
}

bool walkCStyleCastExpr(const CStyleCastExpr *C, CheckerContext &checkerContext) {
    bool res = false;
    for (CStyleCastExpr::const_child_iterator iter = C->child_begin(),
      iter_end = C->child_end(); iter != iter_end; ++iter) {
        if (const Expr *E = dyn_cast<Expr>(*iter)) {
            res |= walkExpr(E, checkerContext);
        }
        else {
            llvm::outs() << "\n[!] CStyleCastExpr Iter Error!\n";
        }
    }
    return res;
}

bool walkParenExpr(const ParenExpr *P, CheckerContext &checkerContext) {
    const Expr *SP = P->getSubExpr();
    if (!SP) {
        llvm::outs() << "\n[!] walkParenExpr getSubExpr error!\n";
        return false;
    }
    return walkExpr(SP, checkerContext);
}

bool walkCallExpr(const CallExpr *C, CheckerContext &checkerContext) {
    bool res = false;
    for (CallExpr::const_arg_iterator iter = C->arg_begin(),
      iter_end = C->arg_end(); iter != iter_end; ++iter) {
        if (const Expr *E = dyn_cast<Expr>(*iter)) {
            res |= walkExpr(E, checkerContext);
        }
        else {
            llvm::outs() << "\n[!] CallExpr Iter Error!\n";
        }
    }
    return res;
}

bool walkStringLiteral(const StringLiteral *S, CheckerContext &checkerContext) {
    return false;
}

bool walkMemberExpr(const MemberExpr *M, CheckerContext &checkerContext) {
    bool res = false;
    std::string name, type;

    name = M->getMemberDecl()->getNameAsString();
    // Desugared Type: for example, typedef struct _HISEE_MODULE_DATA hisee_module_data,
    // then _HISEE_MODULE_DATA is the desugar type of hisee_module_data
    type = M->getMemberDecl()->getType().getSingleStepDesugaredType(
      checkerContext.getASTContext()).getAsString();
    llvm::outs() << "\n[+] Dump Member Info\n";
    llvm::outs() << "name: " << name << "  type: " << type << "\n";

    type_vector.push_back({name, type});
    
    for (MemberExpr::const_child_iterator iter = M->child_begin(),
      iter_end = M->child_end(); iter != iter_end; ++iter) {
        if (const Expr *E = dyn_cast<Expr>(*iter)) {
            res |= walkExpr(E, checkerContext);
        }
        else {
            llvm::outs() << "\n[!] MemberExpr Iter Error!\n";
        }
    }
    return res;
}

bool walkDeclRefExpr(const DeclRefExpr *D, CheckerContext &checkerContext) {
    std::string name, type;
    std::string field_name, field_type;
    std::string value_str="";

    name = D->getDecl()->getNameAsString();
    // Desugared Type: for example, typedef struct _HISEE_MODULE_DATA hisee_module_data,
    // then _HISEE_MODULE_DATA is the desugar type of hisee_module_data
    type = D->getDecl()->getType().getSingleStepDesugaredType(
      checkerContext.getASTContext()).getAsString();

    llvm::outs() << "\n[+] DeclName: " << name << "\n    DeclType: " << type << "\n";

    // not normal type like int, but struct/enum like type
    if (type.find("struct ") != type.npos || type.find("enum ") != type.npos || type.find("union ") != type.npos) {
      value_str = findMemberDeclNo(D->getDecl(), checkerContext);
      type_vector.clear();
    }

    if (type.find("struct ") != type.npos) {
        value_str = "struct." + type.substr(type.find("struct ") + 7) + ",0," + value_str;
    } 
    else if (type.find("enum ") != type.npos) {
        value_str = "enum." + type.substr(type.find("enum ") + 5) + ",0," + value_str;
    }
    else if (type.find("union ") != type.npos) {
        value_str = "union." + type.substr(type.find("union ") + 6) + ",0," + value_str;
    }
    else {
        value_str = "var." + name;
    }

    llvm::outs() << value_str << "\n";

    if (sv_str_set.count(value_str) != 0) {
        return true;
    }
    return false;
}


// return like "0,9" included in "_HISEE_MODULE_DATA,0,9"
// g_hisee_data->element1->element2在type_vector表示为
// bottom <- element2 <- element1 <- top
// 因此需要找到最上层struct定义后pop vector来一层层找到子结构体定义
std::string findMemberDeclNo(const ValueDecl *VD, CheckerContext &checkerContext) {
    std::map<name_type_pair, valueDecl_no_pair> field_type_map;
    std::string name, type;
    std::string field_name, field_type;
    name_type_pair nt_pair;
    valueDecl_no_pair vn_pair;
    std::string memberDeclNo_str="", tmp_str="";

    name = VD->getNameAsString();
    // Desugared Type: for example, typedef struct _HISEE_MODULE_DATA hisee_module_data,
    // then _HISEE_MODULE_DATA is the desugar type of hisee_module_data
    type = VD->getType().getSingleStepDesugaredType(
      checkerContext.getASTContext()).getAsString();

    if (const RecordType *RT = VD->getType()->getPointeeType().isNull()?
          VD->getType()->getAsStructureType():
          VD->getType()->getPointeeType()->getAsStructureType()) {
        const RecordDecl *RD = RT->getDecl()->getDefinition();
        assert(RD && "Referred record has no definition");
        int field_no = 0;
        for (const auto *I : RD->fields()) {
            field_name = I->getNameAsString();
            field_type = I->getType().getSingleStepDesugaredType(
              checkerContext.getASTContext()).getAsString();
            // llvm::outs() << "[+] FieldName: " << field_name << "\n    FieldType: " << field_type << "\n";
            if (const ValueDecl *vd_field = dyn_cast<ValueDecl>(I)) {
                nt_pair = std::make_pair(field_name, field_type);
                vn_pair = std::make_pair(vd_field, field_no);
                field_type_map[nt_pair] = vn_pair;
            }
            field_no++;
        }
    }
    if (!type_vector.empty() && !field_type_map.empty()) {
        nt_pair = type_vector.back();
        type_vector.pop_back();
        if (field_type_map.count(nt_pair) != 0) {
#ifdef DEBUG
            llvm::outs() << "[+] Match, FieldName: " << nt_pair.first
                         << "\n    FieldType: " << nt_pair.second << "\n";
#endif
            tmp_str = findMemberDeclNo(field_type_map[nt_pair].first, checkerContext);
        
            std::ostringstream oss;
            if (tmp_str.compare("")) {
                // if tmp_str not empty
                oss << field_type_map[nt_pair].second << "," << tmp_str;
            } else {
                oss << field_type_map[nt_pair].second;
            }
            memberDeclNo_str = oss.str();
        }
    }
    return memberDeclNo_str;
}

qualType_str_pair handleRegion(const MemRegion *R, PrimRangeSet range_set, CheckerContext &checkerContext, QualType T) {
    QualType qt;
    std::string tmp;

    if (R == NULL) {
        if (T.isNull())
            return std::make_pair(qt, "[!] NULL Region");
        else
        {
            tmp = T->getPointeeType().isNull()?
              T.getSingleStepDesugaredType(
                checkerContext.getASTContext()).getAsString():
              T->getPointeeType().getSingleStepDesugaredType(
                checkerContext.getASTContext()).getAsString();
            if (tmp.find("struct ") != tmp.npos)
                tmp = tmp.substr(tmp.find("struct ") + 7) + ",0";
            else if (tmp.find("enum ") != tmp.npos)
                tmp = tmp.substr(tmp.find("enum ") + 5) + ",0";
            else if (tmp.find("union ") != tmp.npos)
                tmp = tmp.substr(tmp.find("union ") + 6) + ",0";
            return std::make_pair(T, tmp);
        }
    }
    #ifdef DEBUG
        llvm::outs() << "handle Region: " << R << "\n";
    #endif
    if (const FieldRegion *fr = dyn_cast<FieldRegion>(R)) {
        return handleFieldRegion(fr, range_set, checkerContext);
    } 
    else if (const ElementRegion *er = dyn_cast<ElementRegion>(R)) {
        return handleElementRegion(er, range_set, checkerContext);
    } 
    else if (const VarRegion *vr = dyn_cast<VarRegion>(R)) {
        return handleVarRegion(vr, range_set, checkerContext);
    }
    else if (const SymbolicRegion *sr = dyn_cast<SymbolicRegion>(R)) {
        return handleSymbolicRegion(sr, range_set, checkerContext);
    }
    else {
        return std::make_pair(qt, "[!] Unknown Region");
    }
}

qualType_str_pair handleVarRegion(const VarRegion *VR, PrimRangeSet range_set, CheckerContext &checkerContext) {
    std::string name, type;
    llvm::raw_string_ostream os(name);
    const auto *VD = cast<VarDecl>(VR->getDecl());
    type = VR->getDecl()->getType().getSingleStepDesugaredType(
      checkerContext.getASTContext()).getAsString();
    if (const IdentifierInfo *ID = VD->getIdentifier())
        name = ID->getName().str();
    else {
        os << "VarRegion{D" << VD->getID() << '}';
        name = os.str();
    }
    // if var is a struct/enum type
    if (type.find("struct ") != type.npos || type.find("enum ") != type.npos || type.find("union ") != type.npos) {
        type = VR->getDecl()->getType()->getPointeeType().isNull()?
          VR->getDecl()->getType().getSingleStepDesugaredType(
      checkerContext.getASTContext()).getAsString():
          VR->getDecl()->getType()->getPointeeType().getSingleStepDesugaredType(
      checkerContext.getASTContext()).getAsString();
        if (type.find("struct ") != type.npos) {
            type = type.substr(type.find("struct ") + 7) + ",0";
            return std::make_pair(VR->getDecl()->getType(), "structType: " + type);
        }
        else if (type.find("enum ") != type.npos) {
            type = type.substr(type.find("enum ") + 5) + ",0";
            return std::make_pair(VR->getDecl()->getType(), "enumType: " + type);            
        }
        else if (type.find("union ") != type.npos) {
            type = type.substr(type.find("union ") + 6) + ",0";
            return std::make_pair(VR->getDecl()->getType(), "unionType: " + type);            
        }
    }
    else {
        if (VD->isLocalVarDeclOrParm())
            return std::make_pair(VR->getDecl()->getType(), "lvarType(Local): " + type + " varName: " + name);
        else
            return std::make_pair(VR->getDecl()->getType(), "varType: " + type + " varName: " + name);
    }
}

qualType_str_pair handleFieldRegion(const FieldRegion *FR, PrimRangeSet range_set, CheckerContext &checkerContext) {
    qualType_str_pair qs_pair;
    QualType qt;
    std::string name="", type="", field_name, field_type;
    std::ostringstream oss;
    std::string res_str="";
    bool findField = false;

    name = FR->getDecl()->getNameAsString();
    type = FR->getDecl()->getType().getSingleStepDesugaredType(
      checkerContext.getASTContext()).getAsString();

    if (const MemRegion *superR = dyn_cast<MemRegion>(FR->getSuperRegion()))
    {
        qs_pair = handleRegion(superR, range_set, checkerContext, qt);
        if (qs_pair.first.isNull())
        {
#ifdef DEBUG
            llvm::outs() << "[!] superR is Null!\n";
#endif
            return std::make_pair(FR->getDecl()->getType(), res_str);
        }
#ifdef DEBUG
        llvm::outs() << " superR type: " << qs_pair.first.getAsString() << "\n";
#endif
        if (const RecordType *RT = qs_pair.first->getPointeeType().isNull()? 
          qs_pair.first->getAsStructureType():
          qs_pair.first->getPointeeType()->getAsStructureType()) {
            const RecordDecl *RD = RT->getDecl()->getDefinition();
            assert(RD && "Referred record has no definition");
            int field_no = -1;
            findField = false;
            bool isFirstBitField = true;
            for (const auto *I : RD->fields()) {
                if (I->isBitField()) {
                    if (isFirstBitField) {
                        field_no++;
                        isFirstBitField = false;
                    }
                } else {
                    field_no++;
                    isFirstBitField = true;
                }
                field_name = I->getNameAsString();
                field_type = I->getType().getSingleStepDesugaredType(
                    checkerContext.getASTContext()).getAsString();
#ifdef DEBUG
                llvm::outs() << "[+] FieldName: " << field_name << "\n    FieldType: " << field_type << " isBitField:" << I->isBitField() << " idx: "<< field_no << "\n";
#endif
                if (!field_name.compare(name) && !field_type.compare(type)) {
                    if (!qs_pair.second.compare(""))
                    {
                        // parent str is ""
                        oss << name;
                    }
                    else {
                        if (field_type.find("struct ") != field_type.npos || field_type.find("union ") != field_type.npos)
                            oss << qs_pair.second << "," << field_no << "::" << field_type << ",0";
                        else
                            oss << qs_pair.second << "," << field_no;
                    }
                    res_str = oss.str();
                    findField = true;
#ifdef DEBUG
                    llvm::outs() << "[+] FieldName: " << field_name << "\n    FieldType: " << field_type << " isBitField:" << I->isBitField() << " idx: "<< field_no << "\n";
#endif
                    break;
                }
            }
        }
        // union type
        else if (const RecordType *RTU = qs_pair.first->getPointeeType().isNull()? 
          qs_pair.first->getAsUnionType():
          qs_pair.first->getPointeeType()->getAsUnionType()) {
            const RecordDecl *RDU = RTU->getDecl()->getDefinition();
            assert(RDU && "Referred record has no definition");
            int field_no_u = -1;
            bool isFirstBitField = true;
            findField = false;
            for (const auto *I : RDU->fields()) {
                if (I->isBitField()) {
                    if (isFirstBitField) {
                        field_no_u++;
                        isFirstBitField = false;
                    }
                } else {
                    field_no_u++;
                    isFirstBitField = true;
                }
                field_name = I->getNameAsString();
                field_type = I->getType().getSingleStepDesugaredType(
                    checkerContext.getASTContext()).getAsString();
#ifdef DEBUG
                llvm::outs() << "[+] FieldName: " << field_name << "\n    FieldType: " << field_type << " isBitField:" << I->isBitField() << " idx: "<< field_no_u << "\n";
#endif
                if (!field_name.compare(name) && !field_type.compare(type)) {
                    if (!qs_pair.second.compare(""))
                    {
                        // parent str is ""
                        oss << name;
                    }
                    else {
                        if (field_type.find("struct ") != field_type.npos || field_type.find("union ") != field_type.npos)
                            oss << qs_pair.second << "," << field_no_u << "::" << field_type << ",0";
                        else
                            oss << qs_pair.second << "," << field_no_u;
                    }
                    res_str = oss.str();
                    findField = true;
#ifdef DEBUG
                    llvm::outs() << "[+] FieldName: " << field_name << "\n    FieldType: " << field_type << " isBitField:" << I->isBitField() << " idx: "<< field_no_u << "\n";
#endif
                    break;
                }
            }
        }
#ifdef DEBUG
        else {
            llvm::outs() << "[!] SuperRegion is not getAsStructure/UnionType().\n";
        }
#endif
    }
    else {
#ifdef DEBUG
        llvm::outs() << "[!] superR cast to MemRegion failed!\n";
#endif
        return std::make_pair(FR->getDecl()->getType(), "");
    }
    if (!findField)
    {
#ifdef DEBUG
        llvm::outs() << "[!] find Field failed!\n";
#endif
        return std::make_pair(FR->getDecl()->getType(), "");
    }
    return std::make_pair(FR->getDecl()->getType().getSingleStepDesugaredType(
                    checkerContext.getASTContext()), res_str);
}

qualType_str_pair handleElementRegion(const ElementRegion *ER, PrimRangeSet range_set, CheckerContext &checkerContext) {
    std::string type;
    type = ER->getElementType()->getPointeeType().isNull()?
          ER->getElementType().getSingleStepDesugaredType(
      checkerContext.getASTContext()).getAsString():
          ER->getElementType()->getPointeeType().getSingleStepDesugaredType(
      checkerContext.getASTContext()).getAsString();
    if (type.find("struct ") != type.npos) {
        type = type.substr(type.find("struct ") + 7) + ",0";
        return std::make_pair(ER->getElementType().getSingleStepDesugaredType(
      checkerContext.getASTContext()), "structType: " + type);
    }
    else if (type.find("enum ") != type.npos) {
        type = type.substr(type.find("enum ") + 5) + ",0";
        return std::make_pair(ER->getElementType().getSingleStepDesugaredType(
      checkerContext.getASTContext()), "enumType: " + type);
    }
    else if (type.find("union ") != type.npos) {
        type = type.substr(type.find("union ") + 6) + ",0";
        return std::make_pair(ER->getElementType().getSingleStepDesugaredType(
      checkerContext.getASTContext()), "unionType: " + type);
    }
// #ifdef DEBUG
//     llvm::outs() << "ElementRegion Type: " << type << "\n";
// #endif
    return std::make_pair(ER->getElementType().getSingleStepDesugaredType(
      checkerContext.getASTContext()), type);
}

qualType_str_pair handleSymbolicRegion(const SymbolicRegion *SR, PrimRangeSet range_set, CheckerContext &checkerContext) {
    MemRegion_str_tuple rs_tuple;
    QualType qt;

    rs_tuple = handleCommonSymbolExpr(SR->getSymbol(), range_set, checkerContext);
    return handleRegion(std::get<0>(rs_tuple), range_set, checkerContext, std::get<2>(rs_tuple));
}

MemRegion_str_tuple handleSymbolRegionValue(const SymbolRegionValue *SR, PrimRangeSet range_set, CheckerContext &checkerContext) {
    const MemRegion *R = SR->getRegion();
    std::string sym_type = SR->getType().getSingleStepDesugaredType(
          checkerContext.getASTContext()).getAsString();

    dumpRange(R, sym_type, range_set, checkerContext);
    return std::make_tuple(R, sym_type, SR->getType());
}

MemRegion_str_tuple handleSymbolDerived(const SymbolDerived *SD, PrimRangeSet range_set, CheckerContext &checkerContext) {
    const MemRegion *R = SD->getRegion();
    std::string sym_type = SD->getType().getSingleStepDesugaredType(
          checkerContext.getASTContext()).getAsString();

    dumpRange(R, sym_type, range_set, checkerContext);
    return std::make_tuple(R, sym_type, SD->getType());
}

MemRegion_str_tuple handleSymbolMetadata(const SymbolMetadata *SM, PrimRangeSet range_set, CheckerContext &checkerContext) {
    const MemRegion *R = SM->getRegion();
    std::string sym_type = SM->getType().getSingleStepDesugaredType(
          checkerContext.getASTContext()).getAsString();

    dumpRange(R, sym_type, range_set, checkerContext);
    return std::make_tuple(R, sym_type, SM->getType());
}

MemRegion_str_tuple handleSymbolExtent(const SymbolExtent *SE, PrimRangeSet range_set, CheckerContext &checkerContext) {
    const MemRegion *R = SE->getRegion();
    std::string sym_type = SE->getType().getSingleStepDesugaredType(
          checkerContext.getASTContext()).getAsString();

    dumpRange(R, sym_type, range_set, checkerContext);
    return std::make_tuple(R, sym_type, SE->getType());
}
MemRegion_str_tuple handleSymbolConjured(const SymbolConjured *SC, PrimRangeSet range_set, CheckerContext &checkerContext) {
    const MemRegion *R = NULL;
    std::string sym_type = "";
    QualType qual_type;

    sym_type = SC->getType()->getPointeeType().isNull()?
          SC->getType().getSingleStepDesugaredType(
      checkerContext.getASTContext()).getAsString():
          SC->getType()->getPointeeType().getSingleStepDesugaredType(
      checkerContext.getASTContext()).getAsString();
    qual_type = SC->getType()->getPointeeType().isNull()?
          SC->getType().getSingleStepDesugaredType(
      checkerContext.getASTContext()):
          SC->getType()->getPointeeType().getSingleStepDesugaredType(
      checkerContext.getASTContext());
    return std::make_tuple(R, sym_type, qual_type);
}

MemRegion_str_tuple handleSymbolCast(const SymbolCast *SCAST, PrimRangeSet range_set, CheckerContext &checkerContext) {
    return handleCommonSymbolExpr(SCAST->getOperand(), range_set, checkerContext);
}

MemRegion_str_tuple handleSymSymExpr(const SymSymExpr *SSE, PrimRangeSet range_set, CheckerContext &checkerContext) {
    const MemRegion *R = NULL;
    std::string sym_type = "";
    QualType qt;

    // if (range_set.isEmpty())
    //     return std::make_tuple(R, sym_type, qt);

    const SymExpr *lhs, *rhs;
    BinaryOperator::Opcode Op = SSE->getOpcode();
    lhs = SSE->getLHS();
    rhs = SSE->getRHS();
    // just handle the situation of that one side is constant
// #ifdef DEBUG
//     if (lhs)
//         llvm::outs() << "lhs: " << lhs << "\n";
//     if (rhs)
//         llvm::outs() << "rhs: " << rhs << "\n";
// #endif
    if (lhs) {
        RangeSet::Factory F;
        PrimRangeSet newRanges = F.getEmptySet();
        // todo: parse real newRanges
        handleCommonSymbolExpr(lhs, newRanges, checkerContext);
    }
    if (rhs) {
        RangeSet::Factory F;
        PrimRangeSet newRanges = F.getEmptySet();
        // todo: parse real newRanges
        handleCommonSymbolExpr(rhs, newRanges, checkerContext);
    }

    return std::make_tuple(R, sym_type, qt);
}

MemRegion_str_tuple handleSymIntExpr(const SymIntExpr *SIE, PrimRangeSet range_set, CheckerContext &checkerContext) {
    const MemRegion *R = NULL;
    std::string sym_type = "";
    QualType qt;
    // <from, to>
    std::set<std::pair<int, int>> new_range_set;

    if (range_set.isEmpty()) {
        const SymExpr *lhs = SIE->getLHS();
        if (lhs) {
            RangeSet::Factory F;
            PrimRangeSet newRanges = F.getEmptySet();
            handleCommonSymbolExpr(lhs, newRanges, checkerContext);
        }
        return std::make_tuple(R, sym_type, qt);
    }
        

    BinaryOperator::Opcode Op = SIE->getOpcode();
    const SymExpr *lhs = SIE->getLHS();
    const llvm::APSInt& rhs = SIE->getRHS();

    // if in cache
    std::string rhs_str = rhs.toString(10);
    std::set<std::pair<std::string, std::string>> range_set_tmp;
    cacheKey new_key;
    range_set_tmp.clear();
    for (auto i : range_set) {
        range_set_tmp.insert(std::make_pair(i.From().toString(10), i.To().toString(10)));
    }
    new_key = std::make_tuple(BinaryOperator::getOpcodeStr(Op), rhs_str, range_set_tmp);
    for (auto cacheItem : cacheSymIntExpr) {
        if (!((std::get<0>(new_key)).compare(std::get<0>(cacheItem.first))) && !((std::get<1>(new_key)).compare(std::get<1>(cacheItem.first))) && 
          std::get<2>(new_key) == std::get<2>(cacheItem.first)) {
            // hit the cache
#ifdef DEBUG
            llvm::outs() << "[+] Cache Hit\n";
#endif
            RangeSet::Factory F;
            PrimRangeSet newRanges = F.getEmptySet();
            for (auto range : cacheItem.second) {
                llvm::APSInt lower = llvm::APSInt(llvm::APInt(32, range.first, true), false);
                llvm::APSInt upper = llvm::APSInt(llvm::APInt(32, range.second, true), false);
                newRanges = F.add(newRanges, Range(lower, upper));
            }
            handleCommonSymbolExpr(lhs, newRanges, checkerContext);
            return std::make_tuple(R, sym_type, qt);
        }
    }


#ifdef DEBUG
    // just handle the situation of that one side is constant
    if (lhs)
        llvm::outs() << "lhs: " << lhs << "\n";
    llvm::outs() << "rhs: " << rhs << "\n";
#endif

    z3::context c;
    params p(c);
    p.set("mul2concat", true);
    tactic t = 
        with(tactic(c, "simplify"), p) &
        tactic(c, "solve-eqs") &
        tactic(c, "bit-blast") &
        tactic(c, "aig") &
        tactic(c, "sat");
    expr x = c.bv_const("x", 32);
    expr y = c.bv_const("y", 32);
    solver s = t.mk_solver();
    for (auto i : range_set) {
        int tmp_lower, tmp_upper;
        // prevent stoi out of range
        tmp_lower = i.From().toString(10).length() > 9 ?
          INT_MIN : std::stoi(i.From().toString(10));
        tmp_upper = i.To().toString(10).length() > 9 ?
          INT_MAX : std::stoi(i.To().toString(10));
#ifdef DEBUG
        llvm::outs().SetBufferSize(1);
        llvm::outs() << " From: " << i.From() << " To: " << i.To() << "\n";
#endif
        if (rhs.toString(10).length() > 9)
            continue;
        // 2分法 估计范围，需要从正值负值两方面入手
        // loop:
        // add constraint c把带求解的条件加上
        //  add x > 0
        //    x = 1
        //    add(x = x * 2)
        //  add x < 0
        //  add x == 0
        int tmp_x, new_lower, new_upper;
        //  zero
        tmp_x = 0;
        s.reset();
        addSymIntConstraint(s, x, y, Op, std::stoi(rhs.toString(10)), INT_MAX, tmp_lower);
        addSymIntConstraint(s, x, y, Op, std::stoi(rhs.toString(10)), tmp_upper, INT_MIN);
        s.add(x == tmp_x);
        if (s.check() == sat) {
            new_range_set.insert(std::make_pair(0, 0));
        }

#ifdef DEBUG        
        llvm::outs() << "Op: " << Op << "\n";
#endif
        // 对于位运算，为了得到小数值满足约束的解，1 ~ 15范围内求出所有满足的解
        if (Op == BO_And || Op == BO_Or || Op == BO_Xor || Op == BO_Shl || Op == BO_Shr) {
            tmp_x = 1;
            while (tmp_x <= 15) {
                if (tmp_x == 0) {
                    // case 0 handled in previous step
                    tmp_x++;
                    continue;
                }
                s.reset();
                addSymIntConstraint(s, x, y, Op, std::stoi(rhs.toString(10)), INT_MAX, tmp_lower);
                addSymIntConstraint(s, x, y, Op, std::stoi(rhs.toString(10)), tmp_upper, INT_MIN);
                s.add(x == tmp_x);
                if (s.check() == sat) {
#ifdef DEBUG
                    llvm::outs() << "BO Sat: " << tmp_x << "\n";
#endif
                    new_range_set.insert(std::make_pair(tmp_x, tmp_x));
                }
                tmp_x++;
            }
        }

        // positve
        new_lower = 0;
        tmp_x = 1;
        while (1) {
            s.reset();
            addSymIntConstraint(s, x, y, Op, std::stoi(rhs.toString(10)), INT_MAX, tmp_lower);
            addSymIntConstraint(s, x, y, Op, std::stoi(rhs.toString(10)), tmp_upper, INT_MIN);
            s.add(x >= tmp_x);
            if (s.check() == sat) {new_lower = tmp_x; break;}
            // 2^30 = 1073741824
            if (tmp_x == 1073741824) break;
            tmp_x *= 2;
        }
        if (new_lower) {
            tmp_x = new_lower;
            while (1) {
                s.reset();
                addSymIntConstraint(s, x, y, Op, std::stoi(rhs.toString(10)), INT_MAX, tmp_lower);
                addSymIntConstraint(s, x, y, Op, std::stoi(rhs.toString(10)), tmp_upper, INT_MIN);
                s.add(x >= (tmp_x*2));
                if (s.check() != sat || tmp_x == 1073741824 / 2) {new_upper = tmp_x; break;}
                tmp_x *= 2;
            }
#ifdef DEBUG
            llvm::outs().SetBufferSize(1);
            llvm::outs() << "lower: " << new_lower << " upper: " << new_upper << "\n";
#endif
            new_range_set.insert(std::make_pair(new_lower, new_upper));
        }
        // negative
        new_upper = 0;
        tmp_x = -1;
        while (1) {
            s.reset();
            addSymIntConstraint(s, x, y, Op, std::stoi(rhs.toString(10)), INT_MAX, tmp_lower);
            addSymIntConstraint(s, x, y, Op, std::stoi(rhs.toString(10)), tmp_upper, INT_MIN);
            s.add(x <= tmp_x);
            if (s.check() == sat) {new_upper = tmp_x; break;}
            // 2^30 = 1073741824
            if (tmp_x == -1073741824) break;
            tmp_x *= 2;
        }
        if (new_upper) {
            tmp_x = new_upper;
            while (1) {
                s.reset();
                addSymIntConstraint(s, x, y, Op, std::stoi(rhs.toString(10)), INT_MAX, tmp_lower);
                addSymIntConstraint(s, x, y, Op, std::stoi(rhs.toString(10)), tmp_upper, INT_MIN);
                s.add(x <= (tmp_x*2));
                if (s.check() != sat || tmp_x == -1073741824 / 2) {new_lower = tmp_x; break;}
                tmp_x *= 2;
            }
#ifdef DEBUG
            llvm::outs() << "lower: " << new_lower << " upper: " << new_upper << "\n";
#endif
            new_range_set.insert(std::make_pair(new_lower, new_upper));
        }
        if (new_range_set.size() > 0) {
            RangeSet::Factory F;
            PrimRangeSet newRanges = F.getEmptySet();
            for (auto range : new_range_set) {
                llvm::APSInt lower = llvm::APSInt(llvm::APInt(32, range.first, true), false);
                llvm::APSInt upper = llvm::APSInt(llvm::APInt(32, range.second, true), false);
                newRanges = F.add(newRanges, Range(lower, upper));

                // add to cache
                if (cacheSymIntExpr.count(new_key) == 0) {
                    std::set<std::pair<int, int>> tmp_set = {range};
                    cacheSymIntExpr.insert(std::make_pair(new_key, tmp_set));
                }
                else
                    cacheSymIntExpr[new_key].insert(range);
            }
#ifdef DEBUG
            llvm::outs() << "[+] Cache Insert\n";
            for (auto i : newRanges) {
                llvm::outs().SetBufferSize(1);
                llvm::outs() << " From: " << i.From().toString(10) << " To: " << i.To().toString(10) << "\n";
            }
#endif
            handleCommonSymbolExpr(lhs, newRanges, checkerContext);
        }
#ifdef DEBUG
        else
            llvm::outs() << "[!] Z3 Constraint UnSat.\n";
#endif
    }

    return std::make_tuple(R, sym_type, qt);
}

MemRegion_str_tuple handleIntSymExpr(const IntSymExpr *ISE, PrimRangeSet range_set, CheckerContext &checkerContext) {
    const MemRegion *R = NULL;
    std::string sym_type = "";
    QualType qt;

    // if (range_set.isEmpty())
    //     return std::make_tuple(R, sym_type, qt);

    BinaryOperator::Opcode Op = ISE->getOpcode();
    const llvm::APSInt& lhs = ISE->getLHS();
    const SymExpr *rhs = ISE->getRHS();
    // just handle the situation of that one side is constant
#ifdef DEBUG
    llvm::outs() << "lhs: " << lhs << "\n";
    if (rhs)
        llvm::outs() << "rhs: " << rhs << "\n";
#endif
    if (rhs) {
        RangeSet::Factory F;
        PrimRangeSet newRanges = F.getEmptySet();
        // todo: parse real newRanges
        handleCommonSymbolExpr(rhs, newRanges, checkerContext);
    }

    return std::make_tuple(R, sym_type, qt);
}

void dumpRange(const MemRegion *R, std::string sym_type, PrimRangeSet range_set, CheckerContext &checkerContext) {
    qualType_str_pair qs_pair;
    std::string value_str="", value_str_tmp="";
    QualType qt;
    int comma_cnt;

    if (R) {
        qs_pair = handleRegion(R, range_set, checkerContext, qt);
        // llvm::outs() << "qs_pair.second : " << qs_pair.second << "\n";
        if (qs_pair.second.find("::") != qs_pair.second.npos)
            value_str_tmp = qs_pair.second.substr(qs_pair.second.rfind("::") + 2);
        else
            value_str_tmp = qs_pair.second;
        // llvm::outs() << "value_str_tmp : " << value_str_tmp << "\n";
        comma_cnt = count(value_str_tmp.begin(), value_str_tmp.end(), ',');
        if (comma_cnt == 2 || comma_cnt == 0) {
            if (value_str_tmp.find("varType") == 0) {
                value_str = "var." + value_str_tmp.substr(value_str_tmp.find("varName: ") + 9);
            }
            else if (value_str_tmp.find("structType: ") == 0) {
                if (!value_str_tmp.substr(value_str_tmp.find(",0")).compare(",0"))
                    return;
                value_str = "struct." + value_str_tmp.substr(value_str_tmp.find("structType: ") + 12);
            }
            else if (value_str_tmp.find("struct ") == 0) {
                if (!value_str_tmp.substr(value_str_tmp.find(",0")).compare(",0"))
                    return;
                value_str = "struct." + value_str_tmp.substr(value_str_tmp.find("struct ") + 7);
            }
            else if (value_str_tmp.find("enumType: ") == 0) {
                if (!value_str_tmp.substr(value_str_tmp.find(",0")).compare(",0"))
                    return;
                value_str = "enum." + value_str_tmp.substr(value_str_tmp.find("enumType: ") + 10);
            }
            else if (value_str_tmp.find("unionType: ") == 0) {
                if (!value_str_tmp.substr(value_str_tmp.find(",0")).compare(",0"))
                    return;
                value_str = "union." + value_str_tmp.substr(value_str_tmp.find("unionType: ") + 11);
            }
            else if (value_str_tmp.find("union ") == 0) {
                if (!value_str_tmp.substr(value_str_tmp.find(",0")).compare(",0"))
                    return;
                value_str = "union." + value_str_tmp.substr(value_str_tmp.find("union ") + 6);
            }
        } else if (comma_cnt != 1) {
            llvm::outs() << "[!] Something error in : " << qs_pair.second << "\n";
        }
    }
#ifdef DEBUG
    llvm::outs() << " sym_dump: " << value_str << "\n" << sv_str_set.size() << "\n";
    if ((sv_str_set.count(value_str) != 0 && value_str.compare("")) || value_str.compare("")) {
#else
    // if (sv_str_set.count(value_str) != 0 && value_str.compare("")) {
    std::string st_name;
    if (value_str.find_first_of("struct.") == value_str.npos) {
        st_name = value_str;
    }
    if (value_str.find_first_of("struct.") != value_str.npos && value_str.find_first_of(",") != value_str.npos) {
        st_name = value_str.substr(value_str.find_first_of("struct.") + 7, value_str.find_first_of(",") - value_str.find_first_of("struct.") - 7);
    }
    if (value_str.compare("") != 0 && sv_struct_str_set.count(st_name) != 0) {
#endif
        if (sv_set_in_one_check.count(value_str)==0)
            sv_set_in_one_check.insert(value_str);
        // llvm::outs() << "[+] is_match!\n";
        std::string out_str;
        llvm::raw_string_ostream ros(out_str);
        ros << "sym_name: " << value_str << " " << sym_type << "    sym_ranges :  ";
        // print ranges
        bool isFirst = true;
        ros << "{ ";
        for (auto i = range_set.begin(), e = range_set.end(); i != e; ++i) {
            if (isFirst)
                isFirst = false;
            else
                ros << ", ";
            ros << '[' << i->From().toString(10) << ", " << i->To().toString(10)
              << ']';
        }
        ros << " }\n";
        out_str = ros.str();
        if (out_str_set.count(out_str) == 0) {
            llvm::outs() << out_str;
            out_str_set.insert(out_str);
        }
    }
    return;
}

MemRegion_str_tuple handleCommonSymbolExpr(const SymbolRef sym, PrimRangeSet range_set, CheckerContext &checkerContext) {
    const MemRegion *R = NULL;
    std::string sym_type = "";
    QualType qt;

    if (const SymbolRegionValue *sr = dyn_cast<SymbolRegionValue>(sym)) {
        return handleSymbolRegionValue(sr, range_set, checkerContext);
    }
    else if (const SymbolDerived *sd = dyn_cast<SymbolDerived>(sym)) {
        return handleSymbolDerived(sd, range_set, checkerContext);
    }
    else if (const SymbolMetadata *sm = dyn_cast<SymbolMetadata>(sym)) {
        return handleSymbolMetadata(sm, range_set, checkerContext);
    }
    else if (const SymbolExtent *se = dyn_cast<SymbolExtent>(sym)) {
        return handleSymbolExtent(se, range_set, checkerContext);
    }
    else if (const SymbolConjured *sc = dyn_cast<SymbolConjured>(sym)) {
        return handleSymbolConjured(sc, range_set, checkerContext);
    }
    else if (const SymbolCast *scast = dyn_cast<SymbolCast>(sym)) {
        return handleSymbolCast(scast, range_set, checkerContext);
    }
    else if (const SymSymExpr * sse = dyn_cast<SymSymExpr>(sym)) {
        return handleSymSymExpr(sse, range_set, checkerContext);
    }
    else if (const SymIntExpr * sie = dyn_cast<SymIntExpr>(sym)) {
        return handleSymIntExpr(sie, range_set, checkerContext);
    }
    else if (const IntSymExpr *ise = dyn_cast<IntSymExpr>(sym)) {
        return handleIntSymExpr(ise, range_set, checkerContext);
    }
    // ...
#ifdef DEBUG
    else {
        llvm::outs() << "[!] unsupported type ConstraintRangeTy\n";
    }
#endif
    return std::make_tuple(R, sym_type, qt);
}

void dumpStateRange(ProgramStateRef state, CheckerContext &checkerContext) {
#ifdef DEBUG
    state->print(llvm::outs(), "  ", " |sep| ", checkerContext.getLocationContext());
    llvm::outs() << "\n ------------------------------- \n";
#endif
    ConstraintRangeTy Ranges = state->get<ConstraintRange>();
    if (Ranges.isEmpty()) {
// #ifdef DEBUG
//         llvm::outs() << "[!] Ranges are empty.\n";
// #endif
        return;
    }

    // ConstraintRangeTy ---> using ConstraintRangeTy = llvm::ImmutableMap<SymbolRef, RangeSet>;
    for (ConstraintRangeTy::iterator I = Ranges.begin(), E = Ranges.end();
      I != E; ++I) {
#ifdef DEBUG
        llvm::outs() << "current: " << I.getKey() << "\n";
#endif

        RangeSet RangeSet_tmp = I.getData();
        handleCommonSymbolExpr(I.getKey(), RangeSet_tmp.getRanges(), checkerContext);
    }
}

void SymStateVariableValueAnalysisChecker::checkBranchCondition(const Stmt *Condition, 
                    CheckerContext &C) const {
    char code_line[240];
    const char *loc_char;
    // bool is_match;
#ifdef DEBUG
    llvm::outs() << "Current Dumped Condition: \n";
    Condition->dump(llvm::outs());
#endif

    SourceLocation Loc = Condition->getBeginLoc();

#ifdef DEBUG
    llvm::outs() << "[+] Loc: " << C.getSourceManager().getSpellingLineNumber(Loc) << " "
               << Condition->getStmtClassName() << "\n";
    loc_char = C.getSourceManager().getCharacterData(Loc);
    if (std::strlen(loc_char)) {
        std::strncpy(code_line, loc_char, 200);
        llvm::outs() << code_line << "\n";
    }
#endif

    // const Expr *E = cast<Expr>(Condition);
    // if (!E)
    //     llvm::outs() << "\n[!] Condtion cast to Expr error!\n";

    // if (const BinaryOperator *B = dyn_cast<BinaryOperator>(Condition)) {
    //     llvm::outs() << "[info] BinaryOperator Condition Case\n";
    // } else if (const UnaryOperator *U = dyn_cast<UnaryOperator>(Condition)) {
    //     llvm::outs() << "[info] UnaryOperator Condition Case\n";
    // } else if (const ImplicitCastExpr *IE =
    //                dyn_cast<ImplicitCastExpr>(Condition)) {
    //     llvm::outs() << "[info] ImplicitCastExpr Condition Case\n";
    // } else {
    //     llvm::outs() << "[info] Other Condition Case\n";
    // }
    // type_vector_mutex.lock();
    // is_match = walkExpr(E, C);
    // type_vector_mutex.unlock();
    // if (!is_match)
    //     return;

    SVal cond_sval = C.getSVal(Condition);

    Optional<DefinedSVal> SV = cond_sval.getAs<DefinedSVal>();
    if (!SV) {
#ifdef DEBUG
        llvm::outs() << "\n[!] SV error!\n";
#endif
        return;
    }
    // llvm::outs() << "checkBranchCondition START\n";
    sv_set_in_one_check.clear();
    ProgramStateRef state = C.getState();
    ConstraintManager &CM = C.getConstraintManager();
    ProgramStateRef stateTrue, stateFalse;
    std::tie(stateTrue, stateFalse) = CM.assumeDual(state, *SV);

    if (stateTrue) {
#ifdef DEBUG
        llvm::outs() << "[+] StateTrue Dump: \n";
#endif
        dumpStateRange(stateTrue, C);
    }
    if (stateFalse) {
#ifdef DEBUG
        llvm::outs() << "[+] StateFalse Dump: \n";
#endif
        dumpStateRange(stateFalse, C);
    }
    if (sv_set_in_all_checks.count(sv_set_in_one_check) == 0)
        sv_set_in_all_checks.insert(sv_set_in_one_check);
    // llvm::outs() << "checkBranchCondition END\n";
    return;
}

void ento::registerSymStateVariableValueAnalysisChecker(CheckerManager &mgr) {
    mgr.registerChecker<SymStateVariableValueAnalysisChecker>();
}

bool ento::shouldRegisterSymStateVariableValueAnalysisChecker(const CheckerManager &mgr) {
    return true;
}


