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
#include "clang/AST/RecordLayout.h"
#include <sstream>
#include <iostream>
#include <fstream>
#include <z3++.h>

// #define DEBUG

using namespace clang;
using namespace ento;
using namespace std;


std::set<std::string> sv_name_set;
std::set<std::string> sv_struct_set;

namespace {
class SymStateVariableFieldNameAnalysisChecker : public Checker<check::ASTDecl<RecordDecl>> {
//   mutable std::unique_ptr<BuiltinBug> BT;
//   void reportBug(const char *Msg, ProgramStateRef StateZero, CheckerContext &C,
//                  std::unique_ptr<BugReporterVisitor> Visitor = nullptr) const;
public:
    SymStateVariableFieldNameAnalysisChecker();
    void checkASTDecl(const RecordDecl *RD, AnalysisManager& Mgr,
                    BugReporter &BR) const;
};
} // end anonymous namespace


SymStateVariableFieldNameAnalysisChecker::SymStateVariableFieldNameAnalysisChecker(void) {
    ifstream sv_file;
    std::string line;
    std::string struct_name;
    std::set<std::string> sv_name_set_consistent;
    std::set<std::string> sv_struct_set_consistent;

    sv_file.open("/tmp/sv_list.txt");
    if (!sv_file.is_open()) {
        // cout << "Error opening ioctl_top_function_file";
        llvm::outs() << "[!] open /tmp/sv_list.txt error!\n";
        exit(1);
    }
    sv_name_set_consistent.clear();
    sv_struct_set_consistent.clear();
    while (!sv_file.eof()) {
        getline(sv_file, line);
        // llvm::outs() << "line: " << line << "\n";
        if (line.find_first_of("struct.") != line.npos && line.find_first_of(",") != line.npos) {
            struct_name = line.substr(line.find_first_of("struct.") + 7, line.find_first_of(",") - line.find_first_of("struct.") - 7);
            if (sv_struct_set_consistent.count(struct_name) == 0) {
                sv_struct_set_consistent.insert(struct_name);
            }
        }
        // llvm::outs() << "struct_name: " << struct_name << "\n";
        sv_name_set_consistent.insert(line);
    }
    sv_file.close();
    sv_name_set = sv_name_set_consistent;
    sv_struct_set = sv_struct_set_consistent;
#ifdef DEBUG
    llvm::outs() << "[+] sv_str initialized\n";
#endif
    return;
}

void SymStateVariableFieldNameAnalysisChecker::checkASTDecl(const RecordDecl *RD, AnalysisManager& Mgr,
                    BugReporter &BR) const {
    std::string name, type;
    std::string field_name, field_type;
    std::string value_str = "";
    bool findField = false;
    int field_no = -1;

    if (RD == nullptr) return;    
    name = RD->getNameAsString();
    if (name.compare("") == 0)
        return;
    const RecordDecl *RDDef = RD->getDefinition(); 
    // If not a definition, do nothing
    if (RDDef != RD) return;

    // llvm::outs() << (*RD) << "\n";
    const auto &recordLayout = Mgr.getASTContext().getASTRecordLayout(RD);
    // llvm::outs() << "checkASTDecl!\n";
    // if (1) {
    if (sv_struct_set.count(name) != 0) {
        // llvm::outs() << "\n[+] DeclName: " << name << "\n";
        field_no = -1;
        unsigned field_no_test = 0;
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
            value_str = "";
            field_name = I->getNameAsString();
            field_type = I->getType().getSingleStepDesugaredType(
                Mgr.getASTContext()).getAsString();
            value_str = "struct." + name + ",0," + std::to_string(field_no);
            if (sv_name_set.count(value_str) != 0) {
                llvm::outs() << "[+] Sv Name: " << value_str << " FieldName: " << field_name << " FieldType: " << field_type << " \n";
                llvm::outs() << "getFieldOffset: " << recordLayout.getFieldOffset(field_no_test) << "\n";
            }
            field_no_test++;
        }
    }
    return;
}

void ento::registerSymStateVariableFieldNameAnalysisChecker(CheckerManager &mgr) {
  mgr.registerChecker<SymStateVariableFieldNameAnalysisChecker>();
}

bool ento::shouldRegisterSymStateVariableFieldNameAnalysisChecker(const CheckerManager &mgr) {
  return true;
}


