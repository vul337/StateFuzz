#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include <fstream>
#include <regex>
#include "Common.h"

// #define DEBUG

size_t funcHash(Function *F, bool withName)
{

    hash<string> str_hash;
    string output;

#ifdef HASH_SOURCE_INFO
    DISubprogram *SP = F->getSubprogram();

    if (SP)
    {
        output = SP->getFilename();
        output = output + to_string(uint_hash(SP->getLine()));
    }
    else
    {
#endif
        string sig;
        raw_string_ostream rso(sig);
        Type *FTy = F->getFunctionType();
        FTy->print(rso);
        output = rso.str();

        regex pattern("(\\.[0-9]+)([\\*|,|\\)|$])"); 
#ifdef DEBUG
        errs() << "before regex_replace: " << output << "\n";
#endif
        output = regex_replace(output, pattern, "$2");

        if (withName)
            output += F->getName();
#ifdef HASH_SOURCE_INFO
    }
#endif
    string::iterator end_pos = remove(output.begin(),
                                      output.end(), ' ');
    output.erase(end_pos, output.end());
#ifdef DEBUG
        errs() << "return funcHash: " << output << " -- " << str_hash(output) << "\n";
#endif
    return str_hash(output);
}

size_t callHash(CallInst *CI)
{

    // CallSite CS(CI);
    auto *CB = dyn_cast<CallBase>(CI);
    Function *CF = CB->getCalledFunction();

    if (CF)
        return funcHash(CF);
    else
    {
        hash<string> str_hash;
        string sig;
        raw_string_ostream rso(sig);
        Type *FTy = CB->getFunctionType();
        FTy->print(rso);
        string strip_str = rso.str();
        regex pattern("(\\.[0-9]+)([\\*|,|\\)|$])"); 
#ifdef DEBUG
        errs() << "before regex_replace: " << strip_str << "\n";
#endif
        strip_str = regex_replace(strip_str, pattern, "$2");
        string::iterator end_pos = remove(strip_str.begin(),
                                          strip_str.end(), ' ');
        strip_str.erase(end_pos, strip_str.end());
#ifdef DEBUG
        errs() << "return callHash: " << strip_str << " -- " << str_hash(strip_str) << "\n";
#endif
        return str_hash(strip_str);
    }
}

size_t typeHash(Type *Ty)
{
    hash<string> str_hash;
    string sig;

    raw_string_ostream rso(sig);
    Ty->print(rso);
    string ty_str = rso.str();

    regex pattern("(\\.[0-9]+)([\\*|,|\\)|$])"); 
#ifdef DEBUG
        errs() << "before regex_replace: " << ty_str << "\n";
#endif
    ty_str = regex_replace(ty_str, pattern, "$2");

    string::iterator end_pos = remove(ty_str.begin(), ty_str.end(), ' ');
    ty_str.erase(end_pos, ty_str.end());
#ifdef DEBUG
        errs() << "return typeHash: " << ty_str << " -- " << str_hash(ty_str) << "\n";
#endif
    return str_hash(ty_str);
}

size_t hashIdxHash(size_t Hs, int Idx)
{
    hash<string> str_hash;
    return Hs + str_hash(to_string(Idx));
}

size_t typeIdxHash(Type *Ty, int Idx)
{
    return hashIdxHash(typeHash(Ty), Idx);
}