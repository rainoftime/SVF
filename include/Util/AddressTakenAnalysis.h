/*
 * AddressTakenAnalysis.h
 *
 *
 *      Author: rainoftime
 */
#ifndef ADDRESSTAKENANALYSIS_H_
#define ADDRESSTAKENANALYSIS_H_
#include "Util/AnalysisUtil.h"
#include <unordered_set>
using namespace llvm;

class AddressTakenAnalysis {
    // address taken analysis for functions
    Module* M;
    int callees_num_limit;
    bool enable_field_prunning;
    uint64_t default_ptrsz = 0;
    std::unordered_set<Function*> address_taken_functions;

public:
    AddressTakenAnalysis(Module& _M) : callees_num_limit(10), enable_field_prunning(true) {
        M = &_M;
        default_ptrsz = M->getDataLayout()->getPointerSizeInBits();
        for (Module::iterator FI = M->begin(), FE = M->end(); FI != FE; ++FI) {
            if (isAddressTaken(FI)) {
                address_taken_functions.insert(FI);
            }
        }
    }
    ~AddressTakenAnalysis() {
        address_taken_functions.clear();
    }
    uint64_t getTypeSizeInBits(Type *Ty) const;
    unsigned getGepConstantOffset(GetElementPtrInst* gep);
    int addressTakenFuncStoreIndexBase(Function *func);
    bool isAddressTaken(Value *V);
    bool isTypeCompatible(Type* t1, Type* t2);
    bool isCallsiteFunctionStrictCompatible(CallSite callsite, Function* func);
    void guessCalleesForIndCallSite(CallSite callsite, std::unordered_set<Function*> &result);
    void buildCG();
};

#endif /* ADDRESSTAKENANALYSIS_H_ */
