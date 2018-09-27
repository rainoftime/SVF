#ifndef FUNCTIONPOINTERANALYSIS_H_
#define FUNCTIONPOINTERANALYSIS_H_

#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/CallGraph.h"
#include "Util/AnalysisUtil.h"

using namespace llvm;


class FunctionPointerAnalysis : public ModulePass {

public:
    static char ID;


    FunctionPointerAnalysis(): ModulePass(ID) {
        num_implemented_funcs = 0;
        num_address_taken_funcs = 0;
        num_funcs_with_indirect_calls = 0;
        num_funcs_with_fptr_para = 0;
    }

    virtual ~FunctionPointerAnalysis() {

    }

    void getAnalysisUsage(AnalysisUsage &) const;
    bool runOnModule(Module &);

public:
    void buildCG(Module* M);

    /*
     * Analyze which functions are ''critical to the indirect calls"

    */
    void impactAnalysis();

private:
    //Module* M;
    CallGraph* CG = nullptr;
    unsigned num_implemented_funcs;
    unsigned num_address_taken_funcs;
    unsigned num_funcs_with_indirect_calls;
    unsigned num_funcs_with_fptr_para;

    std::map<Function*, std::map<Value*, Function*>> function_pointer_result;

};


#endif /* FUNCTIONPOINTERANALYSIS_H_ */
