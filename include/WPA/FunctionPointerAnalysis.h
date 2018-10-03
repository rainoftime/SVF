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

    }

    virtual ~FunctionPointerAnalysis() {

    }

    void getAnalysisUsage(AnalysisUsage &) const;
    bool runOnModule(Module &);
    void computeGlobalStorage(Module& M);
    void computeFuncWithIndCall(Module& M);
    void computeAddressTakenFuncs(Module& M);
    void computeFuncWithFptrParaOrRet(Module& M);
    void collectTypes(Module& M);
    void printStat();

    void collectFptrAccess(Module& M);


public:
    void buildCG(Module& M);

    /*
     * Analyze which functions are ''critical to the indirect calls"

    */
    void impactAnalysis(Module& M);

private:

    CallGraph* llvm_cg = nullptr;

    // Maybe I need the result of Andersen's analsyis
    PointerAnalysis* _pta = nullptr;  ///<  pointer analysis to be executed.
    PTACallGraph* svf_cg = nullptr;

    // implemented functions
    unsigned num_implemented_funcs = 0;

    // functions having their addresses taken
    unsigned num_address_taken_funcs = 0;
    std::set<Function*> address_taken_functions;
    std::set<Function*> address_taken_happen_at;

    // functions containing indirect call sites
    unsigned num_funcs_with_indirect_calls = 0;
    std::set<Function*> funcs_with_indirect_calls;

    // functions whose parameters and returns include fptr
    unsigned num_funcs_with_fptr_para_or_ret = 0;
    std::set<Function*> funcs_with_fptr_para_or_ret;

    unsigned num_funcs_impact_fptr = 0;
    std::set<Function*> impacted_by_fptr_functions;

    // caches
    std::map<Value*, std::set<Value*>> global_values_cache;
    std::map<const llvm::StructType*, const llvm::StructType *> struct_types_cache;
    std::map<Value*, const llvm::Type *> function_types_cache;


    std::map<Function*, std::map<Value*, Function*>> function_pointer_result;

};


#endif /* FUNCTIONPOINTERANALYSIS_H_ */
