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
    void collectTypes(Module& M);

public:
    void buildCG(Module& M);

    /*
     * Analyze which functions are ''critical to the indirect calls"

    */
    void impactAnalysis(Module& M);

private:

    CallGraph* CG = nullptr;
    unsigned num_implemented_funcs = 0;
    unsigned num_address_taken_funcs = 0;
    unsigned num_funcs_with_indirect_calls = 0;
    unsigned num_funcs_with_fptr_para = 0;

    std::map<Value*, std::set<Value*>> global_values_cache;
    std::map<const llvm::StructType*, const llvm::StructType *> struct_types_cache;
    std::map<Value*, const llvm::Type *> function_types_cache;

    std::set<Function*> address_taken_functions;
    std::set<Function*> funcs_with_indirect_calls;
    std::set<Function*> impacted_by_fptr_functions;
    std::map<Function*, std::map<Value*, Function*>> function_pointer_result;

};


#endif /* FUNCTIONPOINTERANALYSIS_H_ */
