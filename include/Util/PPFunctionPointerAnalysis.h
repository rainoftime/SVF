#ifndef PPFUNCTIONPOINTERANALYSIS_H_
#define PPFUNCTIONPOINTERANALYSIS_H_
#include <llvm/IR/Value.h>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <map>
#include <algorithm>
#include "Util/CPPUtil.h"
using namespace llvm;

class PPFunctionPointerAnalysis {
private:
    //CallSite m_cs;
    int verbose_lvl = 0;
    unsigned analyze_inst_count;

public:
    PPFunctionPointerAnalysis();

    ~PPFunctionPointerAnalysis();

    std::unordered_set<Function*> callsite_targets;

    // process the function pointer
    void run(Function* func, CallSite CS);
    void processFuncPtr(Value* ftpr);
    void processFuncPtrLoadInst(LoadInst* load_inst);
    void processFuncPtrArgFuncptr(Argument* argument);
    void processFuncPtrPhiNode(PHINode* phi_node);
    void processFuncPtrCallInst(CallInst* call_inst);
    void processFuncPtrGEPInst(GetElementPtrInst* get_inst);
    bool processFuncPtrCmpGEPInst (GetElementPtrInst* gep_left, GetElementPtrInst* gep_right);

protected:
    bool cmpValue(Value* L, Value* R);

};



#endif /* PPFUNCTIONPOINTERANALYSIS_H_ */
