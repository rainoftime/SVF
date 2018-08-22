/*
 * GlobalInitializationAnalysis.h
 *
 */
#ifndef GLOBALINITIALIZATIONANALYSIS_H_
#define GLOBALINITIALIZATIONANALYSIS_H_

#include "Util/AnalysisUtil.h"
#include <unordered_map>
#include <unordered_set>
using namespace llvm;
class GlobalInitializationAnalysis {
    std::unordered_map<Value*, std::unordered_set<Value*>> global_values_cache;
    Module* m_mod;

public:
    GlobalInitializationAnalysis(Module& M) {
        m_mod = &M;
    }

    void computeGlobalStorage(Module &M);
    int addressTakenFuncStoreIndexBase(Function *func);

};


#endif /* GLOBALINITIALIZATIONANALYSIS_H_ */
