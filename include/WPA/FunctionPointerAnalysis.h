#ifndef FUNCTIONPOINTERANALYSIS_H_
#define FUNCTIONPOINTERANALYSIS_H_

#include "Util/AnalysisUtil.h"

using namespace llvm;


class FunctionPointerAnalysis {
    Module* M;

public:
    FunctionPointerAnalysis(Module& _M) {
        M = &_M;
    }

    void buildCG();

};


#endif /* FUNCTIONPOINTERANALYSIS_H_ */
