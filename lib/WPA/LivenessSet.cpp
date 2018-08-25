#include "llvm/Support/raw_ostream.h"

#include "WPA/LivenessSet.h"

void LivenessSet::dump() const {
    bool first = true;
    for (auto N : s) {
        if (!first)
            errs() << ", ";
        first = false;
        errs() << N->getName();
    }
    errs() << "\n";
}
