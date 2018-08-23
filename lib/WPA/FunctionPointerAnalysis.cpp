#include "WPA/FunctionPointerAnalysis.h"
#include "Util/AddressTakenAnalysis.h"
#include "Util/PPFunctionPointerAnalysis.h"
using namespace llvm;

void FunctionPointerAnalysis::buildCG() {
    int CG_BUCKET_NUMBER = 11;
    int cg_bucket[11] = { 0 };
    int cg_bucket_steps[11] = { 0, 1, 2, 3, 4, 5, 6, 7, 10, 30, 100 };

    for (Function& f : *M) {
        if (f.isDeclaration() || f.isIntrinsic()) {
            continue;
        }
        for (BasicBlock& bb : f) {
            for (Instruction& inst : bb) {
                CallSite cs(&inst);
                if (cs.isCall() || cs.isInvoke()) {
                    Function *callee = cs.getCalledFunction();
                    if (!callee) {
                        if (cppUtil::isVirtualCallSite(cs) || isa<InlineAsm>(cs.getCalledValue())) {
                            continue;
                        } else {
                            std::unordered_set<Function*> result;

                            // First, use PPFunctionPointerAnalysis
                            PPFunctionPointerAnalysis* pfa = new PPFunctionPointerAnalysis();
                            pfa->run(&f, cs);
                            if (pfa->callsite_targets.size() >= 1) {
                                outs() << "PPFptrAna finds the following functions\n";
                                for (Function* func : pfa->callsite_targets) {
                                    outs() << func->getName() << "\n";
                                    result.insert(func);
                                }
                            } else {
                                // First, use AddressTakenFunctionAnalysis
                                AddressTakenAnalysis* ata = new AddressTakenAnalysis(*M);
                                ata->guessCalleesForIndCallSite(cs, result);
                            }

                            int i;
                            int cg_resolve_size = result.size();
                            for (i = 0; i < CG_BUCKET_NUMBER - 1; i++) {
                                if (cg_resolve_size < cg_bucket_steps[i + 1]) {
                                    cg_bucket[i]++;
                                    break;
                                }
                            }
                            if (i == CG_BUCKET_NUMBER - 1) {
                                cg_bucket[i]++;
                            }
                        }
                    }
               }
           }
       }
    }

    llvm::outs() << "--------------FunctionPointerAnalysis CG Begin------------------\n";
    outs() << "\n";
    int i;
    for (i = 0; i < CG_BUCKET_NUMBER - 1; i++) {
        if (cg_bucket_steps[i] == cg_bucket_steps[i + 1] - 1)
            outs() << "\t" << cg_bucket_steps[i] << ":\t\t";
        else
            outs() << "\t" << cg_bucket_steps[i] << " - " << cg_bucket_steps[i + 1] - 1 << ": \t\t";
        outs() << cg_bucket[i] << "\n";
    }
    outs() << "\t>" << cg_bucket_steps[i] << ": \t\t";
    outs() << cg_bucket[i] << "\n";
    outs() << "\n";
    llvm::outs() << "-------------FunctionPointerAnalysis CG End------------------\n";

}
