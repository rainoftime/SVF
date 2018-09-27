#include "WPA/FunctionPointerAnalysis.h"
#include "Util/AddressTakenAnalysis.h"
#include "Util/PPFunctionPointerAnalysis.h"
using namespace llvm;


char FunctionPointerAnalysis::ID = 0;

static RegisterPass<FunctionPointerAnalysis> FunctionPointerAnalysis("fpa",
        "Whole Program Function Pointer Analysis Pass");

void  FunctionPointerAnalysis::getAnalysisUsage(AnalysisUsage &AU) const {
    AU.setPreservesAll();
    AU.addRequired<CallGraphWrapperPass>();
}


bool FunctionPointerAnalysis::runOnModule(Module& M) {
    CallGraphWrapperPass *CGPass =
      getAnalysisIfAvailable<CallGraphWrapperPass>();

    CG = CGPass ? &CGPass->getCallGraph() : nullptr;
    if (CG == nullptr) {
        errs() << "FunctionPointerAnalysis: Initialize CG failed\n";
    } else {
        outs() << "CG initialized!\n";
    }

    outs() << "Running Function Pointer Analysis\n";

    computeAddressTakenFuncs(M);

    computeFuncWithIndCall(M);

    computeGlobalStorage(M);



    return false;
}

void FunctionPointerAnalysis::computeAddressTakenFuncs(Module& M) {
    AddressTakenAnalysis* ata = new AddressTakenAnalysis(M);
    ata->getAddressTakenFunctions();
    for (Function* func : *(ata->getAddressTakenFunctions())) {
        address_taken_functions.insert(func);
    }
}

void FunctionPointerAnalysis::computeFuncWithIndCall(Module& M) {
    for (Function& func : M) {
        if (func.isDeclaration() || func.isIntrinsic()) {
            continue;
        }
        bool contain_indcall = false;
        for (BasicBlock& bb : func) {
            for (Instruction& inst : bb) {
                CallSite cs(&inst);
                if (cs.isCall() || cs.isInvoke()) {
                    Function *callee = cs.getCalledFunction();
                    // indirect call
                    if (!callee) {
                        if (isa<InlineAsm>(cs.getCalledValue())) {
                            continue;
                        } else {
                            contain_indcall = true;
                            goto ADDTOSET;
                        }
                    }
               }
           }
       }
ADDTOSET:
       if (contain_indcall) funcs_with_indirect_calls.insert(&func);
    }

}

void FunctionPointerAnalysis::computeGlobalStorage(Module& M) {
    for (Function& f : M) {
        for (BasicBlock& bb : f) {
            for (Instruction& inst : bb) {
                if (StoreInst* store = dyn_cast<StoreInst>(&inst)) {
                    Value* store_ptr = store->getPointerOperand();
                    Value* store_value = store->getValueOperand();
                    if (isa<GlobalValue>(store_ptr) && isa<Constant>(store_value)) {
                        global_values_cache[store_ptr].insert(store_value);
                    }
                }
            }
        }
    }

    for (GlobalVariable& gv : M.getGlobalList()) {
        if (gv.hasInitializer()) {
            Constant* initializer = gv.getInitializer();
            if (initializer) {
                global_values_cache[&gv].insert(initializer);
            }
        }
    }
}


// Collect struct type info
void FunctionPointerAnalysis::collectTypes(Module& M) {
    const DataLayout *layout = M.getDataLayout();

    for (StructType *st : M.getIdentifiedStructTypes()) {
        bool add_to_cache = false;

        unsigned n_fields = st->getStructNumElements();

        if (st->isOpaque()) {
            //std::cout << "isOpque!\n";
        } else {
            const StructLayout *st_layout = layout->getStructLayout(st);
            for (unsigned i = 0; i < n_fields; i++) {
                Type *field_type = st->getStructElementType(i);
                if (field_type->isPointerTy()) {
                    if (field_type->getPointerElementType()->isStructTy()) {
                        // TODO: clang may transform a function pointer filed of a struct to {}*
                        // Currently, we exclude this case by checking the struct size.
                        //outs() << st->getName() << ": a field points to struct!\n";
                        //outs() << "And the index is: " << i << " \n";
                                        //6.19: try caching them
                        //if (field_type->getPointerElementType()->getStructNumElements() > 0) {
                        //  add_to_cache = false;
                        //  break;
                        //}
                    }
                    if (field_type->getPointerElementType()->isFunctionTy()) {
                        //outs() << st->getName() << ": a field points to function!\n";
                        add_to_cache = true;
                    }
                }

                unsigned field_offset = st_layout->getElementOffset(i);
                unsigned fielf_bitoffset = st_layout->getElementOffsetInBits(i);
            }
            // Currently we record "bottom-level method-table struct", i.e., a struct containing
            // a function pointer field, but no not struct pointer filed.
            if (add_to_cache) {
                struct_types_cache[st] = st;
            }
        }
    }

    // Collect function signature info
    for (Function &func : M.getFunctionList()) {
        FunctionType* func_ty = func.getFunctionType();

        unsigned n_parameters = func_ty->getFunctionNumParams();
        const llvm::Type *return_type = func_ty->getReturnType();

        // FunctionResolver* func_resolver = lang_manager->getFunctionResolver(nullptr);


        if (return_type->isPointerTy()) {
          if (return_type->getPointerElementType()->isStructTy()) {
             //std::cout << func_resolver->demangleFunction(func.getName()) << ": ret is a pointer to struct ty\n";
             //function_types_cache[func_resolver->demangleFunction(func.getName())] = return_type->getPointerElementType();
             function_types_cache[&func] = return_type->getPointerElementType();
          }
        }

        for (unsigned i = 0; i < n_parameters; i++) {
            // TODO: record the parameters types
        }
    }


    for (auto& func_cache : function_types_cache) {
        //std::cout << func_cache.first << std::endl;
        const Type* ty = func_cache.second;
        for (auto& st : struct_types_cache) {
            if (st.first == ty ) {
                //outs() << "type maching!!!\n";
                //outs() << ty->getStructName() << "\n";
            }
        }
    }
}


void FunctionPointerAnalysis::impactAnalysis(Module& M) {
    // First, collect all address taken functions
    for (Function* func : address_taken_functions) {
        impacted_by_fptr_functions.insert(func);
    }

    // Second, collect functions with indirect call sites
    for (Function* func : funcs_with_indirect_calls) {
        impacted_by_fptr_functions.insert(func);
    }

}

// not used now
void FunctionPointerAnalysis::buildCG(Module& M) {
    int CG_BUCKET_NUMBER = 11;
    int cg_bucket[11] = { 0 };
    int cg_bucket_steps[11] = { 0, 1, 2, 3, 4, 5, 6, 7, 10, 30, 100 };

    for (Function& f : M) {
        if (f.isDeclaration() || f.isIntrinsic()) {
            continue;
        }
        for (BasicBlock& bb : f) {
            for (Instruction& inst : bb) {
              if (isa<CallInst>(inst)) {
                CallSite cs(&inst);
                if (isa<InlineAsm>(cs.getCalledValue())) { 
                    continue;
                }
                else if (cs.isCall() || cs.isInvoke()) {
                    Function *callee = cs.getCalledFunction();
                    if (!callee) {
                        if (cppUtil::isVirtualCallSite(cs)) {
                            continue;
                        } else {
                            std::unordered_set<Function*> result;
                            // First, use PPFunctionPointerAnalysis
                            PPFunctionPointerAnalysis* pfa = new PPFunctionPointerAnalysis();
                            pfa->run(&f, cs);
                            if (pfa->callsite_targets.size() >= 1) {
                                //outs() << "PPFptrAna finds the following functions\n";
                                for (Function* func : pfa->callsite_targets) {
                                    //outs() << func->getName() << "\n";
                                    result.insert(func);
                                }
                            } else {
                                // Then, use AddressTakenFunctionAnalysis
                                AddressTakenAnalysis* ata = new AddressTakenAnalysis(M);
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
