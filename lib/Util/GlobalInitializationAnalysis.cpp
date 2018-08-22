#include "Util/AnalysisUtil.h"
#include "Util/GlobalInitializationAnalysis.h"


void GlobalInitializationAnalysis::computeGlobalStorage(Module& M) {
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


int GlobalInitializationAnalysis::addressTakenFuncStoreIndexBase(Function *func) {
    int ret = 40086;
#if 0
    for (Value::const_use_iterator I = func->use_begin(), E = func->use_end(); I != E; ++I) {
        User* U = I->getUser ();
        if (isa<StoreInst>(U)) {
            if (StoreInst* store_inst = dyn_cast<StoreInst>(U)) {
                if (store_inst->getNumOperands() >= 2) {
                    Value* target = store_inst->getOperand(1);
                    if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(target)) {
                        unsigned offset = getGepConstantOffset(gep);
                        if (offset != 40085) {
                            return offset;
                        }
                    }
                }
            }
        } else if (isa<Constant>(U)) {
            if (ConstantStruct* pt_val = dyn_cast<ConstantStruct>(U)) {
                //outs() << "Is a constant struct!!!!!!!!!!!!!!!!!!!!!!!\n";
                StructType *struct_type = dyn_cast<StructType>(pt_val->getType());
                // FIXME
                unsigned struct_size = TSDL->getTypeSizeInBits(struct_type);
                unsigned num_fields = pt_val->getType()->getStructNumElements();
                for (unsigned i = 0; i < num_fields; i++) {
                    if (struct_type->getElementType(i)->isPointerTy()) {
                        if (struct_type->getElementType(i)->getPointerElementType()->isFunctionTy()) {
                            Constant* elem_val = pt_val->getAggregateElement(i);
                            if (Function* pt_func = dyn_cast<Function>(elem_val)) {
                                if (pt_func == func) {
                                    ret = i;
                                    return ret;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
#endif
    return ret;
}
