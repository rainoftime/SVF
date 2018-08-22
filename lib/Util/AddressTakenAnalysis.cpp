#include <llvm/Pass.h>
#include "Util/AddressTakenAnalysis.h"
#include "Util/AnalysisUtil.h"
#include "Util/CPPUtil.h"
#include <unordered_set>
using namespace llvm;

unsigned AddressTakenAnalysis::getGepConstantOffset(GetElementPtrInst* gep) {
    unsigned ret = 40085;
    Value* val = gep->getOperand(0);
    if (val->getType()->isPointerTy()) {
        if (val->getType()->getPointerElementType()->isStructTy()) {
            if (gep->getNumOperands() >= 3) {
                Value* offset_val = gep->getOperand(2);
                if (llvm::ConstantInt* CI = dyn_cast<llvm::ConstantInt>(offset_val)) {
                    ret = CI->getSExtValue();
                }
            }
        }
    }
    return ret;
}

int AddressTakenAnalysis::addressTakenFuncStoreIndexBase(Function *func) {
    // FIXME
    // This needs datalayout analysis
    return 0;
}

bool AddressTakenAnalysis::isAddressTaken(Value* V) {
  for (Value::const_use_iterator I = V->use_begin(), E = V->use_end(); I != E; ++I) {
    User *U = I->getUser ();
    if (isa<StoreInst>(U))
      return true;
    if (!isa<CallInst>(U) && !isa<InvokeInst>(U)) {
      if (U->use_empty())
        continue;
      if (isa<GlobalAlias>(U)) {
        if (isAddressTaken(U))
          return true;
      } else {
        if (Constant *C = dyn_cast<Constant>(U)) {
          if (ConstantExpr *CE = dyn_cast<ConstantExpr>(C)) {
            if (CE->getOpcode() == Instruction::BitCast) {
              return isAddressTaken(CE);
            }
          }
        }
        return true;
      }

      // FIXME: Can be more robust here for weak aliases that
      // are never used
    } else {
      llvm::CallSite CS(cast<Instruction>(U));
      if (!CS.isCallee(&*I))
        return true;
    }
  }
  return false;
}

bool AddressTakenAnalysis::isTypeCompatible(Type* t1, Type* t2) {
    if ((!t1) || (!t2))
        return false;
    if (t1->isPointerTy() && t2->isPointerTy())
        return true;
    return t1 == t2;
}

bool AddressTakenAnalysis::isCallsiteFunctionStrictCompatible(CallSite callsite, Function* func) {
    auto& arg_list = func->getArgumentList();
    unsigned callsite_arg_size = callsite.arg_size();
    unsigned func_arg_size = arg_list.size();
    if (!isTypeCompatible(callsite->getType(), func->getReturnType())) {
        // return type incompatible
        return false;
    }
    if ((!func->isVarArg()) && callsite_arg_size != func_arg_size) {
        // non-va-arg, function and callsite must have the same amount of arguments to be compatible
        return false;
    }

    unsigned idx = 0;
    for (Argument& formal_arg : arg_list) {
        if (idx >= callsite_arg_size) {
            // not enough callsite arguments
            return false;
        }
        Value* real_arg = callsite.getArgument(idx);
        Type* real_type = real_arg->getType();
        Type* formal_type = formal_arg.getType();

        if ((!real_type) || (!formal_type))
            return false;

        if (real_type->isPointerTy() && formal_type->isPointerTy()) {
            if (real_type->getPointerElementType()->isStructTy()) {
                if (!formal_type->getPointerElementType()->isStructTy()) {
                    return false;
                } else {
                    if (real_type->getPointerElementType()->getStructNumElements() !=
                        formal_type->getPointerElementType()->getStructNumElements()) {
                        return false;
                    }
                }
            }
        } else if (real_type->isStructTy() && formal_type->isStructTy()) {
            // here we only match the number of fields (this is not safe)
            if (real_type->getStructNumElements() != formal_type->getStructNumElements()) {
                return false;
            }
        } else if (real_type != formal_type) {
            return false;
        }
        idx++;
    }
    return true;
}

void AddressTakenAnalysis::guessCalleesForIndCallSite(CallSite callsite, std::unordered_set<Function*> &result) {
    Value* callee_val = callsite.getCalledValue();
    Function *base_func = callsite->getParent()->getParent();
    std::unordered_set<Function*> matched_address_taken_funcs;

    for (Function* func : address_taken_functions) {
        if (isCallsiteFunctionStrictCompatible(callsite, func)) {
            matched_address_taken_funcs.insert(func);
        }
    }

    // disabled by default
    if (enable_field_prunning) {
        if (matched_address_taken_funcs.size() <= callees_num_limit) {
            for (Function* func : matched_address_taken_funcs) {
                if (func == base_func) {
                    continue;
                }
                result.insert(func);
            }
        } else {
            std::unordered_set<Function*> matched_after_pruning;
            int called_func_index = 40085;
            if (LoadInst* load = dyn_cast<LoadInst>(callee_val)) {
                Value* load_ptr = load->getPointerOperand();
                if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(load_ptr)) {
                    int offset = getGepConstantOffset(gep);
                    if (offset != 40085) {
                        called_func_index = offset;
                    }
                } else if (CastInst* cast = dyn_cast<CastInst>(load_ptr)) {
                    if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(cast->getOperand(0))) {
                        int offset = getGepConstantOffset(gep);
                        if (offset != 40085) {
                            called_func_index = offset;
                        }
                    }
                }
            } else if (CastInst* cast = dyn_cast<CastInst>(callee_val)) {
                if (LoadInst* load = dyn_cast<LoadInst>(cast->getOperand(0))) {
                    if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(load->getPointerOperand())) {
                        int offset = getGepConstantOffset(gep);
                        if (offset != 40085) {
                            called_func_index = offset;
                        }
                    }
                }
            } else if (PHINode* phi = dyn_cast<PHINode>(callee_val)) {
                unsigned num_values = phi->getNumIncomingValues();
                if (num_values >= 1) {
                    for (unsigned i = 0; i < num_values; i++) {
                        Value* val_i = phi->getIncomingValue(i);
                        if (LoadInst* load_i = dyn_cast<LoadInst>(val_i)) {
                            if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(load_i->getPointerOperand())) {
                                int offset = getGepConstantOffset(gep);
                                if (offset != 40085) {
                                    called_func_index = offset;
                                }
                            } else if (CastInst* cast = dyn_cast<CastInst>(load_i->getPointerOperand())) {
                                if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(cast->getOperand(0))) {
                                    int offset = getGepConstantOffset(gep);
                                    if (offset != 40085) {
                                        called_func_index = offset;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            for (Function* func : matched_address_taken_funcs) {
                int canidate_func_index = addressTakenFuncStoreIndexBase(func);
                if (called_func_index == canidate_func_index) {
                    matched_after_pruning.insert(func);
                }
            }
            if (matched_after_pruning.size() >=1 && matched_after_pruning.size() <= callees_num_limit) {
                for (Function* func : matched_after_pruning) {
                    if (func == base_func) {
                        continue;
                    }
                    result.insert(func);
                }
            }
        }

    } else {
        for (Function* func : matched_address_taken_funcs) {
            if (func == base_func) {
                continue;
            }
            result.insert(func);
        }
    }
}


void AddressTakenAnalysis::buildCG() {
    int CG_BUCKET_NUMBER = 11;
    int cg_bucket[11] = { 0 };
    int cg_bucket_steps[11] = { 0, 1, 2, 3, 4, 5, 6, 7, 10, 30, 100 };

    for (Function& f : M) {
        if (f.isDeclaration() || f.isIntrinsic()) {
            continue;
        }
        for (BasicBlock& bb : f) {
            for (Instruction& inst : bb) {
                CallSite CS(&inst);
                if (CS.isCall() || CS.isInvoke()) {
                    Function *callee = CS.getCalledFunction();
                    if (!callee) {
                        if (cppUtil::isVirtualCallSite(CS) || isa<InlineAsm>(CS.getCalledValue())) {
                            continue;
                        } else {
                            Value* callee_val = CS.getCalledValue();
                            std::unordered_set<Function*> matched_address_taken_funcs;
                            for (Function* func : address_taken_functions) {
                                if (isCallsiteFunctionStrictCompatible(CS, func)) {
                                    matched_address_taken_funcs.insert(func);
                                }
                            }
                            // Look for how the "address taken" happens
                            if (matched_address_taken_funcs.size() == 0) {
                                cg_bucket[0]++;
                            } else if (matched_address_taken_funcs.size() >= 1) {
                                int i;
                                for (i = 0; i < CG_BUCKET_NUMBER - 1; i++) {
                                    if (matched_address_taken_funcs.size() < cg_bucket_steps[i + 1]) {
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

    llvm::outs() << "--------------AddressTakenAnalysis CG Begin------------------\n";
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
    llvm::outs() << "--------------AddressTakenAnalysis CG End------------------\n";
}
