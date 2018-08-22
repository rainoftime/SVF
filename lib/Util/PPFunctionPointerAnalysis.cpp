#include <llvm/IR/Function.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/ADT/Statistic.h>
#include <llvm/IR/InstIterator.h>
#include "Util/AnalysisUtil.h"
#include "Util/PPFunctionPointerAnalysis.h"

#define DEBUG_TYPE "PPPPFunctionPointerAnalysis"

using namespace llvm;
using namespace std;

PPFunctionPointerAnalysis::PPFunctionPointerAnalysis() {
    analyze_inst_count = 0;
}

PPFunctionPointerAnalysis::~PPFunctionPointerAnalysis() {
    callsite_targets.clear();
}

void PPFunctionPointerAnalysis::run(Function* func, CallSite CS) {
    m_cs = CS;
    Value* callee_val = CS.getCalledValue();
    processFuncPtr(callee_val);
}

/*
 *  Process four types
 *    - argument: the function pointer may be passed by the arg
 *    - phinode:
 *    - loadinst
 *    - callinst: the function pointer is a call intruction,recursively process
 */

void PPFunctionPointerAnalysis::processFuncPtr(Value* funcptr) {
    if (Argument* argument = dyn_cast<Argument>(funcptr)) {
        // the function pointer may be passed by the arg, get the use of the argument
        processFuncPtrArgFuncptr(argument);
    } else if (PHINode* phi_node = dyn_cast<PHINode>(funcptr)) {
        // TODO
        processFuncPtrPhiNode(phi_node);
    } else if (CallInst* call_inst = dyn_cast<CallInst>(funcptr)) {
        // the function pointer is a call instruction; recursively process?
        processFuncPtrCallInst(call_inst);
    } else if (LoadInst* load_inst = dyn_cast<LoadInst>(funcptr)) {
        // LoadInst seems to be the hardest ?..
        processFuncPtrLoadInst(load_inst);
    } else if (CastInst* cast_inst = dyn_cast<CastInst>(funcptr)) {
        Value* cast_val = cast_inst->getOperand(0);
        if (Function *func = dyn_cast<Function>(cast_val)) {
            outs() << __LINE__ << ", PPFptrAnalysis find a function: " <<
                   func->getName() << "\n";
            callsite_targets.insert(func);
        } else if (Argument* argument = dyn_cast<Argument>(cast_val)) {
            processFuncPtrArgFuncptr(argument);
        } else if (LoadInst* load_inst = dyn_cast<LoadInst>(cast_val)) {
            processFuncPtrLoadInst(load_inst);
        }
    }
}

void PPFunctionPointerAnalysis::processFuncPtrLoadInst(LoadInst* load_inst) {
    // TODO: summarize the patterns of load to avoid redundancy ...
    if (verbose_lvl > 1) outs() << "PPFPtrana load!!\n";
    Value* v = load_inst->getPointerOperand();
    if (GetElementPtrInst* gep_inst = dyn_cast<GetElementPtrInst>(v)) {
        if (verbose_lvl > 1) outs() << __LINE__ << "\n";
        processFuncPtrGEPInst(gep_inst);
    } else {
        for (User* U : v->users()) {
            if (StoreInst* st = dyn_cast<StoreInst>(U)) {
                Value* value = st->getOperand(0);
                if (Function* func = dyn_cast<Function>(value)) {
                    outs() << __LINE__ << ", PPFptrAnalysis find a function " << func->getName() << "\n";
                    callsite_targets.insert(func);
                } else if (Argument* argument = dyn_cast<Argument>(value)) {
                    processFuncPtrArgFuncptr(argument);
                } else if (PHINode* phi = dyn_cast<PHINode>(value)) {
                    processFuncPtrPhiNode(phi);
                }
            } else if (LoadInst* st = dyn_cast<LoadInst>(U)) {
                Value* v_st = st->getOperand(0);
                if (Function* func = dyn_cast<Function>(v_st)) {
                    outs() << __LINE__ << ", PPFptrAnalysis find a function " << func->getName() << "\n";
                    callsite_targets.insert(func);
                } else if (isa<GlobalValue>(v_st)) {

                } else if (ConstantExpr* val_exp = dyn_cast<ConstantExpr>(v_st)) {
                    if (CastInst* cast_inst = dyn_cast<CastInst>(val_exp->getAsInstruction())) {
                        if (Function* func = dyn_cast<Function>(cast_inst->getOperand(0))) {
                            outs() << __LINE__ << ", PPFptrAnalysis find a function: " <<
                                   func->getName() << "\n";
                            callsite_targets.insert(func);
                        }
                    }
                } else  {
                    if (verbose_lvl > 1) outs() << __LINE__ << "\n";
                }
            } else {
                if (verbose_lvl > 1) outs() << __LINE__ << "\n";
            }
        }
    }
}

void PPFunctionPointerAnalysis::processFuncPtrGEPInst(GetElementPtrInst* gep_inst) {
    //outs() << "PPFPtrana GEP!!\n";
    Value* v = gep_inst->getOperand(0);
    for (User* U : v->users()) {
        //U->dump();
        if (GetElementPtrInst* gepi = dyn_cast<GetElementPtrInst>(U)) {
            //if (processFuncPtrCmpGEPInst(gep_inst, gepi)) {  // TODO: fix
            if (true) {
                for (User* UL : gepi->users()) {
                    if (StoreInst* store_inst = dyn_cast<StoreInst>(UL)) {
                        Value* vl = store_inst->getOperand(0);
                        if (Function* func = dyn_cast<Function>(vl)) {
                            outs() << __LINE__ << ", PPFptrAnalysis find a function " << func->getName() << "\n";
                            callsite_targets.insert(func);
                        } else if (ConstantExpr* val_exp = dyn_cast<ConstantExpr>(vl)) {
                            if (CastInst* cast_inst = dyn_cast<CastInst>(val_exp->getAsInstruction())) {
                                if (Function *func = dyn_cast<Function>(cast_inst->getOperand(0))) {
                                    outs() << __LINE__ << ", PPFptrAnalysis find a function: " <<
                                           func->getName() << "\n";
                                    callsite_targets.insert(func);
                                }
                            }
                        } else if (CallInst* call = dyn_cast<CallInst>(vl)){
                            if (verbose_lvl > 1) outs() << __LINE__ << "\n";
                            processFuncPtrCallInst(call);
                        }
                    }
                }
            }
        }
    }
}

bool PPFunctionPointerAnalysis::processFuncPtrCmpGEPInst(GetElementPtrInst * gep_left, GetElementPtrInst * gep_right) {
    // TODO
    unsigned int ASL = gep_left->getPointerAddressSpace();
    unsigned int ASR = gep_right->getPointerAddressSpace();
    if (ASL != ASR) return false;

    // LLVM 3.6 does not have getSourceElementType
    // pruning with types
    /*
    Type *ETL = gep_left->getSourceElementType();
    Type *ETR = gep_right->getSourceElementType();

    string bufferL;
    raw_string_ostream osL(bufferL);
    osL << *ETL;
    string strETL = osL.str();

    string bufferR;
    raw_string_ostream osR(bufferR);
    osR << *ETL;
    string strETR = osR.str();

    if (strETL != strETR) return false;
    */

    // This can be possibly very slow
    unsigned int NPL = gep_left->getNumOperands();
    unsigned int NPR = gep_right->getNumOperands();

    if (NPL != NPR) return false;

    for (unsigned i = 0, e = gep_left->getNumOperands(); i != e; ++i) {
      Value* vL = gep_left->getOperand(i);
      Value* vR = gep_right->getOperand(i);
      if (cmpValue(vL, vR) == false) return false;
    }
    return true;
}

// process the function pointer that is passed by argument
void PPFunctionPointerAnalysis::processFuncPtrArgFuncptr(Argument* argument) {
    outs() << "PPFptrAna argu\n";
    unsigned offset = argument->getArgNo();
    if (analyze_inst_count++ > 10) {
        return;   // In python and ar, there may be infinite loops here..
    }
    // get its parent caller
    Function* parent = argument->getParent();
    // Analyze the functions that may call the func
    // TODO: use current CG results
    for (User* U : parent->users()) {
        if (CallInst* call_inst_call = dyn_cast<CallInst>(U)) {
            Value* val = call_inst_call->getArgOperand(offset);
            if (ConstantExpr* val_exp = dyn_cast<ConstantExpr>(val)) {
                Instruction* val_exp_inst = val_exp->getAsInstruction();
                if (CastInst* cast_inst = dyn_cast<CastInst>(val_exp_inst)) {
                    if (Function* func = dyn_cast<Function>(cast_inst->getOperand(0))) {
                        outs() << __LINE__ << ", PPFptrAnalysis find a function: " <<
                               func->getName() << "\n";
                        callsite_targets.insert(func);
                    }
                }
            } else if (Function* func = dyn_cast<Function>(val)) {
                outs() <<  __LINE__ << ", PPFptrAnalysis find a function " << func->getName() << "\n";
                callsite_targets.insert(func);
            } else if (PHINode* val_phi = dyn_cast<PHINode>(val)) {
                for (User* U : val_phi->users()) {
                    if (CallInst* call_inst = dyn_cast<CallInst>(U)) {
                        Value* v = call_inst->getArgOperand(offset);
                        if (Function* func  = dyn_cast<Function>(v)) {
                            outs() << __LINE__ << ", PPFptrAnalysis find a function " << func->getName() << "\n";
                            callsite_targets.insert(func);
                        }
                    }
                }
                // processFuncPtrPhiNode(val_phi);
            } else if (Argument* val_argu = dyn_cast<Argument>(val)) {
                processFuncPtrArgFuncptr(val_argu);
            } else if (LoadInst* val_load = dyn_cast<LoadInst>(val)) {
                //processFuncPtrLoadInst(val_load);
            }
        }
    }
}


void PPFunctionPointerAnalysis::processFuncPtrPhiNode(PHINode* phi_node) {
    // In LLVM 3.6, we cannot use phi_node->incoming_values()
    outs() << "PPFptrAna: phi node\n";
    unsigned int num_values = phi_node->getNumIncomingValues();
    if (num_values < 1) {
        return;
    }
    Function* base_func = phi_node->getParent()->getParent();
    // Be careful about cast and sext !!!!!!!!!!!!
    for (unsigned int i = 0; i < num_values; i++) {
        Value* val_i = phi_node->getIncomingValue(i); // crash here
        // the following pattern is a bit tricky ...
        if (CastInst* cast_i = dyn_cast<CastInst>(val_i)) {
            //outs() << __LINE__ << "\n";
            Value* cast_i_val = cast_i->getOperand(0);
            if (SExtInst* sext = dyn_cast<SExtInst>(cast_i_val)) {
                Value* sext_ori = sext->getOperand(0);
                if (CallInst* sext_ori_call = dyn_cast<CallInst>(sext_ori)) {
                    Function* func = sext_ori_call->getCalledFunction();
                    if (func) {
                        outs() <<  __LINE__ << ", PPFptrAnalysis find a function " << func->getName() << "\n";
                        callsite_targets.insert(func);
                    }
                }
            }
        } else if (Function* func = dyn_cast<Function>(val_i)) {
            outs() << __LINE__ << ", PPFptrAnalysis find a function: " << func->getName() << "\n";
            callsite_targets.insert(func);
        } else if (Constant* cons_i = dyn_cast<Constant>(val_i)) {
            //outs() << __LINE__ << "\n";
            //cons_i->dump();
        } else if (PHINode* phi_i = dyn_cast<PHINode>(val_i)) {
            outs() << __LINE__ << "\n";
            processFuncPtrPhiNode(phi_i);
        } else if (Argument* argu_i = dyn_cast<Argument>(val_i)) {
            processFuncPtrArgFuncptr(argu_i);
        } else if (LoadInst* load_i = dyn_cast<LoadInst>(val_i)) {
            if (verbose_lvl > 1) outs() << __LINE__ << "\n";
            //load_i ->getOperand(0)->dump();
            if (Function* func = dyn_cast<Function>(load_i->getOperand(0))) {
                outs() <<  __LINE__ << ", PPFptrAnalysis find a function\n";
                callsite_targets.insert(func);
            } else  {
                // TODO: currently, donot track too-long inforamtion
                // the function might be loaded from a struct with GEP
                // and the struct might be a parameter
            }
        } else {
            if (verbose_lvl > 1) outs() << __LINE__ << "\n";
        }
    }
}


void PPFunctionPointerAnalysis::processFuncPtrCallInst(CallInst* call_inst) {
    outs() << "PPFptrAna: call inst\n";
    Function* func = call_inst->getCalledFunction();
    // funcptr
    if (func != nullptr) {
        for (inst_iterator inst_it = inst_begin(func), inst_ie = inst_end(func); inst_it != inst_ie; ++inst_it) {
            if (ReturnInst* ret = dyn_cast<ReturnInst>(&*inst_it)) {
                Value* v = ret->getReturnValue();
                if (v) {
                    if (Argument* argument = dyn_cast<Argument>(v)) {
                        processFuncPtrArgFuncptr(argument);
                    }
                }
            }
        }
    } else {
        Value* funcptr = call_inst->getCalledValue();
        // simple case
        if (PHINode* phi_node = dyn_cast<PHINode>(funcptr)) {
            unsigned int num_values = phi_node->getNumIncomingValues();
            for (unsigned int i = 0; i < num_values; i++) {
                Value* val_i = phi_node->getIncomingValue(i);
                if (Function* func = dyn_cast<Function>(val_i)) {
                    for (inst_iterator inst_it = inst_begin(func), inst_ie = inst_end(func); inst_it != inst_ie; ++inst_it) {
                        if (ReturnInst* ret = dyn_cast<ReturnInst>(&*inst_it)) {
                            Value* v = ret->getReturnValue();
                            if (Argument* argument = dyn_cast<Argument>(v)) {
                                processFuncPtrArgFuncptr(argument);
                            }
                        }
                    }
                }
            }
        } else {
        }
    }
}


bool PPFunctionPointerAnalysis::cmpValue(Value* L, Value* R) {
    string bufferL;
    raw_string_ostream osL(bufferL);
    osL << *L;
    string strVL = osL.str();

    string bufferR;
    raw_string_ostream osR(bufferR);
    osR << *R;
    string strVR = osR.str();

    if (strVL != strVR) return false;

    return true;

}
