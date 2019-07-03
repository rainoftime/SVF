/*
 * @file: DDAClient.h
 * @author: yesen
 * @date: 4 Feb 2015
 *
 * LICENSE
 *
 */


#ifndef DDACLIENT_H_
#define DDACLIENT_H_


#include "MemoryModel/PAG.h"
#include "MemoryModel/PAGBuilder.h"
#include "MemoryModel/PointerAnalysis.h"
#include "MSSA/SVFGNode.h"
#include "Util/BasicTypes.h"
#include "Util/CPPUtil.h"
#include <llvm/IR/DataLayout.h>

#include <map>
#include <vector>

//#include "SABER/SaberCheckerAPI.h"

/**
 * General DDAClient which queries all top level pointers by default.
 */
class DDAClient {
public:
    DDAClient(llvm::Module& mod) : pag(NULL), module(mod), curPtr(0),
        solveAll(true), queryAliasSet(false), queryAliasPair(false) {}

    virtual ~DDAClient() {}

    virtual inline void initialise(llvm::Module& module) {}

    /// Collect candidate pointers for query.
    virtual inline NodeBS& collectCandidateQueries(PAG* p) {
        setPAG(p);
        if (solveAll)
            candidateQueries = pag->getAllValidPtrs();
        else {
            for (NodeBS::iterator it = userInput.begin(), eit = userInput.end(); it != eit; ++it)
                addCandidate(*it);
        }
        return candidateQueries;
    }
    /// Get candidate queries
    inline const NodeBS& getCandidateQueries() const {
        return candidateQueries;
    }

    /// Call back used by DDAVFSolver.
    virtual inline void handleStatement(const SVFGNode* stmt, NodeID var) {}
    /// Set PAG graph.
    inline void setPAG(PAG* g) {
        pag = g;
    }
    /// Set the pointer being queried.
    void setCurrentQueryPtr(NodeID ptr) {
        curPtr = ptr;
    }
    /// Set pointer to be queried by DDA analysis.
    void setQuery(NodeID ptr) {
        userInput.set(ptr);
        solveAll = false;
    }

    // Set all top-level pointers to be queries
    void setSolveAll() {
        solveAll = true;
    }

    // Set query alias set
    void setQueryAliasSet() {
        queryAliasSet = true;
    }

    // Set query alias pair
    void setQueryAliasPair() {
        queryAliasPair = true;
    }

    // Set query alias set
    void setQueryAliasSetSize(const llvm::Value *val, std::pair<unsigned, unsigned> sz) {
        for (unsigned i = 0; i < DDAAliasSetSize.size(); i++) {
            if (DDAAliasSetSize[i].first == val) {
                DDAAliasSetSize[i].second = sz.second;
                AndersenAliasSetSize[i].second = sz.first;
                break;
            }
        }
    }

    /// Get LLVM module
    inline llvm::Module& getModule() const {
        return module;
    }
    virtual void answerQueries(PointerAnalysis* pta);

    virtual inline void performStat(PointerAnalysis* pta) {}

    virtual inline void collectWPANum(llvm::Module& mod) {}

    /// Indirect call edges type, map a callsite to a set of callees
    //@{
    typedef std::set<llvm::CallSite> CallSiteSet;
    typedef PAG::CallSiteToFunPtrMap CallSiteToFunPtrMap;
    typedef std::set<const llvm::Function*> FunctionSet;
    typedef std::map<llvm::CallSite, FunctionSet> CallEdgeMap;
    typedef SCCDetection<PTACallGraph*> CallGraphSCC;
    //@}
protected:
    void addCandidate(NodeID id) {
        if (pag->isValidTopLevelPtr(pag->getPAGNode(id)))
            candidateQueries.set(id);
    }

    PAG*   pag;				    ///< PAG graph used by current DDA analysis
    llvm::Module& module;		///< LLVM module
    NodeID curPtr;	            ///< current pointer being queried
    NodeBS candidateQueries;	///< store all candidate pointers to be queried

    std::vector<std::pair<llvm::Value*, int>> DDAAliasSetSize;      ///< Demand-driven AliasSet
    std::vector<std::pair<llvm::Value*, int>> AndersenAliasSetSize; ///< Andersen AliasSet

    std::map<llvm::Value*, std::vector<llvm::Value*>> DDASourceDstMap; ///< Demand-driven alias pair
    std::map<llvm::Value*, std::vector<bool>> DDASourceDstResult;      ///< alias pair result
    std::map<llvm::Value*, std::vector<bool>> AnderSourceDstResult;    ///< Andersen alias pair result

private:
    NodeBS userInput;           ///< User input queries
    bool solveAll;		        ///< TRUE if all top level pointers are being queried
    bool queryAliasSet;         ///< Query the alias set
    bool queryAliasPair;        ///< Query the alias pair

};


/**
 * DDA client with function pointers as query candidates.
 */
class FunptrDDAClient : public DDAClient {
private:
    typedef std::map<NodeID,llvm::CallSite> VTablePtrToCallSiteMap;
    VTablePtrToCallSiteMap vtableToCallSiteMap;
public:
    FunptrDDAClient(llvm::Module& module) : DDAClient(module) {}
    ~FunptrDDAClient() {}

    /// Only collect function pointers as query candidates.
    virtual inline NodeBS& collectCandidateQueries(PAG* p) {
        setPAG(p);
        for(PAG::CallSiteToFunPtrMap::const_iterator it = pag->getIndirectCallsites().begin(),
                eit = pag->getIndirectCallsites().end(); it!=eit; ++it) {
            if (cppUtil::isVirtualCallSite(it->first)) {
                const llvm::Value *vtblPtr = cppUtil::getVCallVtblPtr(it->first);
                assert(pag->hasValueNode(vtblPtr) && "not a vtable pointer?");
                NodeID vtblId = pag->getValueNode(vtblPtr);
                addCandidate(vtblId);
                vtableToCallSiteMap[vtblId] = it->first;
            } else {
                addCandidate(it->second);
            }
        }
        return candidateQueries;
    }
    virtual void performStat(PointerAnalysis* pta);
};


/**
 * DDA client that answers alias set
 */
class TaintDDAClient : public DDAClient {
private:

public:
    TaintDDAClient(llvm::Module& module) : DDAClient(module) {}
    ~TaintDDAClient() {}

    ///
    virtual inline NodeBS& collectCandidateQueries(PAG* p) {
        setPAG(p);
        if (llvm::Function* checkFun = module.getFunction("pp_check_alias_set")) {
            for (llvm::Value::user_iterator i = checkFun->user_begin(),
                    e = checkFun->user_end(); i != e; ++i) {
                //llvm::outs() << " Find pp_check_alias_set call!\n";

                if (llvm::CallInst *call = llvm::dyn_cast<llvm::CallInst>(*i)) {
                    assert( call->getNumArgOperands() == 1 && "arguments should be one pointer!!");
                    llvm::Value* val = call->getArgOperand(0);
                    NodeID ptrId = pag->getValueNode(val);
                    addCandidate(ptrId);
                    DDAAliasSetSize.push_back(std::make_pair(val, 0));
                    AndersenAliasSetSize.push_back(std::make_pair(val, 0));
                } else {
                    assert( false && "alias check functions not only used at callsite??");
                }
            }
        }

        llvm::outs() << "Find no instrumentaion, will collect source auto.\n";
        // Find no instrumentation; collect by self..
        if (DDAAliasSetSize.size() == 0) {
            for (llvm::Function& fun : module) {
                for (llvm::BasicBlock& bb : fun) {
                    for (llvm::Instruction& inst : bb) {
                        if (llvm::CallInst *call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
                            if (call->getCalledFunction() == nullptr) continue;
                            llvm::Function* callee = call->getCalledFunction();
                            if (!callee) continue;
                            llvm::StringRef fname = callee->getName();

                            if (fname == "free" || fname == "cfree") {
                                call->getNumArgOperands();
                                unsigned int num_args = call->getNumArgOperands();
                                if (num_args != 1) continue;
                                llvm::Value* arg = call->getArgOperand(0);
                                if (!arg->getType()->isPointerTy()) continue;
                                if (!(llvm::isa<llvm::CallInst>(arg) || llvm::isa<llvm::LoadInst>(arg) || llvm::isa<llvm::CastInst>(arg))) continue;
                                llvm::Type *pointedTy = arg->getType()->getPointerElementType();
                                //if (pointedTy->isAggregateType() ||  pointedTy->isVectorTy()) {
                                  //  continue;
                                //}
                                bool addToQuery = true;
                                for (unsigned i = 0; i < DDAAliasSetSize.size(); i++) {
                                    if (DDAAliasSetSize[i].first == arg) {
                                        addToQuery = false; break;
                                    }
                                }
                                if (addToQuery) {
                                    //arg->dump();
                                    NodeID ptrId = pag->getValueNode(arg);
                                    addCandidate(ptrId); 
                                    DDAAliasSetSize.push_back(std::make_pair(arg, 0));
                                    AndersenAliasSetSize.push_back(std::make_pair(arg, 0));
                                }
                            }
                        }
                    }
                }
            }
        }

        llvm::outs() << "Query size: " << DDAAliasSetSize.size() << "\n";


        return candidateQueries;
    }
    virtual void performStat(PointerAnalysis* pta);
};

/**
 * DDA client that answers alias pair
 */
class SecurityDDAClient : public DDAClient {
private:

public:
    SecurityDDAClient(llvm::Module& module) : DDAClient(module) {}
    ~SecurityDDAClient() {}

    ///
    virtual inline NodeBS& collectCandidateQueries(PAG* p) {
        setPAG(p);

        if (llvm::Function* sourceFun = module.getFunction("pp_is_source")) {
            for (llvm::Value::user_iterator I = sourceFun->user_begin(),
                    E = sourceFun->user_end(); I != E; ++I) {
                // llvm::outs() << " Find pp_check_alias_pair call!\n";
                if (llvm::CallInst *Call = llvm::dyn_cast<llvm::CallInst>(*I)) {
                    assert(Call->getNumArgOperands() == 1 && "arguments should be one!!");
                    llvm::Value* Source = Call->getArgOperand(0);
                    llvm::Instruction *prevInst = Call->getPrevNode();
                    if (!prevInst) continue;
                    if (llvm::CallInst *prevCall = llvm::dyn_cast<llvm::CallInst>(prevInst)) {
                        if (!prevCall->getCalledFunction()) continue;
                        if (prevCall->getCalledFunction()->getName() != "pp_check_alias_pair") continue;
                        // llvm::outs() << "Find Source: " << Source->getName() << "\n";

                        llvm::Value* Index = prevCall->getArgOperand(0);
                        std::vector<llvm::Value*> TmpDstVec;
                        std::vector<bool> TmpResVec;
                        std::vector<bool> TmpAnderResVec;
                        // Find the Dst
                        if (llvm::Function* checkFun = module.getFunction("pp_check_alias_pair")) {
                            for (llvm::Value::user_iterator II = checkFun->user_begin(),
                                    EE = checkFun->user_end(); II != EE; ++II) {
                                if (llvm::CallInst *DstCall = llvm::dyn_cast<llvm::CallInst>(*II)) {
                                    if (DstCall == prevCall) continue;
                                    llvm::Value *DstIndex = DstCall->getArgOperand(0);
                                    if (DstIndex != Index) continue;
                                    llvm::Value *DstVal = DstCall->getArgOperand(1);
                                    TmpDstVec.push_back(DstVal);
                                    TmpResVec.push_back(true);
                                    TmpAnderResVec.push_back(true);
                                }
                            }
                        }
                        DDASourceDstMap[Source] = TmpDstVec;
                        DDASourceDstResult[Source] = TmpResVec;
                        AnderSourceDstResult[Source] = TmpAnderResVec;
                    }
                }
            }
        }

        // Print the queries
        for (auto& Query : DDASourceDstMap) {
            llvm::Value* Src = Query.first;
            std::vector<llvm::Value*> Dsts = Query.second;
            //llvm::outs() << "Source: ";
            //Src->dump();
            for (unsigned I = 0; I < Dsts.size(); I++) {
                //llvm::outs() << "   Dst: ";
                //Dsts[I]->dump();
            }
        }
        return candidateQueries;
    }
    virtual void performStat(PointerAnalysis* pta);
};




#endif /* DDACLIENT_H_ */
