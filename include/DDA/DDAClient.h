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


/**
 * General DDAClient which queries all top level pointers by default.
 */
class DDAClient {
public:
    DDAClient(llvm::Module& mod) : pag(NULL), module(mod), curPtr(0), solveAll(true), queryAliasSet(false) {}

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

    PAG*   pag;				///< PAG graph used by current DDA analysis
    llvm::Module& module;		///< LLVM module
    NodeID curPtr;	                ///< current pointer being queried
    NodeBS candidateQueries;	        ///< store all candidate pointers to be queried

    std::vector<std::pair<llvm::Value*, int>> DDAAliasSetSize;      ///< Demand-driven AliasSet
    std::vector<std::pair<llvm::Value*, int>> AndersenAliasSetSize; ///< Andersen AliasSet
private:
    NodeBS userInput;           ///< User input queries
    bool solveAll;		///< TRUE if all top level pointers are being queried
    bool queryAliasSet;         ///< Query the alias set
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
 * DDA client with function pointers as query candidates.
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
        return candidateQueries;
    }
    virtual void performStat(PointerAnalysis* pta);
};




#endif /* DDACLIENT_H_ */
