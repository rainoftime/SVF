/*
 * FlowDDA.cpp
 *
 *  Created on: Jun 30, 2014
 *      Author: Yulei Sui, Sen Ye
 */

#include "DDA/FlowDDA.h"
#include "DDA/DDAClient.h"
#include "Util/AnalysisUtil.h"
#include <llvm/Support/CommandLine.h>
#include <set>

using namespace llvm;
using namespace std;
using namespace analysisUtil;

static cl::opt<unsigned long long> flowBudget("flowbg",  cl::init(10000),
        cl::desc("Maximum step budget of flow-sensitive traversing"));

/*!
 * Compute points-to set for queries
 */
void FlowDDA::computeDDAPts(NodeID id)
{
    resetQuery();
    LocDPItem::setMaxBudget(flowBudget);

    PAGNode* node = getPAG()->getPAGNode(id);
    LocDPItem dpm = getDPIm(node->getId(),getDefSVFGNode(node));

    /// start DDA analysis
    DOTIMESTAT(double start = DDAStat::getClk());
    const PointsTo& pts = findPT(dpm);
    DOTIMESTAT(ddaStat->_AnaTimePerQuery = DDAStat::getClk() - start);
    DOTIMESTAT(ddaStat->_TotalTimeOfQueries += ddaStat->_AnaTimePerQuery);

    if(isOutOfBudgetQuery() == false)
        unionPts(node->getId(),pts);
    else
        handleOutOfBudgetDpm(dpm);

    if(this->printStat())
        DOSTAT(stat->performStatPerQuery(node->getId()));

    DBOUT(DGENERAL,stat->printStatPerQuery(id,getPts(id)));
}


std::pair<bool, bool> FlowDDA::computeDDAMayAlias(NodeID ida, NodeID idb) {
    bool ander_alias = false, fs_alias = false;
    PointsTo& ander_ptsa = getAndersenAnalysis()->getPts(ida);
    PointsTo& ander_ptsb = getAndersenAnalysis()->getPts(idb);
    if (ander_ptsa.intersects(ander_ptsb)) {
        ander_alias = true;
    }
    PointsTo ptsa = computeDDAPoinsTo(ida);
    PointsTo ptsb = computeDDAPoinsTo(idb);

    // what do containBlackHoleNode mean?
    if (containBlackHoleNode(ptsa) || containBlackHoleNode(ptsb) || ptsa.intersects(ptsb)) {
        fs_alias = true;
    }
    return std::make_pair(ander_alias, fs_alias);
}

/*
 *
 */
PointsTo FlowDDA::computeDDAPoinsTo(NodeID id) {
    resetQuery();
    LocDPItem::setMaxBudget(flowBudget);

    PAGNode* node = getPAG()->getPAGNode(id);
    LocDPItem dpm = getDPIm(node->getId(),getDefSVFGNode(node));

    /// start DDA analysis
    DOTIMESTAT(double start = DDAStat::getClk());
    const PointsTo& pts = findPT(dpm);
    DOTIMESTAT(ddaStat->_AnaTimePerQuery = DDAStat::getClk() - start);
    DOTIMESTAT(ddaStat->_TotalTimeOfQueries += ddaStat->_AnaTimePerQuery);

    if(isOutOfBudgetQuery() == false)
        unionPts(node->getId(),pts);
    else
        handleOutOfBudgetDpm(dpm);

    // TODO: if OutOfBugdet, should we return pts or Andersen's result?
    if(this->printStat())
        DOSTAT(stat->performStatPerQuery(node->getId()));

    DBOUT(DGENERAL,stat->printStatPerQuery(id,getPts(id)));

    return pts;  // is this OK?
}

bool FlowDDA::mayAlias(NodeID ida, NodeID idb) {
    PointsTo ptsa = computeDDAPoinsTo(ida);
    PointsTo ptsb = computeDDAPoinsTo(idb);

    // what do containBlackHoleNode mean?
    if (containBlackHoleNode(ptsa) || containBlackHoleNode(ptsb) || ptsa.intersects(ptsb))
        return true;

    return false;
}

/*!
 * Compute the alias set of a given pointer
 *
 */
std::pair<unsigned, unsigned> FlowDDA::computeDDAAliaseSet(NodeID id) {

    // First, get the points-to set of id,
    PointsTo pts = computeDDAPoinsTo(id);

    // Second, query the pointed-by set of the pre- Andersen analysis
    AliasSet ander_aliases;
    for (NodeBS::iterator nIter = pts.begin(); nIter != pts.end(); ++nIter) {
        // TODO: should we also record the pointed-by locations?
         ander_aliases |= getAndersenAnalysis()->getRevPts(*nIter);
    }
    std::cout << "Andersen alias set size: " << ander_aliases.count() << "\n";

    // Third, flow-sensitively analyze the pointed-by set
    //AliasSet fs_aliases;
    std::set<const Value*> fs_aliases;
    for (NodeBS::iterator nIter = ander_aliases.begin(); nIter != ander_aliases.end(); ++nIter) {
        // May issue many demand-driven points-to queries here
        // TODO: how to "save" the results
        PAGNode* node = getPAG()->getPAGNode(*nIter);
        if (getPAG()->isValidTopLevelPtr(node) && *nIter != id) {
            PointsTo pt = computeDDAPoinsTo(*nIter);
            if (pts.intersects(pt)) {
                if (node->isTopLevelPtr() && node->hasValue()) {
                    fs_aliases.insert(node->getValue());
                }
            }
        }
    }
    std::cout << "FS alias set size: " << fs_aliases.size() << "\n";
    return std::make_pair(ander_aliases.count(), fs_aliases.size());
    //return fs_aliases.size();
}


/*!
 * Handle out-of-budget dpm
 */
void FlowDDA::handleOutOfBudgetDpm(const LocDPItem& dpm) {
    DBOUT(DGENERAL,outs() << "~~~Out of budget query, downgrade to andersen analysis \n");
    PointsTo& anderPts = getAndersenAnalysis()->getPts(dpm.getCurNodeID());
    updateCachedPointsTo(dpm,anderPts);
    unionPts(dpm.getCurNodeID(),anderPts);
    addOutOfBudgetDpm(dpm);
}

bool FlowDDA::testIndCallReachability(LocDPItem& dpm, const llvm::Function* callee, CallSiteID csId) {
    CallSite cs = getSVFG()->getCallSite(csId);

    if(getPAG()->isIndirectCallSites(cs)) {
        if(getPTACallGraph()->hasIndCSCallees(cs)) {
            const FunctionSet& funset = getPTACallGraph()->getIndCSCallees(cs);
            if(funset.find(callee)!=funset.end())
                return true;
        }

        return false;
    }
    else	// if this is an direct call
        return true;

}

bool FlowDDA::handleBKCondition(LocDPItem& dpm, const SVFGEdge* edge) {
    _client->handleStatement(edge->getSrcNode(), dpm.getCurNodeID());
//    CallSiteID csId = 0;
//
//    if (edge->isCallVFGEdge()) {
//        /// we don't handle context in recursions, they treated as assignments
//        if (const CallDirSVFGEdge* callEdge = dyn_cast<CallDirSVFGEdge>(edge))
//            csId = callEdge->getCallSiteId();
//        else
//            csId = cast<CallIndSVFGEdge>(edge)->getCallSiteId();
//
//        const Function* callee = edge->getDstNode()->getBB()->getParent();
//        if(testIndCallReachability(dpm,callee,csId)==false){
//            return false;
//        }
//
//    }
//
//    else if (edge->isRetVFGEdge()) {
//        /// we don't handle context in recursions, they treated as assignments
//        if (const RetDirSVFGEdge* retEdge = dyn_cast<RetDirSVFGEdge>(edge))
//            csId = retEdge->getCallSiteId();
//        else
//            csId = cast<RetIndSVFGEdge>(edge)->getCallSiteId();
//
//        const Function* callee = edge->getSrcNode()->getBB()->getParent();
//        if(testIndCallReachability(dpm,callee,csId)==false){
//            return false;
//        }
//
//    }

    return true;
}

/*!
 * Generate field objects for structs
 */
PointsTo FlowDDA::processGepPts(const GepSVFGNode* gep, const PointsTo& srcPts) {
    PointsTo tmpDstPts;
    for (PointsTo::iterator piter = srcPts.begin(); piter != srcPts.end(); ++piter) {
        NodeID ptd = *piter;
        if (isBlkObjOrConstantObj(ptd))
            tmpDstPts.set(ptd);
        else {
            if (isa<VariantGepPE>(gep->getPAGEdge())) {
                setObjFieldInsensitive(ptd);
                tmpDstPts.set(getFIObjNode(ptd));
            }
            else if (const NormalGepPE* normalGep = dyn_cast<NormalGepPE>(gep->getPAGEdge())) {
                NodeID fieldSrcPtdNode = getGepObjNode(ptd,	normalGep->getLocationSet());
                tmpDstPts.set(fieldSrcPtdNode);
            }
            else
                assert(false && "new gep edge?");
        }
    }
    DBOUT(DDDA, outs() << "\t return created gep objs {");
    DBOUT(DDDA, analysisUtil::dumpSet(srcPts));
    DBOUT(DDDA, outs() << "} --> {");
    DBOUT(DDDA, analysisUtil::dumpSet(tmpDstPts));
    DBOUT(DDDA, outs() << "}\n");
    return tmpDstPts;
}

/// we exclude concrete heap here following the conditions:
/// (1) local allocated heap and
/// (2) not escaped to the scope outside the current function
/// (3) not inside loop
/// (4) not involved in recursion
bool FlowDDA::isHeapCondMemObj(const NodeID& var, const StoreSVFGNode* store)  {
    const MemObj* mem = _pag->getObject(getPtrNodeID(var));
    assert(mem && "memory object is null??");
    if(mem->isHeap()) {
//        if(const Instruction* mallocSite = dyn_cast<Instruction>(mem->getRefVal())) {
//            const Function* fun = mallocSite->getParent()->getParent();
//            const Function* curFun = store->getBB() ? store->getBB()->getParent() : NULL;
//            if(fun!=curFun)
//                return true;
//            if(_callGraphSCC->isInCycle(_callGraph->getCallGraphNode(fun)->getId()))
//                return true;
//            if(loopInfoBuilder.getLoopInfo(fun)->getLoopFor(mallocSite->getParent()))
//                return true;
//
//            return false;
//        }
        return true;
    }
    return false;
}
