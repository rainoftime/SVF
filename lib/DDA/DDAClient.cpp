/*
 * @file: DDAClient.cpp
 * @author: yesen
 * @date: 16 Feb 2015
 *
 * LICENSE
 *
 */


#include "DDA/DDAClient.h"
#include "DDA/FlowDDA.h"
#include <iostream>
#include <iomanip>	// for std::setw
#include <llvm/Support/CommandLine.h> // for tool output file
#include <time.h>
#include <chrono>

using namespace llvm;
using namespace analysisUtil;

static cl::opt<bool> SingleLoad("single-load", cl::init(true),
                                cl::desc("Count load pointer with same source operand as one query"));

static cl::opt<bool> DumpFree("dump-free", cl::init(false),
                              cl::desc("Dump use after free locations"));

static cl::opt<bool> DumpUninitVar("dump-uninit-var", cl::init(false),
                                   cl::desc("Dump uninitialised variables"));

static cl::opt<bool> DumpUninitPtr("dump-uninit-ptr", cl::init(false),
                                   cl::desc("Dump uninitialised pointers"));

static cl::opt<bool> DumpSUPts("dump-su-pts", cl::init(false),
                               cl::desc("Dump strong updates store"));

static cl::opt<bool> DumpSUStore("dump-su-store", cl::init(false),
                                 cl::desc("Dump strong updates store"));

static cl::opt<bool> MallocOnly("malloc-only", cl::init(true),
                                cl::desc("Only add tainted objects for malloc"));

static cl::opt<bool> TaintUninitHeap("uninit-heap", cl::init(true),
                                     cl::desc("detect uninitialized heap variables"));

static cl::opt<bool> TaintUninitStack("uninit-stack", cl::init(true),
                                      cl::desc("detect uninitialized stack variables"));


void DDAClient::answerQueries(PointerAnalysis* pta) {

    collectCandidateQueries(pta->getPAG());
    if (queryAliasPair) {
        std::chrono::high_resolution_clock::time_point ItStart = std::chrono::high_resolution_clock::now();
        // Print the queries
        for (auto& Query : DDASourceDstMap) {
            llvm::Value* Src = Query.first;
            std::vector<llvm::Value*> Dsts = Query.second;
            for (unsigned I = 0; I < Dsts.size(); I++) {
                Value *DstI = Dsts[I];
                NodeID srcId = pag->getValueNode(Src);
                NodeID dstIId = pag->getValueNode(DstI);
                if (pag->isValidTopLevelPtr(pag->getPAGNode(srcId)) &&
                        pag->isValidTopLevelPtr(pag->getPAGNode(dstIId))) {

                    std::pair<bool, bool> res = pta->computeDDAMayAlias(srcId, dstIId);
                    if (!res.first) {
                        AnderSourceDstResult[Src][I] = false;
                    }
                    if (!res.second) {
                        DDASourceDstResult[Src][I] = false;
                    }

                    // pta->getAndersenAnalysis();
                }
            }
        }
        std::chrono::high_resolution_clock::time_point ItFinish = std::chrono::high_resolution_clock::now();
        auto Duration = std::chrono::duration_cast<std::chrono::microseconds> (ItFinish-ItStart).count();

        return;
    }

    u32_t count = 0;
    for (NodeBS::iterator nIter = candidateQueries.begin();
            nIter != candidateQueries.end(); ++nIter,++count) {
        PAGNode* node = pta->getPAG()->getPAGNode(*nIter);
        if(pta->getPAG()->isValidTopLevelPtr(node)) {
            DBOUT(DGENERAL,outs() << "\n@@Computing PointsTo for :" << node->getId() <<
                  " [" << count + 1<< "/" << candidateQueries.count() << "]" << " \n");
            DBOUT(DDDA,outs() << "\n@@Computing PointsTo for :" << node->getId() <<
                  " [" << count + 1<< "/" << candidateQueries.count() << "]" << " \n");
            setCurrentQueryPtr(node->getId());


            if (queryAliasSet) {
                // answer alias set: currently for taint client
                std::pair<unsigned, unsigned> size = pta->computeDDAAliaseSet(node->getId());
                const llvm::Value* val = node->getValue();
                setQueryAliasSetSize(val, size);
            } else {
                pta->computeDDAPts(node->getId());
            }
        }
    }
}

void FunptrDDAClient::performStat(PointerAnalysis* pta) {
    llvm::outs() << "Print stat for demand driven analysis!\n";
    // It seems SUPA will combine the results of anderPts and ddaPts,
    // and only print virtual table results.
#if 0
    AndersenWaveDiff* ander = AndersenWaveDiff::createAndersenWaveDiff(pta->getModuleRef());

    u32_t totalCallsites = 0;
    u32_t morePreciseCallsites = 0;
    u32_t zeroTargetCallsites = 0;
    u32_t oneTargetCallsites = 0;
    u32_t twoTargetCallsites = 0;
    u32_t moreThanTwoCallsites = 0;

    for (VTablePtrToCallSiteMap::iterator nIter = vtableToCallSiteMap.begin();
            nIter != vtableToCallSiteMap.end(); ++nIter) {
        NodeID vtptr = nIter->first;
        const PointsTo& ddaPts = pta->getPts(vtptr);
        const PointsTo& anderPts = ander->getPts(vtptr);

        PTACallGraph* callgraph = ander->getPTACallGraph();
        if(!callgraph->hasIndCSCallees(nIter->second)) {
            //outs() << "virtual callsite has no callee" << *(nIter->second.getInstruction()) << "\n";
            continue;
        }

        const PTACallGraph::FunctionSet& callees = callgraph->getIndCSCallees(nIter->second);
        totalCallsites++;
        if(callees.size() == 0)
            zeroTargetCallsites++;
        else if(callees.size() == 1)
            oneTargetCallsites++;
        else if(callees.size() == 2)
            twoTargetCallsites++;
        else
            moreThanTwoCallsites++;

        if (ddaPts.count() >= anderPts.count() || ddaPts.empty())
            continue;

        std::set<const Function*> ander_vfns;
        std::set<const Function*> dda_vfns;
        ander->getVFnsFromPts(nIter->second,anderPts, ander_vfns);
        pta->getVFnsFromPts(nIter->second,ddaPts, dda_vfns);

        ++morePreciseCallsites;
        outs() << "============more precise callsite =================\n";
        outs() << *(nIter->second).getInstruction() << "\n";
        outs() << getSourceLoc((nIter->second).getInstruction()) << "\n";
        outs() << "\n";
        outs() << "------ander pts or vtable num---(" << anderPts.count()  << ")--\n";
        outs() << "------DDA vfn num---(" << ander_vfns.size() << ")--\n";
        //ander->dumpPts(vtptr, anderPts);
        outs() << "------DDA pts or vtable num---(" << ddaPts.count() << ")--\n";
        outs() << "------DDA vfn num---(" << dda_vfns.size() << ")--\n";
        //pta->dumpPts(vtptr, ddaPts);
        outs() << "-------------------------\n";
        outs() << "\n";
        outs() << "=================================================\n";
    }

    outs() << "=================================================\n";
    outs() << "Total virtual callsites: " << vtableToCallSiteMap.size() << "\n";
    outs() << "Total analyzed virtual callsites: " << totalCallsites << "\n";
    outs() << "Indirect call map size: " << ander->getPTACallGraph()->getIndCallMap().size() << "\n";
    outs() << "Precise callsites: " << morePreciseCallsites << "\n";
    outs() << "Zero target callsites: " << zeroTargetCallsites << "\n";
    outs() << "One target callsites: " << oneTargetCallsites << "\n";
    outs() << "Two target callsites: " << twoTargetCallsites << "\n";
    outs() << "More than two target callsites: " << moreThanTwoCallsites << "\n";
    outs() << "=================================================\n";
#else
    int CG_BUCKET_NUMBER = 11;
    int cg_bucket[11] = { 0 };
    int cg_bucket_steps[11] = { 0, 1, 2, 3, 4, 5, 6, 7, 10, 30, 100 };
 
    llvm::outs() << "==================Function Pointer Targets==================\n";
    const CallEdgeMap& callEdges = pta->getIndCallMap();
    if (callEdges.size() == 0) llvm::outs() << "CallEdgeMap is empty\n";
    CallEdgeMap::const_iterator it = callEdges.begin();
    CallEdgeMap::const_iterator eit = callEdges.end();
    for (; it != eit; ++it) {
        const llvm::CallSite cs = it->first;
        const FunctionSet& targets = it->second;
        int cg_resolve_size = targets.size();
        int i;
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

    const CallSiteToFunPtrMap& indCS = pta->getIndirectCallsites();
    CallSiteToFunPtrMap::const_iterator csIt = indCS.begin();
    CallSiteToFunPtrMap::const_iterator csEit = indCS.end();
    int cg_zero = 0;
    for (; csIt != csEit; ++csIt) {
        const llvm::CallSite& cs = csIt->first;
        if (pta->hasIndCSCallees(cs) == false) {
            // do not consider inline asm now
            if (!isa<InlineAsm>(cs.getCalledValue())) {
                cg_zero++;
                Function* f = cs->getParent()->getParent();
                llvm::outs() << f->getName() << ": a call site unresolved\n";
                cs->dump();
            }
        }
    }

    cg_bucket[0] = cg_zero;

    llvm::outs() << "\n";
    llvm::outs() << "---------------CG Resolution Statistics Begin-------------------------\n";
    outs() << "\n";

    int i;
    for (i = 0; i < CG_BUCKET_NUMBER - 1; i++) {
        if (cg_bucket_steps[i] == cg_bucket_steps[i + 1] - 1)
            llvm::outs() << "\t" << cg_bucket_steps[i] << ":\t\t";
        else
            llvm::outs() << "\t" << cg_bucket_steps[i] << " - " << cg_bucket_steps[i + 1] - 1 << ": \t\t";
        llvm::outs() << cg_bucket[i] << "\n";
    }
    llvm::outs() << "\t>" << cg_bucket_steps[i] << ": \t\t";
    llvm::outs() << cg_bucket[i] << "\n";
    llvm::outs() << "\n";
    llvm::outs() << "---------------CG Resolution Statistics End-------------------------\n";
#endif
}



void TaintDDAClient::performStat(PointerAnalysis* pta) {  

    int dda_total_sz = 0, ander_total_sz = 0;
    int query_num = DDAAliasSetSize.size();
    for (unsigned i = 0; i < DDAAliasSetSize.size(); i++) {
        dda_total_sz += DDAAliasSetSize[i].second;
        ander_total_sz += AndersenAliasSetSize[i].second;
    }

    llvm::outs() << "-----Demand-Driven Alias Set Analysis Statistics Begin------\n";

    llvm::outs() <<     "==== Query Number: ==== " << query_num << "\n";
    if (query_num > 0) {
        llvm::outs() << "==== Andersen Average Size: ==== " << ander_total_sz / query_num << "\n";
        llvm::outs() << "==== DDA Average Size:      ==== " << dda_total_sz / query_num << "\n";
    }

    llvm::outs() << "----- Demand-Driven Alias Set Analysis Statistics End------\n";
}



void SecurityDDAClient::performStat(PointerAnalysis* pta) {
    int totalQuery = 0;
    int totalAnderNotAlias = 0;
    int totalDDANotAlias = 0;
    // Print the queries
    for (auto& Query : DDASourceDstMap) {
        llvm::Value* Src = Query.first;
        std::vector<llvm::Value*> Dsts = Query.second;
        for (unsigned I = 0; I < Dsts.size(); I++) {
            totalQuery++;
            if (!AnderSourceDstResult[Src][I]) totalAnderNotAlias++;
            if (!DDASourceDstResult[Src][I]) totalDDANotAlias++;
        }
    }
    llvm::outs() << "-----Demand-Driven Alias Pair Analysis Statistics Begin------\n";
    llvm::outs() << "==== Query Number: ==== " << totalQuery << "\n"; 
    llvm::outs() << "==== Andersen not alias: ==== " << totalAnderNotAlias << "\n";
    llvm::outs() << "==== DDA not alias: ==== " << totalDDANotAlias << "\n"; 

    llvm::outs() << "-----Demand-Driven Alias Pair Analysis Statistics End------\n";
}


