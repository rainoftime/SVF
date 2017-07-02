//===- UseAfterFreeChecker.cpp -- Use After Free detector ------------------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013-2016>  <Yulei Sui>
// Copyright (C) <2013-2016>  <Jingling Xue>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//===----------------------------------------------------------------------===//

/*
 * UseAfterFreeChecker.cpp
 *
 * Qingkai
 */

#include <llvm/Support/CommandLine.h>

#include "SABER/UseAfterFreeChecker.h"
#include "Util/AnalysisUtil.h"

using namespace llvm;
using namespace analysisUtil;

char UseAfterFreeChecker::ID = 0;

static RegisterPass<UseAfterFreeChecker> UAFCHECKER("uaf-checker", "Use After Free Checker");

/*!
 * Initialize sources
 */
void UseAfterFreeChecker::initSrcs() {
    PAG* G = getPAG();

    for(PAG::CSToArgsListMap::iterator It = G->getCallSiteArgsMap().begin(),
            E = G->getCallSiteArgsMap().end(); It != E; ++It) {
        const Function* F = getCallee(It->first);
        if(isSinkLikeFun(F)) {
            PAG::PAGNodeList& Arglist = It->second;
            assert(!Arglist.empty() && "no actual parameter at deallocation site?");
            const ActualParmSVFGNode* Src = getSVFG()->getActualParmSVFGNode(Arglist.front(),It->first);

            auto& OEs = Src->getOutEdges();
            assert(OEs.size() == 1);
            auto* Edge = *OEs.begin();
            assert(Edge->isCallDirectVFGEdge());

            addToSources(Src); // e.g., add p to sources if free(p)
            addSrcToEdge(Src, Edge);
        }
    }
}

/*!
 * Initialize sinks
 */
void UseAfterFreeChecker::initSnks() {
    // do nothing
}

void UseAfterFreeChecker::reportBug(ProgSlice* Slice) {
    // do nothing
}

bool UseAfterFreeChecker::runOnModule(llvm::Module& M) {
    CFGR = &this->getAnalysis<CFGReachabilityAnalysis>();
    initialize(M);

    for (SVFGNodeSetIter It = sourcesBegin(), E = sourcesEnd(); It != E; ++It) {
        const ActualParmSVFGNode* Src = dyn_cast<ActualParmSVFGNode>(*It);
        assert(Src);

        std::vector<const SVFGEdge*> Ctx;
        Ctx.push_back(SrcToCallEdgeMap[Src]);

        push();
        searchBackward(Src, nullptr, Ctx);
        pop();
    }

    finalize();
    return false;
}

void UseAfterFreeChecker::searchBackward(const SVFGNode* CurrNode, const SVFGNode* PrevNode, std::vector<const SVFGEdge*> Ctx) {
    if (Ctx.size() > ContextCond::getMaxCxtLen() + 1) {
        return;
    }

    SVFGPath.add(CurrNode);

    bool AllCalls = true;
    for (size_t I = 0; I < Ctx.size(); ++I) {
        if (!Ctx[I]->isCallVFGEdge()) {
            AllCalls = false;
            break;
        }
    }
    if (AllCalls) {
        push();
        std::vector<const SVFGEdge*> FCtx;

        assert(!Ctx.empty());
        assert(isa<CallDirSVFGEdge>(Ctx.back()));
        searchForward(CurrNode, PrevNode, FCtx,
                getSVFG()->getCallSite(((const CallDirSVFGEdge*)Ctx.back())->getCallSiteId()).getInstruction(), true);
        pop();
    }

    auto& InEdges = CurrNode->getInEdges();
    for(auto It = InEdges.begin(), E = InEdges.end(); It != E; ++It) {
        auto InEdge = *It;
        SVFGNode* Ancestor = InEdge->getSrcNode();
        assert(Ancestor != CurrNode);

        if (InEdge->isCallVFGEdge() || InEdge->isRetVFGEdge()) {
            if (!matchContextB(Ctx, InEdge)) {
                continue;
            }
        }

        push();
        searchBackward(Ancestor, CurrNode, Ctx);
        pop();
    }
}

void UseAfterFreeChecker::searchForward(const SVFGNode* CurrNode, const SVFGNode* PrevNode,
        std::vector<const SVFGEdge*> Ctx, Instruction* CS, bool TagX) {
    if (Ctx.size() > ContextCond::getMaxCxtLen()) {
        return;
    }

    if (SVFGPath.top() != CurrNode) {
        SVFGPath.add(CurrNode);
    }

    auto& OutEdges = CurrNode->getOutEdges();
    for(auto It = OutEdges.begin(), E = OutEdges.end(); It != E; ++It) {
        auto OutEdge = *It;
        SVFGNode* Child = OutEdge->getDstNode();
        if (Child == PrevNode)
            continue;

        if ((isa<LoadSVFGNode>(Child) || isa<StoreSVFGNode>(Child)) && TagX) {
            auto* Stmt = dyn_cast<StmtSVFGNode>(Child);
            auto* PAGE = Stmt->getPAGEdge();
            auto* Inst = PAGE->getInst();

            if (reachable(CS, Inst)) {
                push();
                SVFGPath.add(Child);
                reportBug();
                pop();
            }
        }

        bool Tag = true && TagX;
        if (OutEdge->isRetVFGEdge() || OutEdge->isCallVFGEdge()) {
            CallSiteID CSID = getCSID(OutEdge);
            CallSite CS2 = getSVFG()->getCallSite(CSID);

            // match ctx
            if (!matchContextF(Ctx, OutEdge)) {
                continue;
            }

            if (!reachable(CS, CS2.getInstruction())) {
                Tag = false;
            }
        }

        push();
        searchForward(Child, CurrNode, Ctx, CS, Tag);
        pop();
    }
}

bool UseAfterFreeChecker::matchContextB(std::vector<const SVFGEdge*>& Ctx, SVFGEdge* Edge) {
    if (!Ctx.empty()) {
        CallSiteID ID = getCSID(Edge);

        auto* Top = Ctx.back();
        CallSiteID TopID = getCSID(Top);

        if (ID == TopID) {
            if (Edge->isCallVFGEdge() != Top->isCallVFGEdge()) {
                Ctx.pop_back();
                return true;
            }
        } else {
            // if it is call and all call in Ctx
            if (Edge->isCallVFGEdge()) {
                bool AllCalls = true;
                for (size_t I = 0; I < Ctx.size(); ++I) {
                    if (!Ctx[I]->isCallVFGEdge()) {
                        AllCalls = false;
                        break;
                    }
                }

                if (AllCalls) {
                    Ctx.push_back(Edge);
                    return true;
                }
            } else {
                assert(Edge->isRetVFGEdge());
                Ctx.push_back(Edge);
                return true;
            }
        }
    } else {
        Ctx.push_back(Edge);
        return true;
    }

    return false;
}


bool UseAfterFreeChecker::matchContextF(std::vector<const SVFGEdge*>& Ctx, SVFGEdge* Edge) {
    if (!Ctx.empty()) {
        CallSiteID ID = getCSID(Edge);

        auto* Top = Ctx.back();
        CallSiteID TopID = getCSID(Top);

        if (ID == TopID) {
            if (Edge->isCallVFGEdge() != Top->isCallVFGEdge()) {
                Ctx.pop_back();
                return true;
            }
        } else {
            // if it is ret and all ret in Ctx
            if (Edge->isRetVFGEdge()) {
                bool AllRets = true;
                for (size_t I = 0; I < Ctx.size(); ++I) {
                    if (!Ctx[I]->isRetVFGEdge()) {
                        AllRets = false;
                        break;
                    }
                }

                if (AllRets) {
                    Ctx.push_back(Edge);
                    return true;
                }
            } else {
                assert(Edge->isCallVFGEdge());
                Ctx.push_back(Edge);
                return true;
            }
        }
    } else {
        Ctx.push_back(Edge);
        return true;
    }

    return false;
}

CallSiteID UseAfterFreeChecker::getCSID(const SVFGEdge* Edge) {
    CallSiteID ID;
    if (auto* X = dyn_cast<CallDirSVFGEdge>(Edge)) {
        ID = X->getCallSiteId();
    } else if (auto* Y = dyn_cast<CallIndSVFGEdge>(Edge)) {
        ID = Y->getCallSiteId();
    } else if (auto* Z = dyn_cast<RetIndSVFGEdge>(Edge)) {
        ID = Z->getCallSiteId();
    } else if (auto* W = dyn_cast<RetDirSVFGEdge>(Edge)) {
        ID = W->getCallSiteId();
    } else {
        assert(false);
    }
    return ID;
}

void UseAfterFreeChecker::reportBug() {
    static unsigned Index = 0;
    outs() << "+++++" << ++Index << "+++++\n";
    for(unsigned I = 0; I < SVFGPath.size(); ++I) {
        auto* N = SVFGPath[I];
        outs() << "[" << I << "] ";
        if (auto* X = dyn_cast<StmtSVFGNode>(N)) {
            outs() << *(X->getInst());
        } if (auto* X = dyn_cast<ActualParmSVFGNode>(N)) {
            outs() << *X->getCallSite().getInstruction();
        } else if (auto* X = dyn_cast<ActualINSVFGNode>(N)) {
            outs() << *X->getCallSite().getInstruction();
        } else if (auto* X = dyn_cast<ActualRetSVFGNode>(N)) {
            outs() << *X->getCallSite().getInstruction();
        } else if (auto* X = dyn_cast<ActualOUTSVFGNode>(N)) {
            outs() << *X->getCallSite().getInstruction();
        } else {
            outs() << N->getId();
        }

        outs() << "\n";
    }
    outs() << "\n";

}

bool UseAfterFreeChecker::reachable(const llvm::Instruction* From, const llvm::Instruction* To) {
    if (From->getParent()->getParent() != To->getParent()->getParent()) {
        return true;
    } else {
        return CFGR->isReachable(From, To);
    }
}
