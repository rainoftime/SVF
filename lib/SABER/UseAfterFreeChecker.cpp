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
#include <llvm/Support/Debug.h>

#include "SABER/UseAfterFreeChecker.h"
#include "Util/AnalysisUtil.h"

#define DEBUG_TYPE "uaf"

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
        if(isSinkLikeFun(F) && F->empty()) {
            PAG::PAGNodeList& Arglist = It->second;
            assert(!Arglist.empty() && "no actual parameter at deallocation site?");
            ActualParmSVFGNode* Src = getSVFG()->getActualParmSVFGNode(Arglist.front(),It->first);

            addToSources(Src); // e.g., add p to sources if free(p)
            addSrcToEdge(Src, new CallDirSVFGEdge(Src, nullptr, getSVFG()->getCallSiteID(Src->getCallSite(), F)));
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


        DEBUG(errs() << "Start.... " << Src->getId() << "\n");

        push();
        searchBackward(Src, nullptr, Ctx);
        pop();
    }

    finalize();
    std::string filename("svfg.dot");
    const_cast<SVFG*>(getSVFG())->dump(filename);
    return false;
}

void UseAfterFreeChecker::searchBackward(const SVFGNode* CurrNode, const SVFGNode* PrevNode, std::vector<const SVFGEdge*> Ctx) {
    if (Ctx.size() > ContextCond::getMaxCxtLen() + 1) {
        return;
    }

    DEBUG(errs() << "VisitingB " << CurrNode->getId() << "\n");

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
            bool match = matchContextB(Ctx, InEdge);
            DEBUG_WITH_TYPE("bctx", printContextStack(Ctx));
            if (!match) {
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

    if (PrevNode)
        DEBUG(errs() << "VisitingF " << CurrNode->getId() << ", Prev: " << PrevNode->getId() << "\n");
    else
        DEBUG(errs() << "VisitingF " << CurrNode->getId() << ", Prev: Null\n");

    if (SVFGPath.top() != CurrNode) {
        SVFGPath.add(CurrNode);
    }


    if (auto* StmtNode = dyn_cast<StmtSVFGNode>(CurrNode)) {
        auto* PAGE = StmtNode->getPAGEdge();
        auto* Inst = PAGE->getInst();
        if(!Inst->getType()->isVoidTy())
            for (auto It = Inst->user_begin(), E = Inst->user_end(); It != E; ++It) {
                auto User = dyn_cast<Instruction>(*It);
                if (!User)
                    continue;

                bool report = false;
                if (auto* X = dyn_cast<LoadInst>(User)) {
                    report = X->getPointerOperand() == Inst;
                } else if (auto* X = dyn_cast<StoreInst>(User)) {
                    report = X->getPointerOperand() == Inst;
                } else if (auto* X = dyn_cast<CallInst>(User)) {
                    if (X->getCalledFunction() && isSinkLikeFun(X->getCalledFunction())) {
                        report = X->getArgOperand(0) == Inst;
                    }
                }

                if (report && reachable(CS, Inst)) {
                    reportBug(User);
                }
            }
    }

    auto& OutEdges = CurrNode->getOutEdges();
    for(auto It = OutEdges.begin(), E = OutEdges.end(); It != E; ++It) {
        auto OutEdge = *It;
        SVFGNode* Child = OutEdge->getDstNode();
        if (Child == PrevNode)
            continue;

        bool Tag = true && TagX;
        if (OutEdge->isRetVFGEdge() || OutEdge->isCallVFGEdge()) {
            CallSiteID CSID = getCSID(OutEdge);
            CallSite CS2 = getSVFG()->getCallSite(CSID);

            if (CS2.getInstruction() == CS) {
                continue;
            }

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
                DEBUG_WITH_TYPE("bctx", errs() << "Pop back visiting " <<
                        getSourceLoc(getSVFG()->getCallSite(ID).getInstruction()));
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

                if (AllCalls && Edge->getDstNode()->getBB()->getParent()
                        == Top->getSrcNode()->getBB()->getParent()) {
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

                if (AllRets && Top->getDstNode()->getBB()->getParent()
                        == Edge->getSrcNode()->getBB()->getParent()) {
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

void UseAfterFreeChecker::reportBug(const Instruction* TailInst) {
    static unsigned Index = 0;
    outs() << "+++++" << ++Index << "+++++\n";
    for(unsigned I = 0; I < SVFGPath.size(); ++I) {
        auto* N = SVFGPath[I];
        outs() << "[" << I << "] ";
        const Instruction* Inst = nullptr;
        if (auto* X = dyn_cast<StmtSVFGNode>(N)) {
            Inst = (X->getInst());
        } if (auto* X = dyn_cast<ActualParmSVFGNode>(N)) {
            Inst = X->getCallSite().getInstruction();
        } else if (auto* X = dyn_cast<ActualINSVFGNode>(N)) {
            Inst = X->getCallSite().getInstruction();
        } else if (auto* X = dyn_cast<ActualRetSVFGNode>(N)) {
            Inst = X->getCallSite().getInstruction();
        } else if (auto* X = dyn_cast<ActualOUTSVFGNode>(N)) {
            Inst = X->getCallSite().getInstruction();
        }

        if (Inst) {
            outs() << N->getId() << " (" << Inst->getParent()->getParent()->getName() << ") \t" << " " << *Inst;
        } else {
            outs() << N->getId() << " (" << N->getBB()->getParent()->getName() << ") ";
        }
        outs() << "\n";
    }
    outs() << "[" << SVFGPath.size() << "] ";
    outs() << "XX (" << TailInst->getParent()->getParent()->getName() << ") \t" << *TailInst;
    outs() << "\n\n";

}

bool UseAfterFreeChecker::reachable(const llvm::Instruction* From, const llvm::Instruction* To) {
    if (From->getParent()->getParent() != To->getParent()->getParent()) {
        return true;
    } else {
        return CFGR->isReachable(From, To) && From != To;
    }
}

void UseAfterFreeChecker::printContextStack(std::vector<const SVFGEdge*>& Ctx) {
    outs() << "+++++++++++++++++++++++++\n";
    for (auto* Edge : Ctx) {
        bool Call = Edge->isCallVFGEdge();
        CallSiteID Id = getCSID(Edge);
        CallSite CS = getSVFG()->getCallSite(Id);
        if (Call)
            outs() << "+ Call to ";
        else
            outs() << "+ Retn fm ";
        outs() << CS.getCalledFunction()->getName();
        outs() << " at Line " << getSourceLoc(CS.getInstruction()) << "\n";
    }
    outs() << "+++++++++++++++++++++++++\n";
}
