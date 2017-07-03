//===- LeakChecker.h -- Detecting memory leaks--------------------------------//
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
 * UseAfterFreeChecker.h
 *
 * Qingkai
 */

#ifndef USEAFTERFREECHECKER_H_
#define USEAFTERFREECHECKER_H_

#include "SABER/SrcSnkDDA.h"
#include "SABER/SaberCheckerAPI.h"
#include "SABER/CFGReachabilityAnalysis.h"
#include "Util/PushPopCache.h"

/*!
 * Static Use After Free Detector
 */
class UseAfterFreeChecker : public SrcSnkDDA, public llvm::ModulePass {

public:
    typedef FIFOWorkList<llvm::CallSite> CSWorkList;
    typedef ProgSlice::VFWorkList WorkList;
    typedef NodeBS SVFGNodeBS;
    typedef PAG::CallSiteSet CallSiteSet;
    enum LEAK_TYPE {
        NEVER_FREE_LEAK,
        CONTEXT_LEAK,
        PATH_LEAK,
        GLOBAL_LEAK
    };

    /// Pass ID
    static char ID;

    /// Constructor
    UseAfterFreeChecker(char id = ID): ModulePass(ID), CFGR(nullptr) {
    }
    /// Destructor
    virtual ~UseAfterFreeChecker() {
    }

    /// We start from here
    virtual bool runOnModule(llvm::Module& module);

    /// Get pass name
    virtual const char* getPassName() const {
        return "Static Use After Free Detector";
    }

    /// Pass dependence
    virtual void getAnalysisUsage(llvm::AnalysisUsage& au) const {
        /// do not intend to change the IR in this pass,
        au.setPreservesAll();
        au.addRequired<CFGReachabilityAnalysis>();
    }

    /// Initialize sources and sinks
    //@{
    /// Initialize sources and sinks
    virtual void initSrcs();
    virtual void initSnks();
    /// Whether the function is a heap allocator/reallocator (allocate memory)
    virtual inline bool isSourceLikeFun(const llvm::Function* fun) {
        return SaberCheckerAPI::getCheckerAPI()->isMemAlloc(fun);
    }
    /// Whether the function is a heap deallocator (free/release memory)
    virtual inline bool isSinkLikeFun(const llvm::Function* fun) {
        return SaberCheckerAPI::getCheckerAPI()->isMemDealloc(fun);
    }

    virtual bool isSouce(const SVFGNode* node){
        assert(false);
        return false;
    }
    virtual bool isSink(const SVFGNode* node){
        assert(false);
        return false;
    }
    //@}

protected:
    /// Get PAG
    PAG* getPAG() const {
        return PAG::getPAG();
    }
    /// Report uaf
    //@{
    virtual void reportBug(ProgSlice* slice);
    //@}

    /// Record a source to its callsite
    //@{
    inline void addSrcToEdge(const SVFGNode* Src, const SVFGEdge* Edge) {
        SrcToCallEdgeMap[Src] = Edge;
    }
    //@}

private:
    std::map<const SVFGNode*, const SVFGEdge*> SrcToCallEdgeMap;

    CFGReachabilityAnalysis* CFGR;

    PushPopVector<const SVFGNode*> SVFGPath;

    void searchBackward(const SVFGNode*, const SVFGNode*, std::vector<const SVFGEdge*>);

    void searchForward(const SVFGNode*, const SVFGNode*, std::vector<const SVFGEdge*>, llvm::Instruction*, bool);

    void push() {
        SVFGPath.push();
    }

    void pop() {
        SVFGPath.pop();
    }

    bool matchContextB(std::vector<const SVFGEdge*>& Ctx, SVFGEdge* Edge);
    bool matchContextF(std::vector<const SVFGEdge*>& Ctx, SVFGEdge* Edge);

    CallSiteID getCSID(const SVFGEdge*);

    void reportBug(const Instruction*);

    bool reachable(const llvm::Instruction*, const llvm::Instruction*);

    void printContextStack(std::vector<const SVFGEdge*>&);
};

#endif /* USEAFTERFREECHECKER_H_ */
