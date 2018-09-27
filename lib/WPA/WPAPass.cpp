//===- WPAPass.cpp -- Whole program analysis pass------------------------------//
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
//===-----------------------------------------------------------------------===//

/*
 * @file: WPA.cpp
 * @author: yesen
 * @date: 10/06/2014
 * @version: 1.0
 *
 * @section LICENSE
 *
 * @section DESCRIPTION
 *
 */


#include "MemoryModel/PointerAnalysis.h"
#include "WPA/WPAPass.h"
#include "WPA/Andersen.h"
#include "WPA/FlowSensitive.h"

// Function pointer analysis
#include "WPA/FunctionPointerAnalysis.h"

// Liveness-based points-to analysis
#include "WPA/CallString.h"
#include "WPA/LivenessPointsTo.h"
#include "WPA/PointsToData.h"


#include "Util/AddressTakenAnalysis.h"
#include "Util/ReachingDefinitionAnalysis.h"
#include <llvm/Support/CommandLine.h>

using namespace llvm;

char WPAPass::ID = 0;

static RegisterPass<WPAPass> WHOLEPROGRAMPA("wpa",
        "Whole Program Pointer Analysis Pass");

/// register this into alias analysis group
///static RegisterAnalysisGroup<AliasAnalysis> AA_GROUP(WHOLEPROGRAMPA);

static cl::bits<PointerAnalysis::PTATY> PASelected(cl::desc("Select pointer analysis"),
        cl::values(
            clEnumValN(PointerAnalysis::Andersen_WPA, "nander", "Standard inclusion-based analysis"),
            clEnumValN(PointerAnalysis::AndersenLCD_WPA, "lander", "Lazy cycle detection inclusion-based analysis"),
            clEnumValN(PointerAnalysis::AndersenWave_WPA, "wander", "Wave propagation inclusion-based analysis"),
            clEnumValN(PointerAnalysis::AndersenWaveDiff_WPA, "ander", "Diff wave propagation inclusion-based analysis"),
            clEnumValN(PointerAnalysis::FSSPARSE_WPA, "fspta", "Sparse flow sensitive pointer analysis"),
            clEnumValN(PointerAnalysis::FUNCPTR_ANA, "fptrana", "Untra-fast function pointer analysis"),
            clEnumValN(PointerAnalysis::LIVENESS_PTA, "livepta", "liveness-based pointer analysis"),
            clEnumValEnd));


static cl::bits<WPAPass::AliasCheckRule> AliasRule(cl::desc("Select alias check rule"),
        cl::values(
            clEnumValN(WPAPass::Conservative, "conservative", "return MayAlias if any pta says alias"),
            clEnumValN(WPAPass::Veto, "veto", "return NoAlias if any pta says no alias"),
            clEnumValEnd));

cl::opt<bool> anderSVFG("svfg", cl::init(false),
                        cl::desc("Generate SVFG after Andersen's Analysis"));


static cl::opt<std::string> dumpCallers("dump-caller-for-func", cl::init(""),
        cl::desc("Dump the callers of a configured function"));


/*!
 * Destructor
 */
WPAPass::~WPAPass() {
    PTAVector::const_iterator it = ptaVector.begin();
    PTAVector::const_iterator eit = ptaVector.end();
    for (; it != eit; ++it) {
        PointerAnalysis* pta = *it;
        delete pta;
    }
    ptaVector.clear();
}

/*!
 * We start from here
 */
bool WPAPass::runOnModule(llvm::Module& module)
{
    /// initialization for llvm alias analyzer
    //InitializeAliasAnalysis(this, SymbolTableInfo::getDataLayout(&module));

    for (u32_t i = 0; i< PointerAnalysis::Default_PTA; i++) {
        if (PASelected.isSet(i))
            runPointerAnalysis(module, i);
    }
    return false;
}


/*!
 * Create pointer analysis according to a specified kind and then analyze the module.
 */
void WPAPass::runPointerAnalysis(llvm::Module& module, u32_t kind)
{

    //ReachingDefinitionAnalysis* dfa = nullptr;  // for testing
    /// Initialize pointer analysis.
    switch (kind) {
    case PointerAnalysis::Andersen_WPA:
        _pta = new Andersen();
        break;
    case PointerAnalysis::AndersenLCD_WPA:
        _pta = new AndersenLCD();
        break;
    case PointerAnalysis::AndersenWave_WPA:
        _pta = new AndersenWave();
        break;
    case PointerAnalysis::AndersenWaveDiff_WPA:
        _pta = new AndersenWaveDiff();
        break;
    case PointerAnalysis::FSSPARSE_WPA:
        _pta = new FlowSensitive();
        break;
    case PointerAnalysis::FUNCPTR_ANA:
        func_ptr_mode = true;
        _pta= new Andersen(); // TODO: we do not need to create this
        // TODO: fpa is now a module pass; we should not initialize it in this way
        _fpta = &getAnalysis<FunctionPointerAnalysis>();
        // fpa->buildCG();
        break;
    case PointerAnalysis::LIVENESS_PTA:
        func_ptr_mode = true;
        _pta= new Andersen(); // TODO: wo do not need to create this
        _livepta = new LivenessPointsTo();
        break;

    default:
        llvm::outs() << "This pointer analysis has not been implemented yet.\n";
        break;
    }

    //if (func_ptr_mode) return;

    if (_fpta) {
        _fpta->runOnModule(module);
    }

    ptaVector.push_back(_pta);
    if (_pta && !func_ptr_mode)
        _pta->analyze(module);
    if (anderSVFG) {
        SVFGBuilder memSSA(true);
        SVFG *svfg = memSSA.buildSVFG((BVDataPTAImpl*)_pta);
        svfg->dump("ander_svfg");
    }

#if 0

    if (dumpCallers != "") {
        Function* func = nullptr;
        for (Module::iterator FI = module.begin(), FE = module.end(); FI != FE; ++FI) {
            if (FI->getName() == dumpCallers) {
                func = FI;
            }
        }
        if (func) {
            llvm::outs() << "Find the configured function!!\n";
            AddressTakenAnalysis ata(module);
            if (!ata.isAddressTaken(func)) {
                for (Value::const_use_iterator I = func->use_begin(), E = func->use_end(); I != E; ++I) {
                    User *U = I->getUser ();
                    if (isa<CallInst>(U) || isa<InvokeInst>(U)) {
                        CallSite CS(cast<Instruction>(U));
                        llvm::outs() << " direct call targets!!!\n";
                        llvm::outs() << CS->getParent()->getParent()->getName() << "\n";
                    }
                }
            } else {
                //PTACallGraph* cg = _pta->getPTACallGraph();
                //PTACallGraphNode* node = cg->getCallGraphNode(func);
                const CallEdgeMap& callEdges = _pta->getIndCallMap();
                CallEdgeMap::const_iterator it = callEdges.begin();
                CallEdgeMap::const_iterator eit = callEdges.end();
                for (; it != eit; ++it) {
                    const llvm::CallSite CS = it->first;
                    const FunctionSet& targets = it->second;
                    for (const Function* f : targets) {
                        if (f == func) {
                            llvm::outs() << " indirect call targets!!!\n";
                            llvm::outs() << CS->getParent()->getParent()->getName() << "\n";
                        }
                    }
                }
            }
        }
    }
#endif
}



/*!
 * Return alias results based on our points-to/alias analysis
 * TODO: Need to handle PartialAlias and MustAlias here.
 */
AliasAnalysis::AliasResult WPAPass::alias(const Value* V1, const Value* V2) {

    AliasAnalysis::AliasResult result = MayAlias;

    PAG* pag = _pta->getPAG();

    /// TODO: When this method is invoked during compiler optimizations, the IR
    ///       used for pointer analysis may been changed, so some Values may not
    ///       find corresponding PAG node. In this case, we only check alias
    ///       between two Values if they both have PAG nodes. Otherwise, MayAlias
    ///       will be returned.
    if (pag->hasValueNode(V1) && pag->hasValueNode(V2)) {
        /// Veto is used by default
        if (AliasRule.getBits() == 0 || AliasRule.isSet(Veto)) {
            /// Return NoAlias if any PTA gives NoAlias result
            result = MayAlias;

            for (PTAVector::const_iterator it = ptaVector.begin(), eit = ptaVector.end();
                    it != eit; ++it) {
                if ((*it)->alias(V1, V2) == NoAlias)
                    result = NoAlias;
            }
        }
        else if (AliasRule.isSet(Conservative)) {
            /// Return MayAlias if any PTA gives MayAlias result
            result = NoAlias;

            for (PTAVector::const_iterator it = ptaVector.begin(), eit = ptaVector.end();
                    it != eit; ++it) {
                if ((*it)->alias(V1, V2) == MayAlias)
                    result = MayAlias;
            }
        }
    }

    return result;
}
