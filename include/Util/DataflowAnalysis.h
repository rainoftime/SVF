#ifndef LLVM_DATAFLOW_ANALYSIS_H
#define LLVM_DATAFLOW_ANALYSIS_H

#include "llvm/InitializePasses.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include <deque>
#include <map>
#include <memory>
#include <utility>
#include <vector>
#include <set>

namespace llvm {

class AnalysisInfo {
 public:
  AnalysisInfo() { }
  virtual ~AnalysisInfo() { }

  virtual void Print() = 0;
  static bool Equals(const AnalysisInfo*, const AnalysisInfo*);
  static std::unique_ptr<AnalysisInfo> Join(const AnalysisInfo*, const AnalysisInfo*);
};

template <typename Info, bool Direction>
class MyDataFlowAnalysis {
 protected:
  typedef std::pair<int, int> Edge; // <node id, edge id>.

  std::vector<Instruction*> insts_;
  std::map<Instruction*, int> inst_map_;

  std::vector<Info> edges_;
  std::map<int, std::vector<Edge>> in_edges_;
  std::map<int, std::vector<Edge>> out_edges_;
  std::map<int, std::set<int>> existing_edges_;

  Info bottom_;
  Info initial_state_;
  Instruction* entry_inst_;

  void AssignIndexToInst(Function* F) {
    int cnt = 1, i = 1;

    for (inst_iterator inst_it = inst_begin(F), inst_e = inst_end(F);
         inst_it != inst_e; ++inst_it) {
      cnt += 1;
    }
    insts_.resize(cnt);

    inst_map_[nullptr] = 0;
    insts_[0] = nullptr;

    for (inst_iterator inst_it = inst_begin(F), inst_e = inst_end(F);
         inst_it != inst_e; ++inst_it) {
      Instruction* inst = &*inst_it;
      inst_map_[inst] = i;
      insts_[i] = inst;
      i += 1;
    }
  }

  void AddEdge(Instruction* src, Instruction* dst, const Info& e) {
    std::map<Instruction*, int>::iterator src_it = inst_map_.find(src);
    std::map<Instruction*, int>::iterator dst_it = inst_map_.find(dst);

    if (src_it == inst_map_.end() || dst_it == inst_map_.end()) {
      return;
    }

    int src_index = src_it->second, dst_index = dst_it->second;
    int new_index = edges_.size();

    if (existing_edges_[src_index].count(dst_index)) {
      return;
    }
    existing_edges_[src_index].insert(dst_index);

    edges_.push_back(e);
    in_edges_[dst_index].push_back(std::make_pair(src_index, new_index));
    out_edges_[src_index].push_back(std::make_pair(dst_index, new_index));
  }

  void InitializeForwardMap(Function* F) {
    AssignIndexToInst(F);

    for (Function::iterator blk_it = F->begin(), blk_e = F->end();
         blk_it != blk_e; ++blk_it) {
      BasicBlock* block = &*blk_it;
      Instruction* first_inst = &(block->front());

      // Initialize incoming edges to the basic block.
      for (auto pred_it = pred_begin(block), pred_e = pred_end(block);
           pred_it != pred_e; ++pred_it) {
        BasicBlock* prev = *pred_it;
        Instruction* src = (Instruction*) prev->getTerminator();
        Instruction* dst = first_inst;
        AddEdge(src, dst, bottom_);
      }

      // If there is at least one phi node, add an edge from the first phi node
      // to the first non-phi node instruction in the basic block.
      if (isa<PHINode>(first_inst)) {
        AddEdge(first_inst, block->getFirstNonPHI(), bottom_);
      }

      // Initialize edges within the basic block.
      for (auto inst_it = block->begin(), inst_e = block->end();
           inst_it != inst_e; ++inst_it) {
        Instruction* inst = &*inst_it;
        if (isa<PHINode>(inst)) {
          continue;
        }
        if (inst == (Instruction *) block->getTerminator()) {
          break;
        }
        Instruction* next = inst->getNextNode();
        AddEdge(inst, next, bottom_);
      }

      // Initialize outgoing edges of the basic block.
      Instruction* term = (Instruction *) block->getTerminator();
      for (auto succ_it = succ_begin(block), succ_e = succ_end(block);
           succ_it != succ_e; ++succ_it) {
        BasicBlock* succ = *succ_it;
        Instruction* next = &(succ->front());
        AddEdge(term, next, bottom_);
      }
    }

    entry_inst_ = (Instruction *) &((F->front()).front());
    AddEdge(nullptr, entry_inst_, initial_state_);
  }

  void InitializeBackwardMap(Function* F) {
    AssignIndexToInst(F);

    for (Function::iterator blk_it = F->begin(), blk_e = F->end();
         blk_it != blk_e; ++blk_it) {
      BasicBlock* block = &*blk_it;

      Instruction* first_inst = &(block->front());

      // Initialize outgoing edges to the basic block.
      for (auto pred_it = pred_begin(block), pred_e = pred_end(block);
           pred_it != pred_e; ++pred_it) {
        BasicBlock* prev = *pred_it;
        Instruction* dst = (Instruction*) prev->getTerminator();
        Instruction* src = first_inst;
        AddEdge(src, dst, bottom_);
      }

      // If there is at least one phi node, add an edge from the first non-phi node instruction
      // in the basic block to the first phi node.
      if (isa<PHINode>(first_inst)) {
        AddEdge(block->getFirstNonPHI(), first_inst, bottom_);
      }

      // Initialize edges within the basic block.
      for (auto inst_it = block->begin(), inst_e = block->end();
           inst_it != inst_e; ++inst_it) {
        Instruction* inst = &*inst_it;
        if (isa<PHINode>(inst)) {
          continue;
        }
        if (inst == block->getTerminator()) {
          break;
        }
        Instruction* next = inst->getNextNode();
        AddEdge(next, inst, bottom_);
      }

      // Initialize incoming edges of the basic block.
      Instruction* term = (Instruction *) block->getTerminator();
      for (auto succ_it = succ_begin(block), succ_e = succ_end(block);
           succ_it != succ_e; ++succ_it) {
        BasicBlock* succ = *succ_it;
        Instruction* next = &(succ->front());
        AddEdge(next, term, bottom_);
      }
    }

    entry_inst_ = F->back().getTerminator();
    AddEdge(nullptr, entry_inst_, initial_state_);
  }

  virtual void FlowFunction(
      Instruction* I,                /* instruction */
      int inst_index,                /* instruction index */
      const Info& in,                /* joined input */
      const std::vector<Edge>& outs, /* outgoing edges */
      std::vector<Info>& infos       /* output */
  ) const = 0;

 public:
  MyDataFlowAnalysis(const Info& bottom, const Info& initial_state)
    : bottom_(bottom), initial_state_(initial_state), entry_inst_(nullptr) { }

  virtual ~MyDataFlowAnalysis() { }

  void Print() {
    for (std::map<int, std::vector<Edge>>::iterator it = out_edges_.begin();
         it != out_edges_.end(); ++it) {
      for (const Edge& e : it->second) {
        errs() << "Edge " << it->first << "->" "Edge " << e.first << ":";
        edges_[e.second].Print();
      }
    }
  }

  void RunWorklistAlgorithm(Function* F) {
    std::deque<int> worklist;

    // Initialize info of each edge to bottom.
    if (Direction) {
      InitializeForwardMap(F);
    } else {
      InitializeBackwardMap(F);
    }

    assert(entry_inst_ != nullptr);

    // Initialize the work list.
    for (size_t i = 1; i < insts_.size(); ++i) {
      worklist.push_back(i);
    }

    // Compute until the work list is empty.
    std::vector<Info> newly_computed;

    while (!worklist.empty()) {
      int cur = worklist.front();
      Instruction* inst = insts_[cur];
      const std::vector<Edge> ins = in_edges_[cur];
      const std::vector<Edge> outs = out_edges_[cur];

      worklist.pop_front();
      assert(inst != nullptr);

      // Join all inputs before passing into flow function.
      std::unique_ptr<Info> joined(new Info());
      for (size_t i = 0; i < ins.size(); ++i) {
        joined = Info::Join(joined.get(), &edges_[ins[i].second]);
      }

      FlowFunction(inst, cur, *joined, outs, newly_computed);
      assert(newly_computed.size() == outs.size());

      for (size_t i = 0; i < newly_computed.size(); ++i) {
        Info* old_info = &edges_[outs[i].second];
        std::unique_ptr<Info> new_info = Info::Join(old_info, &newly_computed[i]);

        if (!Info::Equals(old_info, new_info.get())) {
          edges_[outs[i].second] = std::move(*new_info.release());
          worklist.push_back(outs[i].first);
        }
      }
    }
  }
};

}

#endif
