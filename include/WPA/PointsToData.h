/*
 * PointsToData.h
 *
 *  Created on: 2018年8月25日
 *      Author: rainoftime
 */

#ifndef POINTSTODATA_H_
#define POINTSTODATA_H_

#include <set>
#include <tuple>
#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/Function.h"

#include "WPA/CallString.h"
#include "WPA/LivenessSet.h"
#include "WPA/PointsToNode.h"
#include "WPA/PointsToRelation.h"

using namespace llvm;

typedef std::tuple<CallInst *, Function *, PointsToRelation *, LivenessSet, bool> CallData;
typedef DenseMap<const Instruction *, std::pair<LivenessSet *, PointsToRelation *>> IntraproceduralPointsTo;
typedef SmallVector<std::tuple<CallString, IntraproceduralPointsTo *, PointsToRelation, LivenessSet>, 8> ProcedurePointsTo;

bool arePointsToMapsEqual(const Function *F, IntraproceduralPointsTo *a, IntraproceduralPointsTo &b);
IntraproceduralPointsTo copyPointsToMap(IntraproceduralPointsTo *);

class PointsToData {
    public:
        PointsToData() {}
        ProcedurePointsTo *getAtFunction(const Function *) const;
        IntraproceduralPointsTo *getPointsTo(const CallString &, const Function *, PointsToRelation &, LivenessSet &, bool &);
        bool attemptMakeCyclicCallString(const Function *, const CallString &, IntraproceduralPointsTo *);
        bool hasDataForFunction(const Function *) const;
        IntraproceduralPointsTo *get(const Function *, const CallString &) const;
    private:
        DenseMap<const Function *, ProcedurePointsTo *> data;
};


#endif /* POINTSTODATA_H_ */
