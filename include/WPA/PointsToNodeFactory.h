/*
 * PointsToNodeFactory.h
 *
 *  Created on: 2018年8月25日
 *      Author: rainoftime
 */

#ifndef POINTSTONODEFACTORY_H_
#define POINTSTONODEFACTORY_H_

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Value.h"

#include "WPA/PointsToNode.h"

class PointsToNodeFactory {
    private:
        DenseMap<const Value *, PointsToNode *> map;
        DenseMap<const Value *, PointsToNode *> noAliasMap;
        DenseMap<const GlobalObject *, PointsToNode *> globalMap;
        UnknownPointsToNode unknown;
        InitPointsToNode init;
        bool matchGEPNode(const GEPOperator *, const PointsToNode *) const;
        PointsToNode *getGEPNode(const GEPOperator *, const Type *Type, PointsToNode *, PointsToNode *) const;
    public:
        PointsToNode *getUnknown();
        PointsToNode *getInit();
        PointsToNode *getNode(const Value *);
        PointsToNode *getNoAliasNode(const AllocaInst *);
        PointsToNode *getNoAliasNode(const CallInst *);
        PointsToNode *getGlobalNode(const GlobalObject *);
        PointsToNode *getIndexedNode(PointsToNode *, const GEPOperator *);
};


#endif /* POINTSTONODEFACTORY_H_ */
