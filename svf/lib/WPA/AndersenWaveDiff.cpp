//===- AndersenWaveDiff.cpp -- Wave propagation based Andersen's analysis with caching--//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013-2017>  <Yulei Sui>
//

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
//===--------------------------------------------------------------------------------===//

/*
 * AndersenWaveDiff.cpp
 *
 *  Created on: 23/11/2013
 *      Author: yesen
 */

#include "WPA/Andersen.h"

using namespace SVFUtil;
// #define DEBUG 1

AndersenWaveDiff* AndersenWaveDiff::diffWave = NULL;

/*!
 * solve worklist
 */
void AndersenWaveDiff::solveWorklist() {
    // Initialize the nodeStack via a whole SCC detection
    // Nodes in nodeStack are in topological order by default.
    NodeStack& nodeStack = SCCDetect();

    // Process nodeStack and put the changed nodes into workList.
    while (!nodeStack.empty()) {
        NodeID nodeId = nodeStack.top();
        nodeStack.pop();
        collapsePWCNode(nodeId);
        // process nodes in nodeStack
        processNode(nodeId);
        // collapseFields();
    }

    // This modification is to make WAVE feasible to handle PWC analysis
    if (!mergePWC()) {
        NodeStack tmpWorklist;
        while (!isWorklistEmpty()) {
            NodeID nodeId = popFromWorklist();
            collapsePWCNode(nodeId);
            // process nodes in nodeStack
            processNode(nodeId);
            // collapseFields();
            tmpWorklist.push(nodeId);
        }
        while (!tmpWorklist.empty()) {
            NodeID nodeId = tmpWorklist.top();
            tmpWorklist.pop();
            pushIntoWorklist(nodeId);
        }
    }

    // New nodes will be inserted into workList during processing.
    while (!isWorklistEmpty()) {
        NodeID nodeId = popFromWorklist();
        // process nodes in worklist
        postProcessNode(nodeId);
    }
}

/*!
 * Process edge PAGNode
 */
void AndersenWaveDiff::processNode(NodeID nodeId) {
    // This node may be merged during collapseNodePts() which means it is no longer a rep node
    // in the graph. Only rep node needs to be handled.
#ifdef DEBUG
    llvm::outs() << "ProcessNode :" << nodeId << "\n";
    // getPts(7210);
#endif
    if (sccRepNode(nodeId) != nodeId) {
#ifdef DEBUG
        llvm::outs() << sccRepNode(nodeId) << " != " << nodeId << "\n";
#endif
        return;
    }

    double propStart = stat->getClk();
    ConstraintNode* node = consCG->getConstraintNode(nodeId);
    handleCopyGep(node);
    double propEnd = stat->getClk();
    timeOfProcessCopyGep += (propEnd - propStart) / TIMEINTERVAL;
}

/*!
 * Post process node
 */
void AndersenWaveDiff::postProcessNode(NodeID nodeId)
{
    double insertStart = stat->getClk();

    ConstraintNode* node = consCG->getConstraintNode(nodeId);

    // handle load
    for (ConstraintNode::const_iterator it = node->outgoingLoadsBegin(), eit = node->outgoingLoadsEnd();
         it != eit; ++it) {
        if (handleLoad(nodeId, *it))
            reanalyze = true;
    }
    // handle store
    for (ConstraintNode::const_iterator it = node->incomingStoresBegin(), eit =  node->incomingStoresEnd();
         it != eit; ++it) {
        if (handleStore(nodeId, *it))
            reanalyze = true;
    }

    double insertEnd = stat->getClk();
    timeOfProcessLoadStore += (insertEnd - insertStart) / TIMEINTERVAL;
}

/*!
 * Handle copy gep
 */
void AndersenWaveDiff::handleCopyGep(ConstraintNode* node) {
    NodeID nodeId = node->getId();
#ifdef DEBUG
    llvm::outs() << "AndersenWaveDiff::handleCopyGep(ConstraintNode* node) : "<< nodeId << "\n";
#endif
    computeDiffPts(nodeId);

    if (!getDiffPts(nodeId).empty()) {
        for (ConstraintEdge* edge : node->getCopyOutEdges())
            if (CopyCGEdge* copyEdge = SVFUtil::dyn_cast<CopyCGEdge>(edge)) {
#ifdef DEBUG
                llvm::outs() << "processCopy(nodeId, copyEdge);\n";
#endif
                processCopy(nodeId, copyEdge);
            }
        for (ConstraintEdge* edge : node->getGepOutEdges())
            if (GepCGEdge* gepEdge = SVFUtil::dyn_cast<GepCGEdge>(edge)) {
#ifdef DEBUG
                llvm::outs() << "processGep(nodeId, gepEdge);\n";
#endif
                processGep(nodeId, gepEdge);
            }
    }
#ifdef DEBUG
    else {
        llvm::outs() << "getDiffPts(nodeId).empty()\n";
    }
#endif
}


/*!
 * Process load edges
 *	src --load--> dst,
 *	node \in pts(src) ==>  node--copy-->dst
 */
/*!
 * Handle load
 */
// nodeId is srcNode of edge
bool AndersenWaveDiff::handleLoad(NodeID nodeId, const ConstraintEdge* edge)
{
    bool changed = false;
    NodeID srcNode = edge->getSrcID(); 
#ifdef DEBUG
    llvm::outs() << "handleLoad for Node: " << nodeId << "\n";
    llvm::outs() << "Edge : " << edge->getSrcID() << " --> " << edge->getDstID() << "\n";
#endif
    if (processLoad(srcNode, edge)) {
        changed = true;
    }
    for (PointsTo::iterator piter = getPts(nodeId).begin(), epiter = getPts(nodeId).end();
         piter != epiter; ++piter) {
#ifdef DEBUG
        llvm::outs() << "current node in Pts: " << (*piter) << "\n";
#endif
        if (processLoad(*piter, edge)) {
            changed = true;
        }
    }
    return changed;
}

/*!
 * Process store edges
 *	src --store--> dst,
 *	node \in pts(dst) ==>  src--copy-->node
 */
// warnning	node \in pts(dst) ==>  src--copy-->node
// is wrong, cuz the pts direction is  dst ---> src, 
// should be : node in pts(src),  node -- copy --> dst
/*!
 * Handle store
 */
// nodeId is the dstNode of edge
bool AndersenWaveDiff::handleStore(NodeID nodeId, const ConstraintEdge* edge)
{
    bool changed = false;
    NodeID srcNode = edge->getSrcID(); 
#ifdef DEBUG
    llvm::outs() << "handleStore for Node: " << nodeId << "\n";
    llvm::outs() << "Edge : " << edge->getSrcID() << " --> " << edge->getDstID() << "\n";
#endif
    if (processStore(srcNode, edge)) {
        changed = true;
    }
    for (PointsTo::iterator piter = getPts(srcNode).begin(), epiter = getPts(srcNode).end();
         piter != epiter; ++piter) {
#ifdef DEBUG
        llvm::outs() << "current node in Pts: " << (*piter) << "\n";
#endif
        if (processStore(*piter, edge)) {
            changed = true;
        }
    }
    return changed;
}

/*!
 * Propagate diff points-to set from src to dst
 */
bool AndersenWaveDiff::processCopy(NodeID node, const ConstraintEdge* edge) {
    numOfProcessedCopy++;

    bool changed = false;
    assert((SVFUtil::isa<CopyCGEdge>(edge)) && "not copy/call/ret ??");
    NodeID dst = edge->getDstID();
    PointsTo& srcDiffPts = getDiffPts(node);
#ifdef DEBUG
    llvm::outs() << "processing Copy:" << node << " --> " << dst << "\n srcDiffPts: ";
    for (PointsTo::iterator piter = srcDiffPts.begin(), epiter = srcDiffPts.end(); piter != epiter; ++piter) {
        /// get the object
        NodeID ptd = *piter;
        llvm::outs() << "Node in pts of getDiffPts(" << node <<"): " << ptd << "\n";
    }
#endif

    processCast(edge);
    if(unionPts(dst,srcDiffPts)) {
        changed = true;
        pushIntoWorklist(dst);
    }

    return changed;
}

/*
 * Merge a node to its rep node
 */
void AndersenWaveDiff::mergeNodeToRep(NodeID nodeId,NodeID newRepId) {
    if(nodeId==newRepId)
        return;

    /// update rep's propagated points-to set
    updatePropaPts(newRepId, nodeId);

    Andersen::mergeNodeToRep(nodeId, newRepId);
}
