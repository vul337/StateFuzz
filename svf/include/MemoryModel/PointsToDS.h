//===- PointsToDS.h -- Points-to data structure ------------------------------//
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
//===----------------------------------------------------------------------===//

/*
 * PointsToDS.h
 *
 *  PointsTo Data Structure
 *
 *  Created on: Mar 21, 2014
 *      Author: Yulei Sui
 */

#ifndef POINTSTO_H_
#define POINTSTO_H_

#include "MemoryModel/ConditionalPT.h"
// #define DEBUG 1

/// Overloading operator << for dumping conditional variable
//@{
template<class Cond>
raw_ostream& operator<< (raw_ostream &o, const CondVar<Cond> &cvar) {
    o << cvar.toString();
    return o;
}
//@}

/*!
 * Basic points-to data structure
 * Given a key (variable/condition variable), return its points-to data (pts/condition pts)
 * It is designed flexible for different context, heap and path sensitive analysis
 * Context Insensitive			   Key --> Variable, Data --> PointsTo
 * Context sensitive:  			   Key --> CondVar,  Data --> PointsTo
 * Heap sensitive:     			   Key --> Variable  Data --> CondPointsToSet
 * Context and heap sensitive:     Key --> CondVar,  Data --> CondPointsToSet
 */
template<class Key, class Data>
class PTData {
public:
    typedef std::map<const Key, Data> PtsMap;
    typedef typename PtsMap::iterator PtsMapIter;
    typedef typename PtsMap::const_iterator PtsMapConstIter;
    typedef typename Data::iterator iterator;

    /// Types of a points-to data structure
    enum PTDataTY {
        DFPTD,
        IncDFPTD,
        DiffPTD,
        Default
    };
    /// Constructor
    PTData(PTDataTY ty = Default): ptdTy(ty) {
    }

    /// Destructor
    virtual ~PTData() {
    }

    /// Clear maps
    virtual void clear() {
        ptsMap.clear();
        revPtsMap.clear();
    }

    /// Get the type of a points-to data structure
    inline PTDataTY getPTDTY() const {
        return ptdTy;
    }

    /// Return Points-to map
    inline const PtsMap& getPtsMap() const {
#ifdef DEBUG
        llvm::outs() << "getPtsMap\n";
#endif
        return ptsMap;
    }

    // Get conditional points-to set of the pointer
    inline Data& getPts(const Key& var) {
#ifdef DEBUG
        llvm::outs() << "getPts for " << var << "\n"; 
        llvm::outs() << "current Pts: \n";
        for(typename Data::iterator cit = ptsMap[var].begin(), ecit=ptsMap[var].end(); cit!=ecit; ++cit) {
            llvm::outs() << "Node in Pts: " << (*cit) << "\n";
        }
#endif
        return ptsMap[var];
    }

    // Get conditional reverse points-to set of the pointer
    inline Data& getRevPts(const Key& var) {
#ifdef DEBUG
        llvm::outs() << "getRevPts for " << var << "\n"; 
#endif
        return revPtsMap[var];
    }

    /// Union/add points-to, used internally
    //@{
    inline bool addPts(const Key &dstKey, const Key& srcKey) {
#ifdef DEBUG
        llvm::outs() << "addPts for edge: " << srcKey << " --> " << dstKey << "\n";
#endif
        addSingleRevPts(getRevPts(srcKey),dstKey);
        return addPts(getPts(dstKey),srcKey);
    }
    inline bool unionPts(const Key& dstKey, const Key& srcKey) {
#ifdef DEBUG
        llvm::outs() << "unionPts1 for edge : " << srcKey << " --> " << dstKey << "\n";
#endif
        addRevPts(getPts(srcKey),dstKey);
        return unionPts(getPts(dstKey),getPts(srcKey));
    }
    // dstKey是gep的dstNode，srcData是getSrcNode的Pts
    // 把dstNode的pts和srcNode的pts合并到dstNode的pts
    inline bool unionPts(const Key& dstKey, const Data& srcData) {
#ifdef DEBUG
        llvm::outs() << "unionPts2 GepDstNode: " << dstKey << "\n";
#endif
        addRevPts(srcData,dstKey);
        return unionPts(getPts(dstKey),srcData);
    }

protected:
    PtsMap ptsMap;
    PtsMap revPtsMap;

private:
    /// Union/add points-to
    //@{
    // 把dstNode的pts和srcNode的pts合并到dstNode的pts
    inline bool unionPts(Data& dstData, const Data& srcData) {
#ifdef DEBUG
        llvm::outs() << "final UnionPts: add src PtsSet into dst PtsSet\n";
        for(typename Data::iterator cit = dstData.begin(), ecit=dstData.end(); cit!=ecit; ++cit) {
            llvm::outs() << "dst PtsSet: " << (*cit) << "\n";
        }
        for(typename Data::iterator cit = srcData.begin(), ecit=srcData.end(); cit!=ecit; ++cit) {
            llvm::outs() << "Src PtsSet: " << (*cit) << "\n";
        }
#endif
        return dstData |= srcData;
    }
    inline bool addPts(Data &d, const Key& e) {
#ifdef DEBUG
        for(typename Data::iterator cit = d.begin(), ecit=d.end(); cit!=ecit; ++cit) {
            llvm::outs() << "Node in above PtNode's Pts: " << (*cit) << "\n";
        }
        llvm::outs() << "final add node " << e << " into above pts\n";
#endif
        return d.test_and_set(e);
    }
    // revData是gepSrcNode Pts中每一个node的revPts
    // 在gepSrcNode Pts中每一个node的revPts里都加上tgr
    inline void addSingleRevPts(Data &revData, const Key& tgr) {
// #ifdef DEBUG
//         llvm::outs() << "addSingleRevPts for GepDstNode: " << tgr << "\n";
//         for(typename Data::iterator cit = revData.begin(), ecit=revData.end(); cit!=ecit; ++cit) {
//             llvm::outs() << "Node in above PtNode's Pts: " << (*cit) << "\n";
//         }
// #endif
        addPts(revData,tgr);
    }
    // ptsData是gepSrcNode的pts， tgr是getDstNode
    // getRevPts(*it)是
    inline void addRevPts(const Data &ptsData, const Key& tgr) {
// #ifdef DEBUG
//         llvm::outs() << "-------start addRevPts-------\n";
// #endif
        for(iterator it = ptsData.begin(), eit = ptsData.end(); it!=eit; ++it)
        {
// #ifdef DEBUG
//             llvm::outs() << "current Pt in Pts of GepSrcNode: " << (*it) << "\n";
// #endif
            addSingleRevPts(getRevPts(*it),tgr);
        }
// #ifdef DEBUG
//         llvm::outs() << "-------end addRevPts-------\n";
// #endif
    }
    //@}

    PTDataTY ptdTy;

public:
    /// Debugging functions
    //@{
    virtual inline void dumpPts(const PtsMap & ptsSet,raw_ostream & O = SVFUtil::outs()) const {
        for (PtsMapConstIter nodeIt = ptsSet.begin(); nodeIt != ptsSet.end(); nodeIt++) {
            const Key& var = nodeIt->first;
            const Data & pts = nodeIt->second;
            if (pts.empty())
                continue;
            O << var << " ==> { ";
            for(typename Data::iterator cit = pts.begin(), ecit=pts.end(); cit!=ecit; ++cit) {
                O << *cit << " ";
            }
            O << "}\n";
        }
    }
    virtual inline void dumpPTData() {
        dumpPts(ptsMap);
    }
    //@}
};


/*!
 * Diff points-to data with cached information
 * This is an optimisation version on top of base points-to data.
 * The points-to information is propagated incrementally only for the different parts.
 * CahcePtsMap is an additional map which maintains cached points-to.
 */
template<class Key, class Data, class CacheKey>
class DiffPTData : public PTData<Key,Data> {
public:
    typedef typename PTData<Key,Data>::PtsMap PtsMap;
    typedef typename PTData<CacheKey,Data>::PtsMap CahcePtsMap;
    typedef typename PTData<Key,Data>::PTDataTY PTDataTy;
    /// Constructor
    DiffPTData(PTDataTy ty = (PTData<Key,Data>::DiffPTD)): PTData<Key,Data>(ty) {
    }

    /// Destructor
    ~DiffPTData() {}

    /// Get diff points to.
    inline Data & getDiffPts(Key& var) {
        return diffPtsMap[var];
    }
    /// Get propagated points to.
    inline Data & getPropaPts(Key& var) {
        return propaPtsMap[var];
    }

    /**
     * Compute diff points to. Return TRUE if diff is not empty.
     * 1. calculate diff by: diff = all - propa;
     * 2. update propagated pts: propa = all.
     */
    // 把新的Pts更新到Node的Pts里
    inline bool computeDiffPts(Key& var, Data& all) {
        /// clear diff pts.
#ifdef DEBUG
        llvm::outs() << "computeDiffPts for " << var << "\n";
#endif
        Data& diff = getDiffPts(var);
        diff.clear();
        /// get all pts
#ifdef DEBUG
        llvm::outs() << "getCurrentAllPts(" << var << "): \n";
        for (typename Data::iterator piter = all.begin(), epiter =
                all.end(); piter != epiter; ++piter) {
            llvm::outs() << "Current Pt" << (*piter) << "\n";
        }
        llvm::outs() << "getPropaPts(" << var << "): \n";
#endif
        Data& propa = getPropaPts(var);
#ifdef DEBUG
        for (typename Data::iterator piter = propa.begin(), epiter =
                propa.end(); piter != epiter; ++piter) {
            llvm::outs() << "PropaPt: " << (*piter) << "\n";
        }
#endif
        diff.intersectWithComplement(all, propa);
        propa = all;
        return (diff.empty() == false);
    }

    /**
     * Update dst's propagated points-to set with src's.
     * The final result is the intersection of these two sets.
     */
    inline void updatePropaPtsMap(Key& src, Key&dst) {
#ifdef DEBUG
        llvm::outs() << "updatePropaPtsMap for " << src << " --> " << dst <<"\n";
#endif
        Data& srcPropa = getPropaPts(src);
        Data& dstPropa = getPropaPts(dst);
        dstPropa &= srcPropa;
    }

    /// Clear propagated pts
    inline void clearPropaPts(Key& var) {
        getPropaPts(var).clear();
    }

    /// Get cached points-to
    inline Data& getCachePts(CacheKey& cache) {
        return CacheMap[cache];
    }

    /// Add cached points-to
    inline void addCachePts(CacheKey& cache, Data& data) {
        CacheMap[cache] |= data;
    }

    /// Methods for support type inquiry through isa, cast, and dyn_cast:
    //@{
    static inline bool classof(const DiffPTData<Key,Data,CacheKey> *) {
        return true;
    }
    static inline bool classof(const PTData<Key,Data>* ptd) {
        return ptd->getPTDTY() == PTData<Key,Data>::DiffPTD;
    }
    //@}

private:
    PtsMap diffPtsMap;	///< diff points-to to be propagated
    PtsMap propaPtsMap;	///< points-to already propagated

    CahcePtsMap CacheMap;	///< points-to processed at load/store edge
};

#endif /* POINTSTO_H_ */
