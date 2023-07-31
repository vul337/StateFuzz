// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package cover provides types for working with coverage information (arrays of covered PCs).
package cover

import (
	"sort"
)

type PcCover map[uint32]struct{}

// type SvCover map[uint64]struct{}

func (cov *PcCover) Merge(raw []uint32) {
	c := *cov
	if c == nil {
		c = make(PcCover)
		*cov = c
	}
	for _, pc := range raw {
		c[pc] = struct{}{}
	}
}

func (cov PcCover) Serialize() []uint32 {
	res := make([]uint32, 0, len(cov))
	for pc := range cov {
		res = append(res, pc)
	}
	return res
}

func RestorePC(pc uint32, base uint32) uint64 {
	return uint64(base)<<32 + uint64(pc)
}

// Hash : compute hash, prevent pc1 ^ pc2 == 0 (pc1 pc2 is close)
func Hash(a uint32) uint32 {
	a = (a ^ 61) ^ (a >> 16)
	a = a + (a << 3)
	a = a ^ (a >> 4)
	a = a * 0x27d4eb2d
	a = a ^ (a >> 15)
	return a
}

// PathHash : make a hash from PcCover of input program
func (cov PcCover) PathHash() uint32 {
	res := cov.Serialize()
	// sort
	sort.Slice(res, func(i, j int) bool {
		return res[i] < res[j]
	})

	var hash uint32
	for _, s := range res {
		hash = hash ^ Hash(s)
	}
	return hash
}
