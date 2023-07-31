// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package signal provides types for working with feedback signal.
package signal

import (
	"sort"

	"github.com/google/syzkaller/pkg/log"
)

type (
	elemTypeL uint64
	elemType  uint32
	prioType  int8
)

// svranges[sv_no][0] = 0
// svranges[sv_no][1] = 0x2222
type SvRanges map[uint32][]int32

type Signal map[elemType]prioType

type SvCover map[elemTypeL]prioType

type SvExtremum map[uint32]map[string]int32

type Serial struct {
	Elems []elemType
	Prios []prioType
}

type SvSerial struct {
	Elems []elemTypeL
	Prios []prioType
}

func (s Signal) Len() int {
	return len(s)
}

func (s SvCover) Len() int {
	return len(s)
}

func (s SvExtremum) Len() int {
	return len(s)
}

func (s Signal) Empty() bool {
	return len(s) == 0
}

func (s SvCover) Empty() bool {
	return len(s) == 0
}

func (s SvExtremum) Empty() bool {
	return len(s) == 0
}

func (s Signal) Copy() Signal {
	c := make(Signal, len(s))
	for e, p := range s {
		c[e] = p
	}
	return c
}

func (s SvCover) Copy() SvCover {
	c := make(SvCover, len(s))
	for e, p := range s {
		c[e] = p
	}
	return c
}

func (s SvExtremum) Copy() SvExtremum {
	c := make(SvExtremum, len(s))
	for e, p := range s {
		p0 := make(map[string]int32)
		p0["max"] = p["max"]
		p0["min"] = p["min"]
		p0["update"] = p["update"]
		c[e] = p0
	}
	return c
}

func (s *Signal) Split(n int) Signal {
	if s.Empty() {
		return nil
	}
	c := make(Signal, n)
	for e, p := range *s {
		delete(*s, e)
		c[e] = p
		n--
		if n == 0 {
			break
		}
	}
	if len(*s) == 0 {
		*s = nil
	}
	return c
}

func (s *SvCover) Split(n int) SvCover {
	if s.Empty() {
		return nil
	}
	c := make(SvCover, n)
	for e, p := range *s {
		delete(*s, e)
		c[e] = p
		n--
		if n == 0 {
			break
		}
	}
	if len(*s) == 0 {
		*s = nil
	}
	return c
}

func (s *SvExtremum) Split(n int) SvExtremum {
	if s.Empty() {
		return nil
	}
	c := make(SvExtremum, n)
	for e, p := range *s {
		delete(*s, e)
		c[e] = p
		n--
		if n == 0 {
			break
		}
	}
	if len(*s) == 0 {
		*s = nil
	}
	return c
}

func FromRaw(raw []uint32, prio uint8) Signal {
	if len(raw) == 0 {
		return nil
	}
	s := make(Signal, len(raw))
	for _, e := range raw {
		s[elemType(e)] = prioType(prio)
	}
	return s
}

func FromRawL(raw []uint64, prio uint8) SvCover {
	if len(raw) == 0 {
		return nil
	}
	s := make(SvCover, len(raw))
	for _, e := range raw {
		s[elemTypeL(e)] = prioType(prio)
	}
	return s
}

func FromRawExtremum(raw []uint64, prio uint8) SvExtremum {
	if len(raw) == 0 {
		return nil
	}
	svExtremumUpdate := make(map[uint32]map[string]int32)

	for _, e := range raw {
		if e&0xffff000000000000 != 0xffff000000000000 {
			log.Logf(0, "error! non-SvExtremum record in ipc.info")
			continue
		}
		svValue := int32(e & 0xffffffff)
		svNo := uint32((e >> 32) & 0x7fff)
		// log.Logf(0, "item: %x, svValue: %x %v, svNo: %x %v", item, svValue, svValue, svNo, svNo)
		if _, ok := svExtremumUpdate[svNo]; !ok {
			svExtremumUpdate[svNo] = make(map[string]int32)
			svExtremumUpdate[svNo]["max"] = -2147483648
			svExtremumUpdate[svNo]["min"] = 2147483647
			svExtremumUpdate[svNo]["update"] = 0
		}
		if svValue > svExtremumUpdate[svNo]["max"] {
			svExtremumUpdate[svNo]["max"] = svValue
		}
		if svValue < svExtremumUpdate[svNo]["min"] {
			svExtremumUpdate[svNo]["min"] = svValue
		}
	}
	return svExtremumUpdate
}

func (s Signal) Serialize() Serial {
	if s.Empty() {
		return Serial{}
	}
	res := Serial{
		Elems: make([]elemType, len(s)),
		Prios: make([]prioType, len(s)),
	}
	i := 0
	for e, p := range s {
		res.Elems[i] = e
		res.Prios[i] = p
		i++
	}
	return res
}

func (s SvCover) Serialize() SvSerial {
	if s.Empty() {
		return SvSerial{}
	}
	res := SvSerial{
		Elems: make([]elemTypeL, len(s)),
		Prios: make([]prioType, len(s)),
	}
	i := 0
	for e, p := range s {
		res.Elems[i] = e
		res.Prios[i] = p
		i++
	}
	return res
}

func (ser Serial) Deserialize() Signal {
	if len(ser.Elems) != len(ser.Prios) {
		panic("corrupted Serial")
	}
	if len(ser.Elems) == 0 {
		return nil
	}
	s := make(Signal, len(ser.Elems))
	for i, e := range ser.Elems {
		s[e] = ser.Prios[i]
	}
	return s
}

func (ser SvSerial) Deserialize() SvCover {
	if len(ser.Elems) != len(ser.Prios) {
		panic("corrupted Serial")
	}
	if len(ser.Elems) == 0 {
		return nil
	}
	s := make(SvCover, len(ser.Elems))
	for i, e := range ser.Elems {
		s[e] = ser.Prios[i]
	}
	return s
}

func (s Signal) Diff(s1 Signal) Signal {
	if s1.Empty() {
		return nil
	}
	var res Signal
	for e, p1 := range s1 {
		if p, ok := s[e]; ok && p >= p1 {
			continue
		}
		if res == nil {
			res = make(Signal)
		}
		res[e] = p1
	}
	return res
}

func (s SvCover) Diff(s1 SvCover) SvCover {
	if s1.Empty() {
		return nil
	}
	var res SvCover
	for e, p1 := range s1 {
		if p, ok := s[e]; ok && p >= p1 {
			continue
		}
		if res == nil {
			res = make(SvCover)
		}
		res[e] = p1
	}
	return res
}

func (s SvExtremum) Diff(s1 SvExtremum) SvExtremum {
	// in s1 but not in s
	if s1.Empty() {
		return nil
	}
	// extremum, svCover = 0xffff:rw_type:svNo:svValue = 16:1:15:32
	svExtremumUpdate := make(SvExtremum)

	for svNo, item := range s1 {
		isNewSvNo := false
		if _, ok := s[svNo]; !ok {
			isNewSvNo = true
		}
		if !isNewSvNo && s[svNo]["update"] > 50 {
			continue
		}
		if isNewSvNo || item["max"] > s[svNo]["max"] {
			if _, ok := svExtremumUpdate[svNo]; !ok {
				svExtremumUpdate[svNo] = make(map[string]int32)
				svExtremumUpdate[svNo]["max"] = -2147483648
				svExtremumUpdate[svNo]["min"] = 2147483647
				svExtremumUpdate[svNo]["update"] = 0
			}
			// log.Logf(0, "Diff: svNo: %v, update: %v:%v", svNo, svExtremumUpdate[svNo]["update"], item["update"])
			svExtremumUpdate[svNo]["max"] = item["max"]
			svExtremumUpdate[svNo]["update"] = item["update"]
		}
		if isNewSvNo || item["min"] < s[svNo]["min"] {
			if _, ok := svExtremumUpdate[svNo]; !ok {
				svExtremumUpdate[svNo] = make(map[string]int32)
				svExtremumUpdate[svNo]["max"] = -2147483648
				svExtremumUpdate[svNo]["min"] = 2147483647
				svExtremumUpdate[svNo]["update"] = 0
			}
			// log.Logf(0, "Diff: svNo: %v, update: %v:%v", svNo, svExtremumUpdate[svNo]["update"], item["update"])
			svExtremumUpdate[svNo]["min"] = item["min"]
			svExtremumUpdate[svNo]["update"] = item["update"]
		}
	}
	return svExtremumUpdate
}

func (s Signal) DiffRaw(raw []uint32, prio uint8) Signal {
	var res Signal
	for _, e := range raw {
		if p, ok := s[elemType(e)]; ok && p >= prioType(prio) {
			continue
		}
		if res == nil {
			res = make(Signal)
		}
		res[elemType(e)] = prioType(prio)
	}
	return res
}

func (s SvCover) DiffRaw(raw []uint64, prio uint8) SvCover {
	var res SvCover
	for _, e := range raw {
		if p, ok := s[elemTypeL(e)]; ok && p >= prioType(prio) {
			continue
		}
		if res == nil {
			res = make(SvCover)
		}
		res[elemTypeL(e)] = prioType(prio)
	}
	return res
}

func (s SvExtremum) DiffRaw(raw []uint64, prio uint8) SvExtremum {
	// in raw but not in s
	// extremum, svCover = 0xffff:rw_type:svNo:svValue = 16:1:15:32
	svExtremumUpdate := make(SvExtremum)

	for _, e := range raw {
		if e&0xffff000000000000 != 0xffff000000000000 {
			log.Logf(0, "error! non-SvExtremum record in ipc.info")
			continue
		}
		svValue := int32(e & 0xffffffff)
		svNo := uint32((e >> 32) & 0x7fff)
		isNewSvNo := false
		if _, ok := s[svNo]; !ok {
			isNewSvNo = true
		}
		if !isNewSvNo && s[svNo]["update"] > 50 {
			continue
		}

		// log.Logf(0, "item: %x, svValue: %x %v, svNo: %x %v", item, svValue, svValue, svNo, svNo)
		if isNewSvNo || svValue > s[svNo]["max"] {
			if _, ok := svExtremumUpdate[svNo]; !ok {
				svExtremumUpdate[svNo] = make(map[string]int32)
				svExtremumUpdate[svNo]["max"] = -2147483648
				svExtremumUpdate[svNo]["min"] = 2147483647
				svExtremumUpdate[svNo]["update"] = 0
			}
			if svValue > svExtremumUpdate[svNo]["max"] {
				// log.Logf(0, "Diffraw, svNo: %v, update: %v", svNo, s[svNo]["update"])
				svExtremumUpdate[svNo]["max"] = svValue
			}
		}
		if isNewSvNo || svValue < s[svNo]["min"] {
			if _, ok := svExtremumUpdate[svNo]; !ok {
				svExtremumUpdate[svNo] = make(map[string]int32)
				svExtremumUpdate[svNo]["max"] = -2147483648
				svExtremumUpdate[svNo]["min"] = 2147483647
				svExtremumUpdate[svNo]["update"] = 0
			}
			if svValue < svExtremumUpdate[svNo]["min"] {
				// log.Logf(0, "Diffraw, svNo: %v, update: %v", svNo, s[svNo]["update"])
				svExtremumUpdate[svNo]["min"] = svValue
			}
		}
	}
	return svExtremumUpdate
}

func (s Signal) Intersection(s1 Signal) Signal {
	if s1.Empty() {
		return nil
	}
	res := make(Signal, len(s))
	for e, p := range s {
		if p1, ok := s1[e]; ok && p1 >= p {
			res[e] = p
		}
	}
	return res
}

func (s SvCover) Intersection(s1 SvCover) SvCover {
	if s1.Empty() {
		return nil
	}
	res := make(SvCover, len(s))
	for e, p := range s {
		if _, ok := s1[e]; ok {
			res[e] = p
		}
	}
	return res
}

func (s SvExtremum) Intersection(s1 SvExtremum) SvExtremum {
	if len(s1) == 0 {
		return nil
	}
	res := make(SvExtremum)
	for svNo, item := range s {
		if _, ok := s1[svNo]; ok {
			if svValue, ok1 := item["min"]; ok1 {
				if svValue >= s1[svNo]["min"] {
					if _, ok2 := res[svNo]; !ok2 {
						res[svNo] = make(map[string]int32)
						res[svNo]["max"] = -2147483648
						res[svNo]["min"] = 2147483647
						res[svNo]["update"] = 0
					}
					res[svNo]["min"] = s1[svNo]["min"]
				}
			}
			if svValue, ok1 := item["max"]; ok1 {
				if svValue <= s1[svNo]["max"] {
					if _, ok2 := res[svNo]; !ok2 {
						res[svNo] = make(map[string]int32)
						res[svNo]["max"] = -2147483648
						res[svNo]["min"] = 2147483647
						res[svNo]["update"] = 0
					}
					res[svNo]["max"] = s1[svNo]["max"]
				}
			}
		}
	}
	return res
}

func (s *Signal) Merge(s1 Signal) {
	if s1.Empty() {
		return
	}
	s0 := *s
	if s0 == nil {
		s0 = make(Signal, len(s1))
		*s = s0
	}
	for e, p1 := range s1 {
		if p, ok := s0[e]; !ok || p < p1 {
			s0[e] = p1
		}
	}
}

// do not merge: extremum, svCover = 0xffff:rw_type:svNo:svValue = 16:1:15:32
func (s *SvCover) Merge(s1 SvCover) {
	if s1.Empty() {
		return
	}
	s0 := *s
	if s0 == nil {
		s0 = make(SvCover, len(s1))
		*s = s0
	}
	for e, p1 := range s1 {
		if e&0xffff000000000000 == 0xffff000000000000 {
			continue
		}
		if p, ok := s0[e]; !ok || p < p1 {
			s0[e] = p1
		}
	}
}

func (s *SvExtremum) Merge(s1 SvExtremum) {
	if len(s1) == 0 {
		return
	}
	s0 := *s
	if s0 == nil {
		s0 = make(SvExtremum, len(s1))
		*s = s0
	}
	for svNo, item := range s1 {
		update := false
		if _, ok := s0[svNo]; !ok {
			s0[svNo] = make(map[string]int32)
			s0[svNo]["max"] = -2147483648
			s0[svNo]["min"] = 2147483647
			s0[svNo]["update"] = 0
		}
		if svValue, ok := item["min"]; ok {
			if svValue < s0[svNo]["min"] {
				s0[svNo]["min"] = svValue
				update = true
			}
		}
		if svValue, ok := item["max"]; ok {
			if svValue > s0[svNo]["max"] {
				s0[svNo]["max"] = svValue
				update = true
			}
		}
		if s0[svNo]["update"] < s1[svNo]["update"] {
			s0[svNo]["update"] = s1[svNo]["update"]
		}
		if update == true {
			s0[svNo]["update"]++
		}
	}
}

type Context struct {
	Signal   Signal
	SvSignal Signal
	SvCover  SvCover
	Context  interface{}
}

func Minimize(corpus []Context) []interface{} {
	type ContextPrio struct {
		prio prioType
		idx  int
	}
	covered := make(map[elemType]ContextPrio)
	svSignCovered := make(map[elemType]ContextPrio)
	svCovered := make(map[elemTypeL]ContextPrio)
	for i, inp := range corpus {
		for e, p := range inp.Signal {
			if prev, ok := covered[e]; !ok || p > prev.prio {
				covered[e] = ContextPrio{
					prio: p,
					idx:  i,
				}
			}
		}
		for e, p := range inp.SvSignal {
			if prev, ok := svSignCovered[e]; !ok || p > prev.prio {
				svSignCovered[e] = ContextPrio{
					prio: p,
					idx:  i,
				}
			}
		}
		for e, p := range inp.SvCover {
			if prev, ok := svCovered[e]; !ok || p > prev.prio {
				svCovered[e] = ContextPrio{
					prio: p,
					idx:  i,
				}
			}
		}
	}
	indices := make(map[int]struct{}, len(corpus))
	for _, cp := range covered {
		indices[cp.idx] = struct{}{}
	}
	for _, cp := range svSignCovered {
		indices[cp.idx] = struct{}{}
	}
	for _, cp := range svCovered {
		indices[cp.idx] = struct{}{}
	}
	result := make([]interface{}, 0, len(indices))
	for idx := range indices {
		result = append(result, corpus[idx].Context)
	}
	return result
}

// Hash : compute hash, prevent pc1 ^ pc2 == 0 (pc1 pc2 is close)
// From Thomas Wang Interger Hash
func Hash(a uint32) uint32 {
	a = (a ^ 61) ^ (a >> 16)
	a = a + (a << 3)
	a = a ^ (a >> 4)
	a = a * 0x27d4eb2d
	a = a ^ (a >> 15)
	return a
}

func HashL(key uint64) uint64 {
	key = (^key) + (key << 21) // key = (key << 21) - key - 1;
	key = key ^ (key >> 24)
	key = (key + (key << 3)) + (key << 8) // key * 265
	key = key ^ (key >> 14)
	key = (key + (key << 2)) + (key << 4) // key * 21
	key = key ^ (key >> 28)
	key = key + (key << 31)
	return key
}

// PathHash : make a hash from PC signals of input program
func (sign Signal) PathHash() elemType {
	var res []elemType
	tmpMap := make(map[elemType]bool)
	// filter duplication
	serial := sign.Serialize()
	for _, s := range serial.Elems {
		if _, ok := tmpMap[s]; !ok {
			tmpMap[s] = true
			res = append(res, s)
		}
	}
	// sort
	sort.Slice(res, func(i, j int) bool {
		return res[i] < res[j]
	})

	var hash elemType
	for _, s := range res {
		hash = hash ^ elemType(Hash(uint32(s)))
	}

	if hash == 0 {
		log.Logf(4, "hash is 0")
		for _, s := range res {
			log.Logf(4, "signal: %v", s)
		}
		for _, s := range serial.Elems {
			log.Logf(4, "serial.Elems: %v", s)
		}
	}
	return hash
}

// // SvPathHash :compute pathHash with rw_type:sv_no
// SvPathHash :compute pathHash with svInstPc
func (sign SvCover) SvPathHash() elemType {
	var res []elemType
	tmpMap := make(map[elemType]bool)
	// filter duplication
	serial := sign.Serialize()
	for _, s := range serial.Elems {
		pc := elemType(s >> 32)
		// pc := elemType(s & 0xffff0000)
		if _, ok := tmpMap[pc]; !ok {
			tmpMap[pc] = true
			res = append(res, pc)
		}
	}
	// sort
	sort.Slice(res, func(i, j int) bool {
		return res[i] < res[j]
	})

	var hash elemType
	for _, s := range res {
		hash = hash ^ elemType(Hash(uint32(s)))
	}

	if hash == 0 {
		log.Logf(4, "hash is 0")
		for _, s := range res {
			log.Logf(4, "signal: %v", s)
		}
		for _, s := range serial.Elems {
			log.Logf(4, "serial.Elems: %v", s)
		}
	}
	return hash
}

// SvPathHash : make a hash from PC signals of input program
// func (sign SvCover) SvPathHash() elemTypeL {
// 	var res []elemTypeL
// 	tmpMap := make(map[elemTypeL]bool)
// 	// filter duplication
// 	serial := sign.Serialize()
// 	for _, s := range serial.Elems {
// 		if _, ok := tmpMap[s]; !ok {
// 			tmpMap[s] = true
// 			res = append(res, s)
// 		}
// 	}
// 	// sort
// 	sort.Slice(res, func(i, j int) bool {
// 		return res[i] < res[j]
// 	})

// 	var hash elemTypeL
// 	for _, s := range res {
// 		hash = hash ^ elemTypeL(HashL(uint64(s)))
// 	}

// 	if hash == 0 {
// 		log.Logf(4, "hash is 0")
// 		for _, s := range res {
// 			log.Logf(4, "signal: %v", s)
// 		}
// 		for _, s := range serial.Elems {
// 			log.Logf(4, "serial.Elems: %v", s)
// 		}
// 	}
// 	return hash
// }
