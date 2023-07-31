// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

// Calulation of call-to-call priorities.
// For a given pair of calls X and Y, the priority is our guess as to whether
// additional of call Y into a program containing call X is likely to give
// new coverage or not.
// The current algorithm has two components: static and dynamic.
// The static component is based on analysis of argument types. For example,
// if call X and call Y both accept fd[sock], then they are more likely to give
// new coverage together.
// The dynamic component is based on frequency of occurrence of a particular
// pair of syscalls in a single program in corpus. For example, if socket and
// connect frequently occur in programs together, we give higher priority to
// this pair of syscalls.
// Note: the current implementation is very basic, there is no theory behind any
// constants.

func (target *Target) CalculatePrioritiesFuzzer(corpus map[uint32][]*Prog) [][]float32 {

	static := target.CalcStaticPriorities()
	if len(corpus) != 0 {
		dynamic := target.CalcDynamicPrioFuzzer(corpus)
		for i, prios := range dynamic {
			for j, p := range prios {
				static[i][j] *= p
			}
		}
	}
	return static
}

func (target *Target) CalculatePriorities(corpus []*Prog) [][]float32 {

	static := target.CalcStaticPriorities()
	if len(corpus) != 0 {
		dynamic := target.CalcDynamicPrio(corpus)
		for i, prios := range dynamic {
			for j, p := range prios {
				static[i][j] *= p
			}
		}
	}
	return static
}

func (target *Target) CalcStaticPriorities() [][]float32 {
	static := target.CalcResourcePriorities()
	structp := target.CalcGlobalPriorities()
	for i, prios := range static {
		for j, p := range prios {
			structp[i][j] = structp[i][j]*5 + p
		}
	}
	return structp
}

// deprecated
func (target *Target) CalcGlobalPriorities() [][]float32 {
	prios := make([][]float32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]float32, len(target.Syscalls))
	}

	/**/
	var dependMap map[string]map[string]float32
	var sys_name1, sys_name2 string
	syscall_map := make(map[string][]int)

	for call, callpriomap := range dependMap {
		// fmt.Printf("current call in dependMap: %v\n", call)
		if _, ok := syscall_map[call]; !ok {
			syscall_map[call] = make([]int, 0)
			for i, _ := range target.Syscalls {
				// for ioctl alias cases: ioctl$dev_tty_21524_4 ioctl$dev_tty_21524_25
				// same cmd, different arg types
				if strings.HasPrefix(target.Syscalls[i].Name, "ioctl$") {
					last_index := strings.LastIndex(target.Syscalls[i].Name, "_")
					if last_index == -1 {
						sys_name1 = target.Syscalls[i].Name
					} else {
						sys_name1 = target.Syscalls[i].Name[0:last_index]
					}
				} else {
					sys_name1 = target.Syscalls[i].Name
				}
				if sys_name1 == call {
					// fmt.Printf("syscall_mapi[%v] append %v\n", call, target.Syscalls[i].Name)
					syscall_map[call] = append(syscall_map[call], i)
				}
			}
		}

		for call0, prio0 := range callpriomap {
			if _, ok := syscall_map[call0]; !ok {
				syscall_map[call0] = make([]int, 0)
				for i, _ := range target.Syscalls {
					// for ioctl alias cases: ioctl$dev_tty_21524_4 ioctl$dev_tty_21524_25
					// same cmd, different arg types
					if strings.HasPrefix(target.Syscalls[i].Name, "ioctl$") {
						last_index := strings.LastIndex(target.Syscalls[i].Name, "_")
						if last_index == -1 {
							sys_name2 = target.Syscalls[i].Name
						} else {
							sys_name2 = target.Syscalls[i].Name[0:last_index]
						}
					} else {
						sys_name2 = target.Syscalls[i].Name
					}
					if sys_name2 == call0 {
						// fmt.Printf("syscall_mapj[%v] append %v\n", call0, target.Syscalls[i].Name)
						syscall_map[call0] = append(syscall_map[call0], i)
					}
				}
			}
			if call != call0 {
				for _, i := range syscall_map[call] {
					for _, j := range syscall_map[call0] {
						// fmt.Printf("[+] prios[%v][%v]: %v\n", target.Syscalls[i].Name, target.Syscalls[j].Name, prio0)
						prios[i][j] = prio0
					}
				}
			} else {
				for _, i := range syscall_map[call] {
					for _, j := range syscall_map[call0] {
						// fmt.Printf("[+] prios[%v][%v]: fixed 0.01\n", target.Syscalls[i].Name, target.Syscalls[j].Name)
						prios[i][j] = 0.01
					}
				}
			}
		}
	}
	timeStr2 := time.Now().Format("2006/01/02 15:04:05 ")
	fmt.Printf("%v [+] global_dependency prios load done\n", timeStr2)
	/**/

	normalizePrio(prios)
	return prios
}

func (target *Target) CalcResourcePriorities() [][]float32 {
	uses := target.CalcResourceUsage()
	prios := make([][]float32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]float32, len(target.Syscalls))
	}
	for _, calls := range uses {
		for c0, w0 := range calls {
			for c1, w1 := range calls {
				if c0 == c1 {
					// Self-priority is assigned below.
					continue
				}
				// The static priority is assigned based on the direction of arguments. A higher priority will be
				// assigned when c0 is a call that produces a resource and c1 a call that uses that resource.
				prios[c0][c1] += w0.inout*w1.in + 0.7*w0.inout*w1.inout
			}
		}
	}
	normalizePrio(prios)
	// The value assigned for self-priority (call wrt itself) have to be high, but not too high.
	for c0, pp := range prios {
		pp[c0] = 0.9
	}
	return prios
}

func (target *Target) CalcResourceUsage() map[string]map[int]weights {
	uses := make(map[string]map[int]weights)
	ForeachType(target.Syscalls, func(t Type, ctx TypeCtx) {
		c := ctx.Meta
		switch a := t.(type) {
		case *ResourceType:
			if target.AuxResources[a.Desc.Name] {
				noteUsage(uses, c, 0.1, ctx.Dir, "res%v", a.Desc.Name)
			} else {
				str := "res"
				for i, k := range a.Desc.Kind {
					str += "-" + k
					w := 1.0
					if i < len(a.Desc.Kind)-1 {
						w = 0.2
					}
					noteUsage(uses, c, float32(w), ctx.Dir, str)
				}
			}
		case *PtrType:
			if _, ok := a.Elem.(*StructType); ok {
				noteUsage(uses, c, 1.0, ctx.Dir, "ptrto-%v", a.Elem.Name())
			}
			if _, ok := a.Elem.(*UnionType); ok {
				noteUsage(uses, c, 1.0, ctx.Dir, "ptrto-%v", a.Elem.Name())
			}
			if arr, ok := a.Elem.(*ArrayType); ok {
				noteUsage(uses, c, 1.0, ctx.Dir, "ptrto-%v", arr.Elem.Name())
			}
		case *BufferType:
			switch a.Kind {
			case BufferBlobRand, BufferBlobRange, BufferText:
			case BufferString:
				if a.SubKind != "" {
					noteUsage(uses, c, 0.2, ctx.Dir, fmt.Sprintf("str-%v", a.SubKind))
				}
			case BufferFilename:
				noteUsage(uses, c, 1.0, DirIn, "filename")
			default:
				panic("unknown buffer kind")
			}
		case *VmaType:
			noteUsage(uses, c, 0.5, ctx.Dir, "vma")
		case *IntType:
			switch a.Kind {
			case IntPlain, IntRange:
			default:
				panic("unknown int kind")
			}
		}
	})
	return uses
}

type weights struct {
	in    float32
	inout float32
}

func noteUsage(uses map[string]map[int]weights, c *Syscall, weight float32, dir Dir, str string, args ...interface{}) {
	id := fmt.Sprintf(str, args...)
	if uses[id] == nil {
		uses[id] = make(map[int]weights)
	}
	callWeight := uses[id][c.ID]
	if dir != DirOut {
		if weight > uses[id][c.ID].in {
			callWeight.in = weight
		}
	}
	if weight > uses[id][c.ID].inout {
		callWeight.inout = weight
	}
	uses[id][c.ID] = callWeight
}

func (target *Target) CalcDynamicPrioFuzzer(corpus map[uint32][]*Prog) [][]float32 {
	prios := make([][]float32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]float32, len(target.Syscalls))
	}
	for _, bucket := range corpus {
		for _, p := range bucket {
			// if p.IsNewSvSeed == 2 {
			// 	continue
			// }
			for idx0, c0 := range p.Calls {
				for _, c1 := range p.Calls[idx0+1:] {
					id0 := c0.Meta.ID
					id1 := c1.Meta.ID
					prios[id0][id1] += 1.0
				}
			}
		}
	}
	normalizePrio(prios)
	return prios
}

func (target *Target) CalcDynamicPrio(corpus []*Prog) [][]float32 {
	prios := make([][]float32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]float32, len(target.Syscalls))
	}

	for _, p := range corpus {
		// if p.IsNewSvSeed == 2 {
		// 	continue
		// }
		for idx0, c0 := range p.Calls {
			for _, c1 := range p.Calls[idx0+1:] {
				id0 := c0.Meta.ID
				id1 := c1.Meta.ID
				prios[id0][id1] += 1.0
			}
		}
	}

	normalizePrio(prios)
	return prios
}

// normalizePrio assigns some minimal priorities to calls with zero priority,
// and then normalizes priorities to 0.1..1 range.
func normalizePrio(prios [][]float32) {
	for _, prio := range prios {
		max := float32(0)
		min := float32(1e10)
		nzero := 0
		for _, p := range prio {
			if max < p {
				max = p
			}
			if p != 0 && min > p {
				min = p
			}
			if p == 0 {
				nzero++
			}
		}
		if nzero != 0 {
			min /= 2 * float32(nzero)
		}
		if min == max {
			max = 0
		}
		for i, p := range prio {
			if max == 0 {
				prio[i] = 1
				continue
			}
			if p == 0 {
				p = min
			}
			// 0.9 * ((q - p) / (max - min))
			p = (p-min)/(max-min)*0.999 + 0.001
			if p > 1 {
				p = 1
			}
			prio[i] = p
		}
	}
}

// ChooseTable allows to do a weighted choice of a syscall for a given syscall
// based on call-to-call priorities and a set of enabled syscalls.
type ChoiceTable struct {
	target *Target
	runs   [][]int
	calls  []*Syscall
}

func (target *Target) BuildChoiceTableFuzzer(corpus map[uint32][]*Prog, enabled map[*Syscall]bool) *ChoiceTable {
	if enabled == nil {
		enabled = make(map[*Syscall]bool)
		for _, c := range target.Syscalls {
			enabled[c] = true
		}
	}
	for call := range enabled {
		if call.Attrs.Disabled {
			delete(enabled, call)
		}
	}
	var enabledCalls []*Syscall
	for c := range enabled {
		enabledCalls = append(enabledCalls, c)
	}
	if len(enabledCalls) == 0 {
		panic("no syscalls enabled")
	}
	sort.Slice(enabledCalls, func(i, j int) bool {
		return enabledCalls[i].ID < enabledCalls[j].ID
	})
	for _, bucket := range corpus {
		for _, p := range bucket {
			// if p.IsNewSvSeed == 2 {
			// 	continue
			// }
			for _, call := range p.Calls {
				if !enabled[call.Meta] {
					panic(fmt.Sprintf("corpus contains disabled syscall %v", call.Meta.Name))
				}
			}
		}
	}
	prios := target.CalculatePrioritiesFuzzer(corpus)
	run := make([][]int, len(target.Syscalls))
	for i := range run {
		if !enabled[target.Syscalls[i]] {
			continue
		}
		run[i] = make([]int, len(target.Syscalls))
		sum := 0
		for j := range run[i] {
			if enabled[target.Syscalls[j]] {
				sum += int(prios[i][j]*prios[i][j]*1000 + 1)
			}
			run[i][j] = sum
		}
	}
	return &ChoiceTable{target, run, enabledCalls}
}

func (target *Target) BuildChoiceTable(corpus []*Prog, enabled map[*Syscall]bool) *ChoiceTable {
	if enabled == nil {
		enabled = make(map[*Syscall]bool)
		for _, c := range target.Syscalls {
			enabled[c] = true
		}
	}
	for call := range enabled {
		if call.Attrs.Disabled {
			delete(enabled, call)
		}
	}
	var enabledCalls []*Syscall
	for c := range enabled {
		enabledCalls = append(enabledCalls, c)
	}
	if len(enabledCalls) == 0 {
		panic("no syscalls enabled")
	}
	sort.Slice(enabledCalls, func(i, j int) bool {
		return enabledCalls[i].ID < enabledCalls[j].ID
	})
	for _, p := range corpus {
		// if p.IsNewSvSeed == 2 {
		// 	continue
		// }
		for _, call := range p.Calls {
			if !enabled[call.Meta] {
				panic(fmt.Sprintf("corpus contains disabled syscall %v", call.Meta.Name))
			}
		}
	}
	prios := target.CalculatePriorities(corpus)
	run := make([][]int, len(target.Syscalls))
	for i := range run {
		if !enabled[target.Syscalls[i]] {
			continue
		}
		run[i] = make([]int, len(target.Syscalls))
		sum := 0
		for j := range run[i] {
			if enabled[target.Syscalls[j]] {
				sum += int(prios[i][j]*prios[i][j]*1000 + 1)
			}
			run[i][j] = sum
		}
	}
	return &ChoiceTable{target, run, enabledCalls}
}

func (ct *ChoiceTable) enabled(call int) bool {
	return ct.runs[call] != nil
}

func (ct *ChoiceTable) choose(r *rand.Rand, bias int) int {
	if bias < 0 {
		bias = ct.calls[r.Intn(len(ct.calls))].ID
	}
	if !ct.enabled(bias) {
		panic("bias to disabled syscall")
	}
	run := ct.runs[bias]
	if run[len(run)-1] <= 0 {
		log.Logf(0, "syscall: %v, run[len(run)-1] = %v", ct.target.Syscalls[bias].Name, run[len(run)-1])
	}
	x := r.Intn(run[len(run)-1]) + 1
	res := sort.SearchInts(run, x)
	if !ct.enabled(res) {
		panic("selected disabled syscall")
	}
	return res
}

