// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"runtime/debug"
	"sort"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer            *Fuzzer
	pid               int
	env               *ipc.Env
	rnd               *rand.Rand
	execOpts          *ipc.ExecOpts
	execOptsCover     *ipc.ExecOpts
	execOptsComps     *ipc.ExecOpts
	execOptsNoCollide *ipc.ExecOpts
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	var err1 error
	env.SvRanges, err1 = ImportSvRanges()
	if err1 != nil {
		return nil, err1
	}
	env.SvPairs, err1 = ImportSvPairs()
	if err1 != nil {
		return nil, err1
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsNoCollide := *fuzzer.execOpts
	execOptsNoCollide.Flags &= ^ipc.FlagCollide
	execOptsCover := execOptsNoCollide
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := execOptsNoCollide
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:            fuzzer,
		pid:               pid,
		env:               env,
		rnd:               rnd,
		execOpts:          fuzzer.execOpts,
		execOptsCover:     &execOptsCover,
		execOptsComps:     &execOptsComps,
		execOptsNoCollide: &execOptsNoCollide,
	}
	return proc, nil
}

func (proc *Proc) loop() {
	// generatePeriod := 100
	generatePeriod := 19
	// HintPeriod := 19
	// svMutationPeriod := 2
	// reviewCorpusPeriod := 1000

	if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}
	log.Logf(0, "start proc loop")
	for i := 0; ; i++ {
		item := proc.fuzzer.workQueue.dequeue()
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				proc.triageInput(item)
			case *WorkCandidate:
				log.Logf(1, "WorkCandidate")
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
			case *WorkSmash:
				proc.smashInput(item)
			default:
				log.Fatalf("unknown work type: %#v", item)
			}
			continue
		}

		ct := proc.fuzzer.choiceTable
		fuzzerSnapshot := proc.fuzzer.snapshot()

		// randomly mutation
		if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
			// Generate a new prog.
			p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			log.Logf(1, "#%v: generated", proc.pid)
			proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
		} else {
			// Mutate an existing prog.
			p := fuzzerSnapshot.chooseProgram(proc.rnd, i)
			p0 := p.Clone()
			p1 := p.Clone()
			sig := hash.String(p.Serialize())
			if p.IsNewSvSeed == 5 {
				sig = sig + "_extremum"
			}
			proc.fuzzer.corpusMu.Lock()
			proc.fuzzer.corpusMutationCnt[sig]++
			proc.fuzzer.corpusMu.Unlock()
			// if proc.fuzzer.comparisonTracingEnabled && i%HintPeriod == 0 {
			log.Logf(0, "p0.Hinted: %v", p.Hinted)
			if proc.fuzzer.comparisonTracingEnabled && p.Hinted < 2 {
				for callIndex := 0; callIndex < len(p.Calls); callIndex++ {
					proc.executeHintSeed(p, callIndex)
					proc.fuzzer.corpusMu.Lock()
					proc.fuzzer.corpusHintCnt[sig]++
					proc.fuzzer.corpusMu.Unlock()
				}
			}
			log.Logf(0, "Hinted Done, p0.Hinted: %v", p.Hinted)
			p0.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
			log.Logf(1, "#%v: mutated from %v", proc.pid, sig)
			proc.execute(proc.execOpts, p0, ProgNormal, StatFuzz)

			// if p0.IsNewSvSeed != 0 && proc.rnd.Intn(svMutationPeriod)%svMutationPeriod == 0 {
			if p.IsNewSvSeed != 0 {
				p1.SvMutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
				log.Logf(0, "#%v: sv mutated from %v", proc.pid, sig)
				proc.execute(proc.execOpts, p1, ProgNormal, StatFuzz)
			}
		}
	}
}

func (proc *Proc) triageInput(item *WorkTriage) {
	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)

	prio := signalPrio(item.p, &item.info, item.call)
	oldSigString := hash.String(item.p.Serialize())

	inputSignal := signal.FromRaw(item.info.Signal, prio)
	log.Logf(0, "triageInput, item.info.SvSignal len: %v, sig: %v", len(item.info.SvSignal), oldSigString)
	inputSvSignal := signal.FromRaw(item.info.SvSignal, prio)
	// for _, i := range item.info.SvCover {
	// 	log.Logf(0, "oldSig %v, before FromRawL, SvCover : %x", oldSigString, i)
	// }
	inputSvCover := signal.FromRawL(item.info.SvCover, prio)
	inputProgSvCover := signal.FromRawL(item.info.ProgSvCover, prio)
	inputSvExtremum := signal.FromRawExtremum(item.info.SvExtremum, prio)
	// for _, i := range inputSvCover.Serialize().Elems {
	// 	log.Logf(0, "oldSig %v, after FromRawL, SvCover : %x", oldSigString, i)
	// }
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	// newSvSignal := proc.fuzzer.corpusSvSignalDiff(inputSvSignal)
	newSvSignal := proc.fuzzer.corpusSvSignalDiff(inputSvSignal)
	newSvCover := proc.fuzzer.corpusSvCoverDiff(inputSvCover)
	newSvExtremum := proc.fuzzer.corpusSvExtremumDiff(inputSvExtremum)

	log.Logf(4, "newSignal len: %v, newSvSignal len: %v, newSvCover len: %v, newSvExtremum len: %v", newSignal.Len(), newSvSignal.Len(), newSvCover.Len(), len(newSvExtremum))

	if newSignal.Empty() && newSvSignal.Empty() && newSvCover.Empty() && newSvExtremum.Empty() {
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(3, "%v triaging input for %v (new signal=%v, new svSignal=%v)", proc.fuzzer.name, logCallName, newSignal.Len(), newSvSignal.Len())
	var inputPcCover cover.PcCover
	var inputProgPcCover cover.PcCover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	noNewSvSignal := false
	for i := 0; i < signalRuns; i++ {
		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
		if !reexecutionSuccess(info, &item.info, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				// log.Logf(0, "if notexecuted > signalRuns/2+1 {")
				return // if happens too often, give up
			}
			continue
		}
		thisSignal, thisPcCover, thisProgPcCover, thisSvSignal, thisSvCover, _, thisSvExtremum := getSignalAndCover(item.p, info, item.call)
		newSignal = newSignal.Intersection(thisSignal)
		newSvSignal = newSvSignal.Intersection(thisSvSignal)
		newSvCover = newSvCover.Intersection(thisSvCover)
		newSvExtremum = newSvExtremum.Intersection(thisSvExtremum)
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && newSvCover.Empty() && newSvSignal.Empty() && newSvExtremum.Empty() && item.flags&ProgMinimized == 0 {
			return
		}
		if newSvSignal.Empty() && newSvCover.Empty() && newSvExtremum.Empty() {
			noNewSvSignal = true
		}
		inputPcCover.Merge(thisPcCover)
		inputProgPcCover.Merge(thisProgPcCover)
	}

	if newSignal.Empty() && newSvCover.Empty() && newSvSignal.Empty() && newSvExtremum.Empty() {
		return
	}

	// isNewSvSeed:
	// 5--trigger new sv extremum
	// 4--trigger new sv cover
	// 3--trigger new sv signal and new pc signal. Deprecated
	// 2--only trigger new sv signal
	// 1--state mutation seed
	// 0--nothing about sv
	item.p.IsNewSvSeed = 0
	if noNewSvSignal == false && (newSvSignal.Len() > 0 || newSvCover.Len() > 0 || newSvExtremum.Len() > 0) {
		if newSignal.Len() == 0 {
			if newSvCover.Len() > 0 {
				item.p.IsNewSvSeed = 4
			} else if newSvExtremum.Len() > 0 {
				item.p.IsNewSvSeed = 5
			} else {
				item.p.IsNewSvSeed = 2
			}
		} else {
			item.p.IsNewSvSeed = 3
		}
	}

	// discard useless sv inputs
	oldPathHash := uint32(inputProgSvCover.SvPathHash())
	oldIsNewSvSeed := item.p.IsNewSvSeed
	oldParentSig := item.p.ParentSig
	oldHinted := item.p.Hinted

	if item.p.IsNewSvSeed == -1 {
		// if item.p.IsNewSvSeed == 2 {
		if _, ok := proc.fuzzer.corpus[oldPathHash]; !ok {
			return
		}
	}

	log.Logf(4, "IsNewSvSeed %v, before minimized, newSignal len: %v, newSvSignal len: %v, newSvCover len: %v, newSvExtremum len: %v", item.p.IsNewSvSeed, newSignal.Len(), newSvSignal.Len(), newSvCover.Len(), newSvExtremum.Len())
	if item.flags&ProgMinimized == 0 {
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					log.Logf(1, "StatMinimize execute")
					info := proc.execute(proc.execOptsNoCollide, p1, ProgNormal, StatMinimize)
					if !reexecutionSuccess(info, &item.info, call1) {
						// The call was not executed or failed.
						// log.Logf(0, "StatMinimize reexecution not success")
						continue
					}
					thisSignal, _, _, thisSvSignal, thisSvCover, _, thisSvExtremum := getSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() &&
						newSvSignal.Intersection(thisSvSignal).Len() == newSvSignal.Len() &&
						newSvCover.Intersection(thisSvCover).Len() == newSvCover.Len() &&
						newSvExtremum.Intersection(thisSvExtremum).Len() == newSvExtremum.Len() {
						// avoid minimaztion changes sv values
						// inputSvCover.Intersection(thisSvCover).Len() == thisSvCover.Len() {
						// log.Logf(0, "inputSvCover.Intersection(thisSvCover).Len() %v == thisSvCover.Len() %v checkpass", inputSvCover.Intersection(thisSvCover).Len(), thisSvCover.Len())
						// log.Logf(0, "newSignal.Intersection(thisSignal).Len() == newSignal.Len() checkpass")
						// log.Logf(0, "newSignal.Intersection: %v, newSignal: %v, newSvSignal.Intersection: %v, newSvSignal: %v", newSignal.Intersection(thisSignal).Len(), newSignal.Len(), newSvSignal.Intersection(thisSvSignal).Len(), newSvSignal.Len())
						return true
					}
				}
				return false
			})
	}

	item.p.IsNewSvSeed = oldIsNewSvSeed
	item.p.ParentSig = oldParentSig
	item.p.Hinted = oldHinted
	var realSvCover, realProgSvCover signal.SvCover

	// if item.p.IsNewSvSeed != 2 {
	if item.p.IsNewSvSeed != -1 {
		info := proc.executeRaw(proc.execOptsCover, item.p, StatMinimize)
		if !reexecutionSuccess(info, &item.info, item.call) {
			return
		}
		_, _, _, _, realSvCover, realProgSvCover, _ = getSignalAndCover(item.p, info, item.call)
		item.p.PathHash = uint32(realProgSvCover.SvPathHash())
	} else {
		// as for sv inputs, still use old pathHash, in case of changing PathHash after minimize
		info := proc.executeRaw(proc.execOptsCover, item.p, StatMinimize)
		if !reexecutionSuccess(info, &item.info, item.call) {
			return
		}
		_, _, _, _, realSvCover, realProgSvCover, _ = getSignalAndCover(item.p, info, item.call)
		item.p.PathHash = oldPathHash
	}

	data := item.p.Serialize()
	sig := hash.Hash(data)
	sigString := hash.String(item.p.Serialize())

	log.Logf(2, "IsNewSvSeed %v, sv coverage %v, added new input for %v to corpus:\n%s", item.p.IsNewSvSeed, len(inputSvSignal.Serialize().Elems), logCallName, data)

	if item.p.IsNewSvSeed == 5 {
		sigString = sigString + "_extremum"
		proc.fuzzer.sendInputToManager(rpctype.RPCInput{
			Call:           callName,
			Prog:           data,
			Signal:         make(signal.Signal, 0).Serialize(),
			SvSignal:       make(signal.Signal, 0).Serialize(),
			PcCover:        make([]uint32, 0),
			ProgPcCover:    make([]uint32, 0),
			SvCover:        make(signal.SvCover, 0).Serialize(),
			ProgSvCover:    realProgSvCover.Serialize(),
			SvExtremum:     inputSvExtremum,
			PathHash:       0xbeefdead,
			TimeStamp:      time.Now().Unix(),
			IsNewSvSeed:    item.p.IsNewSvSeed,
			ParentSig:      item.p.ParentSig,
			PcCoverChanges: 0,
			SvCoverChanges: 0,
		})
		log.Logf(2, "send to manager for extremum: %v, old sig: %v", sigString, oldSigString)
		proc.fuzzer.addSvExtremumInputToCorpus(item.p, inputSvExtremum, sig)
		return
	}
	// for _, i := range inputSvCover.Serialize().Elems {
	// 	log.Logf(0, "save sig %v, SvCover : %x", sigString, i)
	// }

	// for _, i := range inputSvSignal.Serialize().Elems {
	// 	log.Logf(0, "save sig %v, SvSignal : %x", sigString, i)
	// }

	// if item.p.IsNewSvSeed != 2 {
	if item.p.IsNewSvSeed != -1 {
		proc.fuzzer.sendInputToManager(rpctype.RPCInput{
			Call:           callName,
			Prog:           data,
			Signal:         inputSignal.Serialize(),
			SvSignal:       inputSvSignal.Serialize(),
			PcCover:        inputPcCover.Serialize(),
			ProgPcCover:    inputProgPcCover.Serialize(),
			SvCover:        realSvCover.Serialize(),
			ProgSvCover:    realProgSvCover.Serialize(),
			SvExtremum:     inputSvExtremum,
			PathHash:       item.p.PathHash,
			TimeStamp:      time.Now().Unix(),
			IsNewSvSeed:    item.p.IsNewSvSeed,
			ParentSig:      item.p.ParentSig,
			PcCoverChanges: 0,
			SvCoverChanges: 0,
		})
		log.Logf(2, "send to manager: %v, old sig: %v", sigString, oldSigString)
		// for _, i := range inputPcCover.Serialize() {
		// 	log.Logf(0, "PcCover : %x", i)
		// }
		// for _, i := range realSvCover.Serialize().Elems {
		// 	log.Logf(0, "SvCover : %x", i)
		// }
	} else {
		if _, ok := proc.fuzzer.corpus[uint32(item.p.PathHash)]; ok {
			proc.fuzzer.sendInputToManager(rpctype.RPCInput{
				Call:           callName,
				Prog:           data,
				Signal:         inputSignal.Serialize(),
				SvSignal:       inputSvSignal.Serialize(),
				PcCover:        inputPcCover.Serialize(),
				ProgPcCover:    inputProgPcCover.Serialize(),
				SvCover:        realSvCover.Serialize(),
				ProgSvCover:    realProgSvCover.Serialize(),
				SvExtremum:     inputSvExtremum,
				PathHash:       item.p.PathHash,
				TimeStamp:      time.Now().Unix(),
				IsNewSvSeed:    item.p.IsNewSvSeed,
				ParentSig:      item.p.ParentSig,
				PcCoverChanges: 0,
				SvCoverChanges: 0,
			})
		}
		log.Logf(2, "send to manager: %v, old sig: %v", sigString, oldSigString)
		// for _, i := range inputPcCover.Serialize() {
		// 	log.Logf(0, "PcCover : %x", i)
		// }
		// for _, i := range realSvCover.Serialize().Elems {
		// 	log.Logf(0, "SvCover : %x", i)
		// }
	}

	// proc.fuzzer.addInputToCorpus(item.p, inputSignal, inputSvSignal, sig)
	// if item.p.IsNewSvSeed != 2 {
	if item.p.IsNewSvSeed != -1 {
		proc.fuzzer.addInputToCorpus(item.p, inputSignal, inputSvSignal, inputSvCover, inputSvExtremum, sig)
	} else {
		proc.fuzzer.addSvInputToCorpus(item.p, inputSignal, inputSvSignal, inputSvCover, inputSvExtremum, sig)
	}

	if item.flags&ProgSmashed == 0 {
		proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
	}
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		// log.Logf(0, "reexecutionSuccess? info %v == nil || len(info.Calls) %v == 0", info, len(info.Calls))
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			// log.Logf(0, "reexecutionSuccess? oldInfo.Errno %v == 0 && info.Calls[call].Errno %v != 0", oldInfo.Errno, info.Calls[call].Errno)
			return false
		}
		// log.Logf(0, "reexecutionSuccess? len(info.Calls[call].Signal) %v != 0 || len(info.Calls[call].SvSignal) %v != 0", len(info.Calls[call].Signal), len(info.Calls[call].SvSignal))
		return len(info.Calls[call].Signal) != 0 || len(info.Calls[call].SvSignal) != 0 || len(info.Calls[call].SvCover) != 0
	}
	// log.Logf(0, "reexecutionSuccess? len(info.Extra.Signal) %v != 0 || len(info.Extra.SvSignal) %v != 0", len(info.Extra.Signal), len(info.Extra.SvSignal))
	return len(info.Extra.Signal) != 0 || len(info.Extra.SvSignal) != 0 || len(info.Extra.SvCover) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32, []uint32, signal.Signal, signal.SvCover, signal.SvCover, signal.SvExtremum) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.PcCover, inf.ProgPcCover, signal.FromRaw(inf.SvSignal, signalPrio(p, inf, call)), signal.FromRawL(inf.SvCover, signalPrio(p, inf, call)), signal.FromRawL(inf.ProgSvCover, signalPrio(p, inf, call)), signal.FromRawExtremum(inf.SvExtremum, signalPrio(p, inf, call))
}

func (proc *Proc) smashInput(item *WorkSmash) {
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 {
		proc.failCall(item.p, item.call)
	}
	// svMutationPeriod := 2
	sig := hash.String(item.p.Serialize())
	if item.p.IsNewSvSeed == 5 {
		sig = sig + "_extremum"
	}
	// filter item.p.IsNewSvSeed==2, for such kind of seeds may smash too many times
	// if proc.fuzzer.comparisonTracingEnabled && item.call != -1 && item.p.IsNewSvSeed != 2 {
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
		proc.executeHintSeed(item.p, item.call)
		proc.fuzzer.corpusMu.Lock()
		proc.fuzzer.corpusHintCnt[sig]++
		proc.fuzzer.corpusMu.Unlock()
	}
	fuzzerSnapshot := proc.fuzzer.snapshot()
	// log.Logf(0, "item.p.IsNewSvSeed: %v", item.p.IsNewSvSeed)
	if item.p.IsNewSvSeed == 2 || item.p.IsNewSvSeed == 4 || item.p.IsNewSvSeed == 5 {
		// return
		// inputs may be useless
		for i := 0; i < 25; i++ {
			p0 := item.p.Clone()
			p1 := item.p.Clone()
			p0.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
			log.Logf(0, "#%v: sv input smash mutated from %v", proc.pid, sig)
			proc.execute(proc.execOpts, p0, ProgNormal, StatSmash)
			proc.fuzzer.corpusMu.Lock()
			proc.fuzzer.corpusMutationCnt[sig]++
			proc.fuzzer.corpusMu.Unlock()
			// if proc.rnd.Intn(svMutationPeriod)%svMutationPeriod == 0 {
			p1.SvMutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
			log.Logf(0, "#%v: sv mutated from %v", proc.pid, sig)
			proc.execute(proc.execOpts, p1, ProgNormal, StatSmash)
			// }
		}
	} else {
		for i := 0; i < 100; i++ {
			p0 := item.p.Clone()
			p1 := item.p.Clone()
			p0.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
			log.Logf(0, "#%v: smash mutated from %v", proc.pid, sig)
			proc.execute(proc.execOpts, p0, ProgNormal, StatSmash)
			proc.fuzzer.corpusMu.Lock()
			proc.fuzzer.corpusMutationCnt[sig]++
			proc.fuzzer.corpusMu.Unlock()
			if item.p.IsNewSvSeed == 3 && proc.rnd.Intn(5)%5 == 0 {
				p1.SvMutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
				log.Logf(0, "#%v: sv mutated from %v", proc.pid, sig)
				proc.execute(proc.execOpts, p1, ProgNormal, StatSmash)
			}
		}
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 0; nth < 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		opts := *proc.execOpts
		opts.Flags |= ipc.FlagInjectFault
		opts.FaultCall = call
		opts.FaultNth = nth
		info := proc.executeRaw(&opts, p, StatSmash)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	p.Hinted++

	if p.IsNewSvSeed == 0 || p.IsNewSvSeed == 3 {
		// on/off
		if true {
			// First execute the original program to dump comparisons from KCOV.
			log.Logf(1, "#%v: collecting comparisons", proc.pid)
			info := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
			if info != nil {
				// Then mutate the initial program for every match between
				// a syscall argument and a comparison operand.
				// Execute each of such mutants to check if it gives new coverage.
				p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
					log.Logf(1, "#%v: executing comparison hint", proc.pid)
					proc.execute(proc.execOpts, p, ProgNormal, StatHint)
				})
			}
		}
	}

	if p.IsNewSvSeed == 3 || p.IsNewSvSeed == 4 {
		log.Logf(1, "#%v: collecting sv comparisons", proc.pid)
		info2 := proc.execute(proc.execOpts, p, ProgNormal, StatSeed)
		if info2 != nil {
			log.Logf(0, "ready for sv hint, SvComps Len: %v", len(info2.Calls[call].SvComps))
			// for k, v := range info2.Calls[call].SvComps {
			// 	for kk, _ := range v {
			// 		log.Logf(0, "Hint for %v:%v", int32(k), int32(kk))
			// 	}
			// }
			p.MutateWithHints(call, info2.Calls[call].SvComps, func(p *prog.Prog) {
				log.Logf(1, "#%v: executing sv comparison hint", proc.pid)
				proc.execute(proc.execOpts, p, ProgNormal, StatHint)
			})
		}
	}

	p.Hinted++
	log.Logf(1, "p.Hinted++: %v", p.Hinted)
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) *ipc.ProgInfo {
	info := proc.executeRaw(execOpts, p, stat)
	calls, extra := proc.fuzzer.checkNewSignal(p, info)
	for _, callIndex := range calls {
		// sig := hash.String(p.Serialize())
		// log.Logf(0, "enqueueCallTriage, info.Calls[callIndex].SvCover len: %v, sig %v", len(info.Calls[callIndex].SvCover), sig)
		proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
	}
	if extra {
		// sig := hash.String(p.Serialize())
		// log.Logf(0, "enqueueCallTriage, info.Extra.SvCover len: %v, sig %v", len(info.Extra.SvCover), sig)
		proc.enqueueCallTriage(p, flags, -1, info.Extra)
	}
	return info
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	info.SvSignal = append([]uint32{}, info.SvSignal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.PcCover = nil
	info.SvCover = append([]uint64{}, info.SvCover...)
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		p:     p.Clone(),
		call:  callIndex,
		info:  info,
		flags: flags,
	})
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) *ipc.ProgInfo {
	if opts.Flags&ipc.FlagDedupCover == 0 {
		log.Fatalf("dedup cover is not enabled")
	}
	var sig string
	// if len(proc.fuzzer.procs) == 1 {
	// 	sig = hash.String(p.Serialize())
	// } else {
	// 	sig = "sig"
	// }
	sig = hash.String(p.Serialize())
	log.Logf(0, "%v executeRaw start, p.IsNewSvSeed %v, sig: %v", proc.fuzzer.name, p.IsNewSvSeed, sig)

	// Limit concurrency window and do leak checking once in a while.
	// modified by sgh0t
	// ticket := proc.fuzzer.gate.Enter()
	// defer proc.fuzzer.gate.Leave(ticket)

	proc.logProgram(opts, p)
	for try := 0; ; try++ {
		atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
		output, info, hanged, err := proc.env.Exec(opts, p)
		if err != nil {
			if try > 10 {
				log.Fatalf("executor %v failed %v times:\n%v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "%v result hanged=%v: %s", proc.fuzzer.name, hanged, output)
		log.Logf(0, "%v executeRaw done, stat %v, sig %v", proc.fuzzer.name, stat, sig)
		proc.fuzzer.corpusMu.Lock()
		for i, content := range info.Calls {
			// log.Logf(0, "executeRaw, inf.SvComps.Len: %v", len(content.SvComps))
			dcs := content.SvCover
			for _, dc := range dcs {
				if _, ok := proc.fuzzer.totalSvCover[dc]; ok {
					proc.fuzzer.totalSvCover[dc]++
				} else {
					proc.fuzzer.totalSvCover[dc] = 1
				}
			}
			dss := content.SvSignal
			for _, ds := range dss {
				if _, ok := proc.fuzzer.totalSvSignal[ds]; ok {
					proc.fuzzer.totalSvSignal[ds]++
				} else {
					proc.fuzzer.totalSvSignal[ds] = 1
				}
			}
			newContent := content
			// on/off: control whether we do state-aware tracing
			// newContent.ProgSvCover = nil
			// newContent.SvCover = nil
			// newContent.SvSignal = nil
			// newContent.SvComps = nil
			// newContent.SvExtremum = nil

			info.Calls[i] = newContent
		}
		proc.fuzzer.corpusMu.Unlock()
		return info
	}
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data := p.Serialize()
	var sig string
	// if len(proc.fuzzer.procs) == 1 {
	// 	sig = hash.String(p.Serialize())
	// } else {
	// 	sig = "sig"
	// }
	sig = hash.String(p.Serialize())
	strOpts := ""
	if opts.Flags&ipc.FlagInjectFault != 0 {
		strOpts = fmt.Sprintf(" (fault-call:%v fault-nth:%v)", opts.FaultCall, opts.FaultNth)
	}

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v %v%v:\n%s\n",
			now.Hour(), now.Minute(), now.Second(), sig,
			proc.pid, strOpts, data)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v%v:\n%s\n",
				proc.pid, strOpts, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			if strOpts != "" {
				fmt.Fprintf(f, "#%v\n", strOpts)
			}
			f.Write(data)
			f.Close()
		}
	default:
		log.Fatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
}

type SvType struct {
	Name   string
	Id     uint32
	Values []int32
}

func ImportSvRanges() (signal.SvRanges, error) {
	var svRangesJson []SvType
	bytes, err := ioutil.ReadFile("sv_range.json")
	if err != nil {
		fmt.Println("ReadFile: ", err.Error())
		return nil, err
	}
	if err := json.Unmarshal(bytes, &svRangesJson); err != nil {
		fmt.Println("sv_range.json Unmarshal: ", err.Error())
		return nil, err
	}

	res := make(map[uint32][]int32)
	log.Logf(0, "[+] ImportSvRanges")
	for _, svInfo := range svRangesJson {
		// log.Logf(0, "svId %v, svName %v, Values Len %v", svInfo.Id, svInfo.Name, len(svInfo.Values))
		res[svInfo.Id] = make([]int32, 0)
		for _, value := range svInfo.Values {
			res[svInfo.Id] = append(res[svInfo.Id], value)
		}
		sort.Slice(res[svInfo.Id], func(i, j int) bool {
			return res[svInfo.Id][i] < res[svInfo.Id][j]
		})
	}
	return res, nil
}

type SvPairType struct {
	Name   string
	Id     uint32
	Values []uint32
}

func ImportSvPairs() (map[uint32][]uint32, error) {
	var svPairJson []SvPairType
	bytes, err := ioutil.ReadFile("sv_pairs.json")
	if err != nil {
		fmt.Println("ReadFile: ", err.Error())
		return nil, err
	}
	if err := json.Unmarshal(bytes, &svPairJson); err != nil {
		fmt.Println("sv_pairs.json Unmarshal: ", err.Error())
		return nil, err
	}

	res := make(map[uint32][]uint32)
	log.Logf(0, "[+] ImportSvPairs")
	for _, svPair := range svPairJson {
		// log.Logf(0, "svNo %v, Values Len %v", svPair.Id, len(svPair.Values))
		// for _, x := range svPair.Values {
		// 	log.Logf(0, "	value %v", x)
		// }
		res[svPair.Id] = make([]uint32, 0)
		for _, value := range svPair.Values {
			res[svPair.Id] = append(res[svPair.Id], value)
		}
		sort.Slice(res[svPair.Id], func(i, j int) bool {
			return res[svPair.Id][i] < res[svPair.Id][j]
		})
	}
	return res, nil
}
