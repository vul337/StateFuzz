// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type RPCServer struct {
	mgr             RPCManagerView
	target          *prog.Target
	enabledSyscalls []int
	stats           *Stats
	sandbox         string
	batchSize       int

	mu               sync.Mutex
	fuzzers          map[string]*Fuzzer
	checkResult      *rpctype.CheckArgs
	maxSignal        signal.Signal
	maxSvSignal      signal.Signal
	maxSvCover       signal.SvCover
	maxSvExtremum    signal.SvExtremum
	corpusSignal     signal.Signal
	corpusSvSignal   signal.Signal
	corpusPcCover    cover.PcCover
	corpusSvCover    signal.SvCover
	corpusSvExtremum signal.SvExtremum
	rotator          *prog.Rotator
	rnd              *rand.Rand
}

type Fuzzer struct {
	name             string
	inputs           []rpctype.RPCInput
	newMaxSignal     signal.Signal
	newMaxSvSignal   signal.Signal
	newMaxSvCover    signal.SvCover
	newMaxSvExtremum signal.SvExtremum
	rotatedSignal    signal.Signal
}

type BugFrames struct {
	memoryLeaks []string
	dataRaces   []string
}

// RPCManagerView restricts interface between RPCServer and Manager.
type RPCManagerView interface {
	fuzzerConnect() ([]rpctype.RPCInput, BugFrames)
	machineChecked(result *rpctype.CheckArgs)
	newInput(inp rpctype.RPCInput, sign signal.Signal, svSign signal.Signal, svCover signal.SvCover, svExtremum signal.SvExtremum) bool
	candidateBatch(size int) []rpctype.RPCCandidate
	updateMutationInfo(corpusMutationCnt map[string]uint32, corpusHintCnt map[string]uint32, totalSvCover map[uint64]uint64, totalSvSignal map[uint32]uint64)
	rotateCorpus() bool
}

func startRPCServer(mgr *Manager) (int, error) {
	serv := &RPCServer{
		mgr:              mgr,
		target:           mgr.target,
		enabledSyscalls:  mgr.enabledSyscalls,
		stats:            mgr.stats,
		sandbox:          mgr.cfg.Sandbox,
		fuzzers:          make(map[string]*Fuzzer),
		rnd:              rand.New(rand.NewSource(time.Now().UnixNano())),
		maxSvExtremum:    make(signal.SvExtremum),
		corpusSvExtremum: make(signal.SvExtremum),
	}
	serv.batchSize = 5
	if serv.batchSize < mgr.cfg.Procs {
		serv.batchSize = mgr.cfg.Procs
	}
	s, err := rpctype.NewRPCServer(mgr.cfg.RPC, "Manager", serv)
	if err != nil {
		return 0, err
	}
	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	port := s.Addr().(*net.TCPAddr).Port
	go s.Serve()
	return port, nil
}

func (serv *RPCServer) Connect(a *rpctype.ConnectArgs, r *rpctype.ConnectRes) error {
	log.Logf(1, "fuzzer %v connected", a.Name)
	serv.stats.vmRestarts.inc()

	corpus, bugFrames := serv.mgr.fuzzerConnect()

	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := &Fuzzer{
		name: a.Name,
	}
	serv.fuzzers[a.Name] = f
	r.MemoryLeakFrames = bugFrames.memoryLeaks
	r.DataRaceFrames = bugFrames.dataRaces
	r.EnabledCalls = serv.enabledSyscalls
	r.GitRevision = prog.GitRevision
	r.TargetRevision = serv.target.Revision
	// TODO: temporary disabled b/c we suspect this negatively affects fuzzing.
	if false && serv.mgr.rotateCorpus() && serv.rnd.Intn(3) != 0 {
		// We do rotation every other time because there are no objective
		// proofs regarding its efficiency either way.
		// Also, rotation gives significantly skewed syscall selection
		// (run prog.TestRotationCoverage), it may or may not be OK.
		r.CheckResult = serv.rotateCorpus(f, corpus)
	} else {
		r.CheckResult = serv.checkResult
		f.inputs = corpus
		// added by zbd
		// handle frequent crashes in syz-fuzzer
		// todo power schedule and seed selection
		// now we just make it randomly (shuffle)
		// rand.Seed(time.Now().UnixNano())
		// rand.Shuffle(len(f.inputs), func(i, j int) {
		// 	f.inputs[i], f.inputs[j] = f.inputs[j], f.inputs[i]
		// })
		// added by zbd
		f.newMaxSignal = serv.maxSignal.Copy()
		f.newMaxSvSignal = serv.maxSvSignal.Copy()
		f.newMaxSvCover = serv.maxSvCover.Copy()
		f.newMaxSvExtremum = serv.maxSvExtremum.Copy()
	}

	return nil
}

// todo: should we change rotate for svCover ?
func (serv *RPCServer) rotateCorpus(f *Fuzzer, corpus []rpctype.RPCInput) *rpctype.CheckArgs {
	// Fuzzing tends to stuck in some local optimum and then it fails to cover
	// other state space points since code coverage is only a very approximate
	// measure of logic coverage. To overcome this we introduce some variation
	// into the process which should cause steady corpus rotation over time
	// (the same coverage is achieved in different ways).
	//
	// First, we select a subset of all syscalls for each VM run (result.EnabledCalls).
	// This serves 2 goals: (1) target fuzzer at a particular area of state space,
	// (2) disable syscalls that cause frequent crashes at least in some runs
	// to allow it to do actual fuzzing.
	//
	// Then, we remove programs that contain disabled syscalls from corpus
	// that will be sent to the VM (f.inputs). We also remove 10% of remaining
	// programs at random to allow to rediscover different variations of these programs.
	//
	// Then, we drop signal provided by the removed programs and also 10%
	// of the remaining signal at random (f.newMaxSignal). This again allows
	// rediscovery of this signal by different programs.
	//
	// Finally, we adjust criteria for accepting new programs from this VM (f.rotatedSignal).
	// This allows to accept rediscovered varied programs even if they don't
	// increase overall coverage. As the result we have multiple programs
	// providing the same duplicate coverage, these are removed during periodic
	// corpus minimization process. The minimization process is specifically
	// non-deterministic to allow the corpus rotation.
	//
	// Note: at no point we drop anything globally and permanently.
	// Everything we remove during this process is temporal and specific to a single VM.
	calls := serv.rotator.Select()

	var callIDs []int
	callNames := make(map[string]bool)
	for call := range calls {
		callNames[call.Name] = true
		callIDs = append(callIDs, call.ID)
	}

	f.inputs, f.newMaxSignal = serv.selectInputs(callNames, corpus, serv.maxSignal)
	// Remove the corresponding signal from rotatedSignal which will
	// be used to accept new inputs from this manager.
	f.rotatedSignal = serv.corpusSignal.Intersection(f.newMaxSignal)

	result := *serv.checkResult
	result.EnabledCalls = map[string][]int{serv.sandbox: callIDs}
	return &result
}

func (serv *RPCServer) selectInputs(enabled map[string]bool, inputs0 []rpctype.RPCInput, signal0 signal.Signal) (
	inputs []rpctype.RPCInput, signal signal.Signal) {
	signal = signal0.Copy()
	for _, inp := range inputs0 {
		calls, _, err := prog.CallSet(inp.Prog)
		if err != nil {
			panic(fmt.Sprintf("rotateInputs: CallSet failed: %v\n%s", err, inp.Prog))
		}
		for call := range calls {
			if !enabled[call] {
				goto drop
			}
		}
		if serv.rnd.Float64() > 0.9 {
			goto drop
		}
		inputs = append(inputs, inp)
		continue
	drop:
		for _, sig := range inp.Signal.Elems {
			delete(signal, sig)
		}
	}
	signal.Split(len(signal) / 10)
	return inputs, signal
}

func (serv *RPCServer) Check(a *rpctype.CheckArgs, r *int) error {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	if serv.checkResult != nil {
		return nil
	}
	serv.mgr.machineChecked(a)
	a.DisabledCalls = nil
	serv.checkResult = a
	calls := make(map[*prog.Syscall]bool)
	for _, call := range a.EnabledCalls[serv.sandbox] {
		calls[serv.target.Syscalls[call]] = true
	}
	serv.rotator = prog.MakeRotator(serv.target, calls, serv.rnd)
	return nil
}

func (serv *RPCServer) NewInput(a *rpctype.NewInputArgs, r *int) error {
	inputSignal := a.RPCInput.Signal.Deserialize()
	inputSvSignal := a.RPCInput.SvSignal.Deserialize()
	inputSvCover := a.RPCInput.SvCover.Deserialize()
	inputSvExtremum := a.RPCInput.SvExtremum
	log.Logf(4, "new input from %v for syscall %v (signal=%v, svSignal=%v, PcCover=%v, SvCover=%v, SvExtremum=%v)",
		a.Name, a.RPCInput.Call, inputSignal.Len(), inputSvSignal.Len(), len(a.RPCInput.PcCover), inputSvCover.Len(), inputSvExtremum.Len())
	p, err := serv.target.Deserialize(a.RPCInput.Prog, prog.NonStrict)
	if err != nil {
		// This should not happen, but we see such cases episodically (probably corrupted VM memory).
		log.Logf(0, "failed to deserialize program from fuzzer: %v\n%s", err, a.RPCInput.Prog)
		return nil
	}
	if len(p.Calls) > prog.MaxCalls {
		log.Logf(0, "rejecting too long program from fuzzer: %v calls\n%s", len(p.Calls), a.RPCInput.Prog)
		return nil
	}
	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	genuine := (!serv.corpusSignal.Diff(inputSignal).Empty() || !serv.corpusSvSignal.Diff(inputSvSignal).Empty() || !serv.corpusSvCover.Diff(inputSvCover).Empty() || !serv.corpusSvExtremum.Diff(inputSvExtremum).Empty())
	rotated := false
	if !genuine && f.rotatedSignal != nil {
		rotated = !f.rotatedSignal.Diff(inputSignal).Empty()
	}
	if !genuine && !rotated {
		return nil
	}
	if !serv.mgr.newInput(a.RPCInput, inputSignal, inputSvSignal, inputSvCover, inputSvExtremum) {
		return nil
	}

	if f.rotatedSignal != nil {
		f.rotatedSignal.Merge(inputSignal)
	}
	serv.corpusPcCover.Merge(a.RPCInput.PcCover)
	serv.stats.corpusPcCover.set(len(serv.corpusPcCover))
	serv.stats.newInputs.inc()
	if a.RPCInput.IsNewSvSeed == 2 || a.RPCInput.IsNewSvSeed == 4 || a.RPCInput.IsNewSvSeed == 5 {
		serv.stats.svCorpus.inc()
	}
	if rotated {
		serv.stats.rotatedInputs.inc()
	}

	if genuine {
		serv.corpusSignal.Merge(inputSignal)
		serv.corpusSvCover.Merge(inputSvCover)
		serv.corpusSvSignal.Merge(inputSvSignal)
		serv.corpusSvExtremum.Merge(inputSvExtremum)
		// log.Logf(0, "serv.corpusSvCover.Merge(inputSvCover) done, len: %v", len(inputSvCover))
		serv.stats.corpusSignal.set(serv.corpusSignal.Len())
		serv.stats.corpusSvCover.set(serv.corpusSvCover.Len())
		serv.stats.corpusSvSignal.set(serv.corpusSvSignal.Len())

		a.RPCInput.PcCover = nil // Don't send coverage back to all fuzzers.
		for _, other := range serv.fuzzers {
			if other == f {
				continue
			}
			other.inputs = append(other.inputs, a.RPCInput)
		}
	}
	return nil
}

func (serv *RPCServer) Poll(a *rpctype.PollArgs, r *rpctype.PollRes) error {
	// timeStr1 := time.Now().Format("2006/01/02 15:04:05 ")
	// fmt.Printf("%v [+] poll start in syz-manager\n", timeStr1)
	serv.stats.mergeNamed(a.Stats)
	serv.mgr.updateMutationInfo(a.CorpusMutationCnt, a.CorpusHintCnt, a.TotalSvCover, a.TotalSvSignal)

	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	if f == nil {
		log.Fatalf("fuzzer %v is not connected", a.Name)
	}
	newMaxSignal := serv.maxSignal.Diff(a.MaxSignal.Deserialize())
	newMaxSvSignal := serv.maxSvSignal.Diff(a.MaxSvSignal.Deserialize())
	newMaxSvCover := serv.maxSvCover.Diff(a.MaxSvCover.Deserialize())
	newMaxSvExtremum := serv.maxSvExtremum.Diff(a.MaxSvExtremum)
	if !newMaxSignal.Empty() {
		serv.maxSignal.Merge(newMaxSignal)
		for _, f1 := range serv.fuzzers {
			if f1 == f {
				continue
			}
			f1.newMaxSignal.Merge(newMaxSignal)
		}
	}
	if !newMaxSvSignal.Empty() {
		serv.maxSvSignal.Merge(newMaxSvSignal)
		for _, f1 := range serv.fuzzers {
			if f1 == f {
				continue
			}
			f1.newMaxSvSignal.Merge(newMaxSvSignal)
		}
	}
	if !newMaxSvCover.Empty() {
		serv.maxSvCover.Merge(newMaxSvCover)
		for _, f1 := range serv.fuzzers {
			if f1 == f {
				continue
			}
			f1.newMaxSvCover.Merge(newMaxSvCover)
		}
	}
	if !newMaxSvExtremum.Empty() {
		serv.maxSvExtremum.Merge(newMaxSvExtremum)
		for _, f1 := range serv.fuzzers {
			if f1 == f {
				continue
			}
			f1.newMaxSvExtremum.Merge(newMaxSvExtremum)
		}
	}
	r.MaxSignal = f.newMaxSignal.Split(500).Serialize()
	r.MaxSvSignal = f.newMaxSvSignal.Split(500).Serialize()
	r.MaxSvCover = f.newMaxSvCover.Split(500).Serialize()
	r.MaxSvExtremum = f.newMaxSvExtremum.Split(100)
	if a.NeedCandidates {
		r.Candidates = serv.mgr.candidateBatch(serv.batchSize)
	}
	if len(r.Candidates) == 0 {
		batchSize := serv.batchSize
		// When the fuzzer starts, it pumps the whole corpus.
		// If we do it using the final batchSize, it can be very slow
		// (batch of size 6 can take more than 10 mins for 50K corpus and slow kernel).
		// So use a larger batch initially (we use no stats as approximation of initial pump).
		const initialBatch = 30
		if len(a.Stats) == 0 && batchSize < initialBatch {
			batchSize = initialBatch
		}
		for i := 0; i < batchSize && len(f.inputs) > 0; i++ {
			last := len(f.inputs) - 1
			r.NewInputs = append(r.NewInputs, f.inputs[last])
			f.inputs[last] = rpctype.RPCInput{}
			f.inputs = f.inputs[:last]
		}
		if len(f.inputs) == 0 {
			f.inputs = nil
		}
	}
	log.Logf(4, "poll from %v: candidates=%v inputs=%v svInputs=%v maxsignal=%v maxSvSignal=%v maxSvCover=%v maxSvExtremum=%v",
		a.Name, len(r.Candidates), len(r.NewInputs), len(r.NewInputs), len(r.MaxSignal.Elems), len(r.MaxSvSignal.Elems), len(r.MaxSvCover.Elems), len(r.MaxSvExtremum))
	// timeStr2 := time.Now().Format("2006/01/02 15:04:05 ")
	// fmt.Printf("%v [+] poll end in syz-manager\n", timeStr2)
	return nil
}
