// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"

	// "sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type Fuzzer struct {
	name              string
	outputType        OutputType
	config            *ipc.Config
	execOpts          *ipc.ExecOpts
	procs             []*Proc
	gate              *ipc.Gate
	workQueue         *WorkQueue
	needPoll          chan struct{}
	choiceTable       *prog.ChoiceTable
	stats             [StatCount]uint64
	manager           *rpctype.RPCClient
	target            *prog.Target
	triagedCandidates uint32

	faultInjectionEnabled    bool
	comparisonTracingEnabled bool

	corpusMu sync.RWMutex
	// corpus       []*prog.Prog
	// key: hash(signal[]), value: seed bucket
	corpus       map[uint32][]*prog.Prog
	corpusPrios  map[uint32][]int64
	sumPrios     map[uint32]int64
	corpusHashes map[hash.Sig]struct{}

	signalMu     sync.RWMutex
	corpusSignal signal.Signal // signal of inputs in corpus
	maxSignal    signal.Signal // max signal ever observed including flakes
	newSignal    signal.Signal // diff of maxSignal since last sync with master
	logMu        sync.Mutex

	// SvSignalMu        sync.RWMutex
	corpusSvSignal    signal.Signal  // sv signal of inputs in corpus
	corpusSvCover     signal.SvCover // sv coverage of inputs in corpus
	maxSvSignal       signal.Signal  // max sv coverage ever observed including flakes
	maxSvCover        signal.SvCover // max sv coverage ever observed including flakes
	newSvSignal       signal.Signal  // diff of max sv signal since last sync with master
	newSvCover        signal.SvCover // diff of max sv coverage since last sync with master
	corpusSvExtremum  signal.SvExtremum
	maxSvExtremum     signal.SvExtremum
	newSvExtremum     signal.SvExtremum
	corpusMutationCnt map[string]uint32
	corpusHintCnt     map[string]uint32
	totalSvCover      map[uint64]uint64 // SvCover of all executed program
	totalSvSignal     map[uint32]uint64 // SvSignal of all executed program
}

type FuzzerSnapshot struct {
	corpus      map[uint32][]*prog.Prog
	corpusPrios map[uint32][]int64
	sumPrios    map[uint32]int64
}

type Stat int

const (
	StatGenerate Stat = iota
	StatFuzz
	StatCandidate
	StatTriage
	StatMinimize
	StatSmash
	StatHint
	StatSeed
	StatCount
)

var statNames = [StatCount]string{
	StatGenerate:  "exec gen",
	StatFuzz:      "exec fuzz",
	StatCandidate: "exec candidate",
	StatTriage:    "exec triage",
	StatMinimize:  "exec minimize",
	StatSmash:     "exec smash",
	StatHint:      "exec hints",
	StatSeed:      "exec seeds",
}

type OutputType int

const (
	OutputNone OutputType = iota
	OutputStdout
	OutputDmesg
	OutputFile
)

func main() {
	debug.SetGCPercent(50)

	var (
		flagName    = flag.String("name", "test", "unique name for manager")
		flagOS      = flag.String("os", runtime.GOOS, "target OS")
		flagArch    = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager = flag.String("manager", "", "manager rpc address")
		flagProcs   = flag.Int("procs", 1, "number of parallel test processes")
		flagOutput  = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagPprof   = flag.String("pprof", "", "address to serve pprof profiles")
		flagTest    = flag.Bool("test", false, "enable image testing mode")      // used by syz-ci
		flagRunTest = flag.Bool("runtest", false, "enable program testing mode") // used by pkg/runtest
	)
	flag.Parse()
	outputType := parseOutputType(*flagOutput)
	log.Logf(0, "fuzzer started")

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("failed to create default ipc config: %v", err)
	}
	sandbox := ipc.FlagsToSandbox(config.Flags)
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		log.Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	checkArgs := &checkArgs{
		target:      target,
		sandbox:     sandbox,
		ipcConfig:   config,
		ipcExecOpts: execOpts,
	}
	if *flagTest {
		testImage(*flagManager, checkArgs)
		return
	}

	if *flagPprof != "" {
		go func() {
			err := http.ListenAndServe(*flagPprof, nil)
			log.Fatalf("failed to serve pprof profiles: %v", err)
		}()
	} else {
		runtime.MemProfileRate = 0
	}

	log.Logf(0, "dialing manager at %v", *flagManager)
	manager, err := rpctype.NewRPCClient(*flagManager)
	if err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}
	a := &rpctype.ConnectArgs{Name: *flagName}
	r := &rpctype.ConnectRes{}
	if err := manager.Call("Manager.Connect", a, r); err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}
	featureFlags, err := csource.ParseFeaturesFlags("none", "none", true)
	if err != nil {
		log.Fatal(err)
	}
	if r.CheckResult == nil {
		checkArgs.gitRevision = r.GitRevision
		checkArgs.targetRevision = r.TargetRevision
		checkArgs.enabledCalls = r.EnabledCalls
		checkArgs.allSandboxes = r.AllSandboxes
		checkArgs.featureFlags = featureFlags
		r.CheckResult, err = checkMachine(checkArgs)
		if err != nil {
			if r.CheckResult == nil {
				r.CheckResult = new(rpctype.CheckArgs)
			}
			r.CheckResult.Error = err.Error()
		}
		r.CheckResult.Name = *flagName
		if err := manager.Call("Manager.Check", r.CheckResult, nil); err != nil {
			log.Fatalf("Manager.Check call failed: %v", err)
		}
		if r.CheckResult.Error != "" {
			log.Fatalf("%v", r.CheckResult.Error)
		}
	} else {
		if err = host.Setup(target, r.CheckResult.Features, featureFlags, config.Executor); err != nil {
			log.Fatal(err)
		}
	}
	log.Logf(0, "syscalls: %v", len(r.CheckResult.EnabledCalls[sandbox]))
	for _, feat := range r.CheckResult.Features.Supported() {
		log.Logf(0, "%v: %v", feat.Name, feat.Reason)
	}
	if r.CheckResult.Features[host.FeatureExtraCoverage].Enabled {
		config.Flags |= ipc.FlagExtraCover
	}
	if r.CheckResult.Features[host.FeatureNetInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if r.CheckResult.Features[host.FeatureNetDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	config.Flags |= ipc.FlagEnableNetReset
	config.Flags |= ipc.FlagEnableCgroups
	config.Flags |= ipc.FlagEnableCloseFds
	if r.CheckResult.Features[host.FeatureDevlinkPCI].Enabled {
		config.Flags |= ipc.FlagEnableDevlinkPCI
	}

	if *flagRunTest {
		runTest(target, manager, *flagName, config.Executor)
		return
	}

	needPoll := make(chan struct{}, 1)
	needPoll <- struct{}{}
	fuzzer := &Fuzzer{
		name:                     *flagName,
		outputType:               outputType,
		config:                   config,
		execOpts:                 execOpts,
		workQueue:                newWorkQueue(*flagProcs, needPoll),
		needPoll:                 needPoll,
		manager:                  manager,
		target:                   target,
		faultInjectionEnabled:    r.CheckResult.Features[host.FeatureFault].Enabled,
		comparisonTracingEnabled: r.CheckResult.Features[host.FeatureComparisons].Enabled,
		corpusHashes:             make(map[hash.Sig]struct{}),
		corpus:                   make(map[uint32][]*prog.Prog),
		corpusPrios:              make(map[uint32][]int64),
		sumPrios:                 make(map[uint32]int64),
		corpusMutationCnt:        make(map[string]uint32),
		corpusHintCnt:            make(map[string]uint32),
		totalSvCover:             make(map[uint64]uint64),
		totalSvSignal:            make(map[uint32]uint64),
		corpusSvExtremum:         make(signal.SvExtremum),
		maxSvExtremum:            make(signal.SvExtremum),
		newSvExtremum:            make(signal.SvExtremum),
	}
	gateCallback := fuzzer.useBugFrames(r, *flagProcs)
	fuzzer.gate = ipc.NewGate(2**flagProcs, gateCallback)

	for i := 0; fuzzer.poll(i == 0, nil); i++ {
	}
	calls := make(map[*prog.Syscall]bool)
	for _, id := range r.CheckResult.EnabledCalls[sandbox] {
		calls[target.Syscalls[id]] = true
	}

	fuzzer.choiceTable = target.BuildChoiceTableFuzzer(fuzzer.corpus, calls)

	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzer, pid)
		if err != nil {
			log.Fatalf("failed to create proc: %v", err)
		}
		fuzzer.procs = append(fuzzer.procs, proc)
		go proc.loop()
	}

	fuzzer.pollLoop()
}

// Returns gateCallback for leak checking if enabled.
func (fuzzer *Fuzzer) useBugFrames(r *rpctype.ConnectRes, flagProcs int) func() {
	var gateCallback func()

	if r.CheckResult.Features[host.FeatureLeak].Enabled {
		gateCallback = func() { fuzzer.gateCallback(r.MemoryLeakFrames) }
	}

	if r.CheckResult.Features[host.FeatureKCSAN].Enabled && len(r.DataRaceFrames) != 0 {
		fuzzer.blacklistDataRaceFrames(r.DataRaceFrames)
	}

	return gateCallback
}

func (fuzzer *Fuzzer) gateCallback(leakFrames []string) {
	// Leak checking is very slow so we don't do it while triaging the corpus
	// (otherwise it takes infinity). When we have presumably triaged the corpus
	// (triagedCandidates == 1), we run leak checking bug ignore the result
	// to flush any previous leaks. After that (triagedCandidates == 2)
	// we do actual leak checking and report leaks.
	triagedCandidates := atomic.LoadUint32(&fuzzer.triagedCandidates)
	if triagedCandidates == 0 {
		return
	}
	args := append([]string{"leak"}, leakFrames...)
	output, err := osutil.RunCmd(10*time.Minute, "", fuzzer.config.Executor, args...)
	if err != nil && triagedCandidates == 2 {
		// If we exit right away, dying executors will dump lots of garbage to console.
		os.Stdout.Write(output)
		fmt.Printf("BUG: leak checking failed")
		time.Sleep(time.Hour)
		os.Exit(1)
	}
	if triagedCandidates == 1 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 2)
	}
}

func (fuzzer *Fuzzer) blacklistDataRaceFrames(frames []string) {
	args := append([]string{"setup_kcsan_blacklist"}, frames...)
	output, err := osutil.RunCmd(10*time.Minute, "", fuzzer.config.Executor, args...)
	if err != nil {
		log.Fatalf("failed to set KCSAN blacklist: %v", err)
	}
	log.Logf(0, "%s", output)
}

func (fuzzer *Fuzzer) pollLoop() {
	var execTotal uint64
	var lastPoll time.Time
	var lastPrint time.Time
	ticker := time.NewTicker(3 * time.Second).C
	for {
		poll := false
		select {
		case <-ticker:
		case <-fuzzer.needPoll:
			poll = true
		}
		if fuzzer.outputType != OutputStdout && time.Since(lastPrint) > 10*time.Second {
			// Keep-alive for manager.
			log.Logf(0, "alive, executed %v", execTotal)
			lastPrint = time.Now()
		}
		if poll || time.Since(lastPoll) > 10*time.Second {
			needCandidates := fuzzer.workQueue.wantCandidates()
			if poll && !needCandidates {
				continue
			}
			stats := make(map[string]uint64)
			for _, proc := range fuzzer.procs {
				stats["exec total"] += atomic.SwapUint64(&proc.env.StatExecs, 0)
				stats["executor restarts"] += atomic.SwapUint64(&proc.env.StatRestarts, 0)
			}
			for stat := Stat(0); stat < StatCount; stat++ {
				v := atomic.SwapUint64(&fuzzer.stats[stat], 0)
				stats[statNames[stat]] = v
				execTotal += v
			}
			if !fuzzer.poll(needCandidates, stats) {
				lastPoll = time.Now()
			}
		}
	}
}

func (fuzzer *Fuzzer) poll(needCandidates bool, stats map[string]uint64) bool {
	// timeStr1 := time.Now().Format("2006/01/02 15:04:05 ")
	// fmt.Printf("%v [+] poll start in syz-fuzzer\n", timeStr1)
	fuzzer.corpusMu.RLock()
	corpusMutationCntCopy := make(map[string]uint32)
	corpusHintCntCopy := make(map[string]uint32)
	totalSvCoverCopy := make(map[uint64]uint64)
	totalSvSignalCopy := make(map[uint32]uint64)
	for k, m := range fuzzer.corpusMutationCnt {
		corpusMutationCntCopy[k] = m
	}
	for k, m := range fuzzer.corpusHintCnt {
		corpusHintCntCopy[k] = m
	}
	for k, m := range fuzzer.totalSvCover {
		totalSvCoverCopy[k] = m
	}
	for k, m := range fuzzer.totalSvSignal {
		totalSvSignalCopy[k] = m
	}
	fuzzer.corpusMu.RUnlock()
	a := &rpctype.PollArgs{
		Name:              fuzzer.name,
		NeedCandidates:    needCandidates,
		MaxSignal:         fuzzer.grabNewSignal().Serialize(),
		MaxSvSignal:       fuzzer.grabNewSvSignal().Serialize(),
		MaxSvCover:        fuzzer.grabNewSvCover().Serialize(),
		MaxSvExtremum:     fuzzer.grabNewSvExtremum(),
		Stats:             stats,
		CorpusMutationCnt: corpusMutationCntCopy,
		CorpusHintCnt:     corpusHintCntCopy,
		TotalSvCover:      totalSvCoverCopy,
		TotalSvSignal:     totalSvSignalCopy,
	}
	r := &rpctype.PollRes{}
	// log.Logf(0, "[+] fuzzer start poll")
	if err := fuzzer.manager.Call("Manager.Poll", a, r); err != nil {
		log.Fatalf("Manager.Poll call failed: %v", err)
	}
	// log.Logf(0, "[+] fuzzer end poll")
	fuzzer.corpusMu.Lock()
	for sig := range fuzzer.corpusMutationCnt {
		fuzzer.corpusMutationCnt[sig] = 0
	}
	for sig := range fuzzer.corpusHintCnt {
		fuzzer.corpusHintCnt[sig] = 0
	}
	fuzzer.totalSvCover = make(map[uint64]uint64)
	fuzzer.totalSvSignal = make(map[uint32]uint64)
	fuzzer.corpusMu.Unlock()
	maxSignal := r.MaxSignal.Deserialize()
	maxSvSignal := r.MaxSvSignal.Deserialize()
	maxSvCover := r.MaxSvCover.Deserialize()
	maxSvExtremum := r.MaxSvExtremum
	log.Logf(1, "poll: candidates=%v inputs=%v svInputs=%v signal=%v svSignal=%v svCover=%v svExtremum=%v",
		len(r.Candidates), len(r.NewInputs), len(r.NewInputs), maxSignal.Len(), maxSvSignal.Len(), maxSvCover.Len(), maxSvExtremum.Len())
	fuzzer.addMaxSignal(maxSignal)
	fuzzer.addMaxSvSignal(maxSvSignal)
	fuzzer.addMaxSvCover(maxSvCover)
	fuzzer.addMaxSvExtremum(maxSvExtremum)
	for _, inp := range r.NewInputs {
		fuzzer.addInputFromAnotherFuzzer(inp)
	}
	for _, candidate := range r.Candidates {
		fuzzer.addCandidateInput(candidate)
	}
	if needCandidates && len(r.Candidates) == 0 && atomic.LoadUint32(&fuzzer.triagedCandidates) == 0 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 1)
	}
	// log.Logf(0, "after poll: ")
	// for svNo, item := range fuzzer.maxSvExtremum {
	// 	log.Logf(0, "svNo: %v, update: %v", svNo, item["update"])
	// }
	// timeStr2 := time.Now().Format("2006/01/02 15:04:05 ")
	// fmt.Printf("%v [+] poll end in syz-fuzzer\n", timeStr2)
	return len(r.NewInputs) != 0 || len(r.Candidates) != 0 || maxSignal.Len() != 0 || maxSvSignal.Len() != 0 || maxSvCover.Len() != 0
}

func (fuzzer *Fuzzer) sendInputToManager(inp rpctype.RPCInput) {
	a := &rpctype.NewInputArgs{
		Name:     fuzzer.name,
		RPCInput: inp,
	}
	if err := fuzzer.manager.Call("Manager.NewInput", a, nil); err != nil {
		log.Fatalf("Manager.NewInput call failed: %v", err)
	}
}

func (fuzzer *Fuzzer) addInputFromAnotherFuzzer(inp rpctype.RPCInput) {
	p := fuzzer.deserializeInput(inp.Prog)
	if p == nil {
		return
	}
	p.IsNewSvSeed = inp.IsNewSvSeed
	p.SvPrio = inp.SvPrio
	p.PathHash = inp.PathHash
	p.Hinted = inp.Hinted
	p.ParentSig = inp.ParentSig
	sig := hash.Hash(inp.Prog)
	sign := inp.Signal.Deserialize()
	svSign := inp.SvSignal.Deserialize()
	svCov := inp.SvCover.Deserialize()
	svExtre := inp.SvExtremum
	if p.IsNewSvSeed == 5 {
		fuzzer.addSvExtremumInputToCorpus(p, svExtre, sig)
		return
	}
	fuzzer.addInputToCorpus(p, sign, svSign, svCov, svExtre, sig)
}

func (fuzzer *Fuzzer) addCandidateInput(candidate rpctype.RPCCandidate) {
	p := fuzzer.deserializeInput(candidate.Prog)
	if p == nil {
		return
	}
	flags := ProgCandidate
	if candidate.Minimized {
		flags |= ProgMinimized
	}
	if candidate.Smashed {
		flags |= ProgSmashed
	}
	fuzzer.workQueue.enqueue(&WorkCandidate{
		p:     p,
		flags: flags,
	})
}

func (fuzzer *Fuzzer) deserializeInput(inp []byte) *prog.Prog {
	p, err := fuzzer.target.Deserialize(inp, prog.NonStrict)
	if err != nil {
		log.Fatalf("failed to deserialize prog: %v\n%s", err, inp)
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil
	}
	return p
}

// func (fuzzer *FuzzerSnapshot) chooseProgram(r *rand.Rand) *prog.Prog {
// 	randVal := r.Int63n(fuzzer.sumPrios + 1)
// 	idx := sort.Search(len(fuzzer.corpusPrios), func(i int) bool {
// 		return fuzzer.corpusPrios[i] >= randVal
// 	})
// 	// fmt.Printf("Choose Program: %v", fuzzer.corpus[idx].String())
// 	fuzzer.corpus[idx].Mutation++
// 	return fuzzer.corpus[idx]
// }

// choose Program randomly
func (fuzzer *FuzzerSnapshot) chooseProgram(r *rand.Rand, i int) *prog.Prog {
	// fmt.Printf("Choose Program: %v", fuzzer.corpus[idx].String())
	var keys []uint32
	for k := range fuzzer.corpus {
		keys = append(keys, k)
	}
	var bucket []*prog.Prog
	var idx int
	var P1, P2 int
	P1 = 3
	P2 = 3

	var key uint32
	prob := r.Intn(P1 * P2)
	// if r.Intn(P1)%P1 != 0 || (len(fuzzer.corpus[0xdeadbeef]) == 0 && len(fuzzer.corpus[0xbeefdead]) == 0) {
	if prob < P2 || (len(fuzzer.corpus[0xdeadbeef]) == 0 && len(fuzzer.corpus[0xbeefdead]) == 0) {
		keyIdx := r.Intn(len(keys))
		for {
			key = keys[keyIdx%len(keys)]
			bucket = fuzzer.corpus[key]
			if len(bucket) != 0 {
				log.Logf(0, "chooseProgram bucket: %x, len: %v", key, len(bucket))
				break
			}
			keyIdx = r.Intn(len(keys))
		}
		// } else if (r.Intn(P2)%P2 != 0 || len(fuzzer.corpus[0xbeefdead]) == 0) && len(fuzzer.corpus[0xdeadbeef]) != 0 {
	} else if (prob < P1+P2 || len(fuzzer.corpus[0xbeefdead]) == 0) && len(fuzzer.corpus[0xdeadbeef]) != 0 {
		// choose non-sv inputs
		bucket = fuzzer.corpus[0xdeadbeef]
		log.Logf(0, "chooseProgram bucket: 0xdeadbeef, len: %v", len(bucket))
		idx = r.Intn(len(bucket))
		return bucket[idx]

		// controlled buckets
		// if (r.Intn(10)%10 != 0 || len(fuzzer.corpus[0xbeefdead]) == 0) && len(fuzzer.corpus[0xdeadbeef]) != 0 {
		//      // choose non-sv inputs
		//      bucket = fuzzer.corpus[0xdeadbeef]
		//      log.Logf(0, "chooseProgram bucket: 0xdeadbeef, len: %v", len(bucket))
		//      idx = r.Intn(len(bucket))
		//      return bucket[idx]
	} else {
		// extremum choose: 1/2 * 1/5 = 1/10 probability
		bucket = fuzzer.corpus[0xbeefdead]
		log.Logf(0, "chooseProgram bucket: 0xbeefdead, len: %v", len(bucket))
		idx = r.Intn(len(bucket))
		return bucket[idx]
	}

	// bucket may be empty, but it is rare
	idx = r.Intn(len(bucket))
	// randVal := r.Int63n(fuzzer.sumPrios[key] + 1)
	// idx = sort.Search(len(fuzzer.corpusPrios[key]), func(i int) bool {
	//      return fuzzer.corpusPrios[key][i] >= randVal
	// })
	return bucket[idx]
}

func (fuzzer *Fuzzer) addInputToCorpus(p *prog.Prog, sign signal.Signal, svSignal signal.Signal, svCover signal.SvCover, svExtremum signal.SvExtremum, sig hash.Sig) {
	fuzzer.corpusMu.Lock()
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		// hash of path
		pathHash := p.PathHash
		if _, ok := fuzzer.corpus[uint32(pathHash)]; ok {
			fuzzer.corpus[pathHash] = append(fuzzer.corpus[pathHash], p)
		} else {
			// log.Logf(4, "input PathHash hit: %v", pathHash)
			fuzzer.corpus[pathHash] = []*prog.Prog{p}
		}
		fuzzer.corpusHashes[sig] = struct{}{}
		fuzzer.sumPrios[pathHash] += p.SvPrio
		fuzzer.corpusPrios[pathHash] = append(fuzzer.corpusPrios[pathHash], fuzzer.sumPrios[pathHash])
		// we use 0xdeadbeef bucket to preserve all non-sv inputs
		if p.IsNewSvSeed != 2 && p.IsNewSvSeed != 4 && p.PathHash != 0xdeadbeef {
			// controlled buckets
			// if p.IsNewSvSeed != 2 && p.PathHash != 0xdeadbeef {
			fuzzer.corpus[0xdeadbeef] = append(fuzzer.corpus[0xdeadbeef], p)
		}
	}
	fuzzer.corpusMu.Unlock()

	if !sign.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSignal.Merge(sign)
		fuzzer.maxSignal.Merge(sign)
		fuzzer.signalMu.Unlock()
	}
	if !svSignal.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSvSignal.Merge(svSignal)
		fuzzer.maxSvSignal.Merge(svSignal)
		fuzzer.signalMu.Unlock()
	}
	if !svCover.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSvCover.Merge(svCover)
		fuzzer.maxSvCover.Merge(svCover)
		fuzzer.signalMu.Unlock()
	}
	if !svExtremum.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSvExtremum.Merge(svExtremum)
		fuzzer.maxSvExtremum.Merge(svExtremum)
		fuzzer.signalMu.Unlock()
	}
}

// addSvInputToCorpus : add inputs which only trigger sv signal to Corpus
// if pathHash not in corpus, drop it,
// else, add to Corpus[pathHash], update svSignal
func (fuzzer *Fuzzer) addSvInputToCorpus(p *prog.Prog, sign signal.Signal, svSignal signal.Signal, svCover signal.SvCover, svExtremum signal.SvExtremum, sig hash.Sig) {
	fuzzer.corpusMu.Lock()
	added := false
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		pathHash := p.PathHash
		if _, ok := fuzzer.corpus[pathHash]; ok {
			log.Logf(4, "sv input PathHash hit: %v", pathHash)
			// add to Corpus
			fuzzer.corpus[pathHash] = append(fuzzer.corpus[pathHash], p)
			fuzzer.corpusHashes[sig] = struct{}{}
			added = true
		}
	}
	fuzzer.corpusMu.Unlock()

	if added == true {
		if !sign.Empty() {
			fuzzer.signalMu.Lock()
			fuzzer.corpusSignal.Merge(sign)
			fuzzer.maxSignal.Merge(sign)
			fuzzer.signalMu.Unlock()
		}
		if !svSignal.Empty() {
			fuzzer.signalMu.Lock()
			fuzzer.corpusSvSignal.Merge(svSignal)
			fuzzer.maxSvSignal.Merge(svSignal)
			fuzzer.signalMu.Unlock()
		}
		if !svCover.Empty() {
			fuzzer.signalMu.Lock()
			fuzzer.corpusSvCover.Merge(svCover)
			fuzzer.maxSvCover.Merge(svCover)
			fuzzer.signalMu.Unlock()
		}
		if !svExtremum.Empty() {
			fuzzer.signalMu.Lock()
			fuzzer.corpusSvExtremum.Merge(svExtremum)
			fuzzer.maxSvExtremum.Merge(svExtremum)
			fuzzer.signalMu.Unlock()
		}
	}
}

// addSvExtremumInputToCorpus: add svExtremumInput to corpus, and update svExtremum values in procs
func (fuzzer *Fuzzer) addSvExtremumInputToCorpus(p *prog.Prog, svExtremum signal.SvExtremum, sig hash.Sig) {
	fuzzer.corpusMu.Lock()
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		pathHash := uint32(0xbeefdead)
		if _, ok := fuzzer.corpus[uint32(pathHash)]; ok {
			fuzzer.corpus[pathHash] = append(fuzzer.corpus[pathHash], p)
		} else {
			// log.Logf(4, "input PathHash hit: %v", pathHash)
			fuzzer.corpus[pathHash] = []*prog.Prog{p}
		}
		fuzzer.corpusHashes[sig] = struct{}{}
	}
	fuzzer.corpusMu.Unlock()

	if !svExtremum.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSvExtremum.Merge(svExtremum)
		fuzzer.maxSvExtremum.Merge(svExtremum)
		fuzzer.signalMu.Unlock()
	}
}

func (fuzzer *Fuzzer) snapshot() FuzzerSnapshot {
	fuzzer.corpusMu.RLock()
	defer fuzzer.corpusMu.RUnlock()
	corpusCopy := make(map[uint32][]*prog.Prog)
	for k, m := range fuzzer.corpus {
		corpusCopy[k] = m
	}
	return FuzzerSnapshot{corpusCopy, fuzzer.corpusPrios, fuzzer.sumPrios}
}

func (fuzzer *Fuzzer) addMaxSignal(sign signal.Signal) {
	if sign.Len() == 0 {
		return
	}
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSignal.Merge(sign)
}

func (fuzzer *Fuzzer) addMaxSvSignal(svSignal signal.Signal) {
	if svSignal.Len() == 0 {
		return
	}
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSvSignal.Merge(svSignal)
}

func (fuzzer *Fuzzer) addMaxSvCover(svCover signal.SvCover) {
	if svCover.Len() == 0 {
		return
	}
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSvCover.Merge(svCover)
}

func (fuzzer *Fuzzer) addMaxSvExtremum(svExtremum signal.SvExtremum) {
	if len(svExtremum) == 0 {
		return
	}
	// sync Extremum values from manager
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSvExtremum.Merge(svExtremum)
}

func (fuzzer *Fuzzer) grabNewSignal() signal.Signal {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	sign := fuzzer.newSignal
	if sign.Empty() {
		return nil
	}
	fuzzer.newSignal = nil
	return sign
}

func (fuzzer *Fuzzer) grabNewSvSignal() signal.Signal {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	svSignal := fuzzer.newSvSignal
	if svSignal.Empty() {
		return nil
	}
	fuzzer.newSvSignal = nil
	return svSignal
}

func (fuzzer *Fuzzer) grabNewSvCover() signal.SvCover {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	svCover := fuzzer.newSvCover
	if svCover.Empty() {
		return nil
	}
	fuzzer.newSvCover = nil
	return svCover
}

func (fuzzer *Fuzzer) grabNewSvExtremum() signal.SvExtremum {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	svExtremum := fuzzer.newSvExtremum
	if len(svExtremum) == 0 {
		return nil
	}
	fuzzer.newSvExtremum = nil
	return svExtremum
}

func (fuzzer *Fuzzer) corpusSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSignal.Diff(sign)
}

func (fuzzer *Fuzzer) corpusSvSignalDiff(svSignal signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSvSignal.Diff(svSignal)
}

func (fuzzer *Fuzzer) corpusSvCoverDiff(svCover signal.SvCover) signal.SvCover {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSvCover.Diff(svCover)
}

func (fuzzer *Fuzzer) corpusSvExtremumDiff(svExtremum signal.SvExtremum) signal.SvExtremum {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSvExtremum.Diff(svExtremum)
}

func (fuzzer *Fuzzer) checkNewSignal(p *prog.Prog, info *ipc.ProgInfo) (calls []int, extra bool) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	// var appended bool
	for i, inf := range info.Calls {
		// appended = false
		if fuzzer.checkNewCallSignal(p, &inf, i) {
			calls = append(calls, i)
			// appended = true
		}
		// if fuzzer.checkNewCallSvSignal(p, &inf, i) {
		// 	if appended == false {
		// 		calls = append(calls, i)
		// 	}
		// }
	}
	// extra = (fuzzer.checkNewCallSignal(p, &info.Extra, -1) || fuzzer.checkNewCallSvSignal(p, &info.Extra, -1))
	extra = fuzzer.checkNewCallSignal(p, &info.Extra, -1)
	return
}

func (fuzzer *Fuzzer) checkNewCallSignal(p *prog.Prog, info *ipc.CallInfo, call int) bool {
	diff := fuzzer.maxSignal.DiffRaw(info.Signal, signalPrio(p, info, call))
	svDiff := fuzzer.maxSvSignal.DiffRaw(info.SvSignal, signalPrio(p, info, call))
	svCovDiff := fuzzer.maxSvCover.DiffRaw(info.SvCover, signalPrio(p, info, call))
	svExtremumDiff := fuzzer.maxSvExtremum.DiffRaw(info.SvExtremum, signalPrio(p, info, call))

	if diff.Empty() && svDiff.Empty() && svCovDiff.Empty() && svExtremumDiff.Empty() {
		return false
	}
	fuzzer.signalMu.RUnlock()
	fuzzer.signalMu.Lock()
	if !(diff.Empty()) {
		fuzzer.maxSignal.Merge(diff)
		fuzzer.newSignal.Merge(diff)
	}
	if !(svDiff.Empty()) {
		fuzzer.maxSvSignal.Merge(svDiff)
		fuzzer.newSvSignal.Merge(svDiff)
	}
	if !(svCovDiff.Empty()) {
		// do not merge: extremum, svCover = 0xffff:rw_type:svNo:svValue = 16:1:15:32
		fuzzer.maxSvCover.Merge(svCovDiff)
		fuzzer.newSvCover.Merge(svCovDiff)
	}
	if len(svExtremumDiff) != 0 {
		fuzzer.maxSvExtremum.Merge(svExtremumDiff)
		fuzzer.newSvExtremum.Merge(svExtremumDiff)
	}
	fuzzer.signalMu.Unlock()
	fuzzer.signalMu.RLock()

	return true
}

// func (fuzzer *Fuzzer) checkNewCallSvSignal(p *prog.Prog, info *ipc.CallInfo, call int) bool {
// 	diff := fuzzer.maxSvSignal.DiffRaw(info.SvSignal, signalPrio(p, info, call))
// 	if diff.Empty() {
// 		return false
// 	}
// 	fuzzer.SvSignalMu.RUnlock()
// 	fuzzer.SvSignalMu.Lock()
// 	fuzzer.maxSvSignal.Merge(diff)
// 	fuzzer.newSvSignal.Merge(diff)
// 	fuzzer.SvSignalMu.Unlock()
// 	fuzzer.SvSignalMu.RLock()
// 	return true
// }

func signalPrio(p *prog.Prog, info *ipc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Errno == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func parseOutputType(str string) OutputType {
	switch str {
	case "none":
		return OutputNone
	case "stdout":
		return OutputStdout
	case "dmesg":
		return OutputDmesg
	case "file":
		return OutputFile
	default:
		log.Fatalf("-output flag must be one of none/stdout/dmesg/file")
		return OutputNone
	}
}
