// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/gce"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
	flagDebug  = flag.Bool("debug", false, "dump all VM output to console")
	flagBench  = flag.String("bench", "", "write execution statistics into this file periodically")
)

type Manager struct {
	cfg            *mgrconfig.Config
	vmPool         *vm.Pool
	target         *prog.Target
	sysTarget      *targets.Target
	reporter       report.Reporter
	crashdir       string
	port           int
	corpusDB       *db.DB
	startTime      time.Time
	firstConnect   time.Time
	fuzzingTime    time.Duration
	stats          *Stats
	crashTypes     map[string]bool
	vmStop         chan bool
	checkResult    *rpctype.CheckArgs
	fresh          bool
	numFuzzing     uint32
	numReproducing uint32

	dash *dashapi.Dashboard

	mu              sync.Mutex
	phase           int
	enabledSyscalls []int

	candidates       []rpctype.RPCCandidate // untriaged inputs from corpus and hub
	disabledHashes   map[string]struct{}
	corpus           map[string]rpctype.RPCInput
	totalSvCover     map[uint64]uint64
	totalSvSignal    map[uint32]uint64
	buckets          map[uint32]map[string]bool
	newRepros        [][]byte
	lastMinCorpus    int
	memoryLeakFrames map[string]bool
	dataRaceFrames   map[string]bool
	saturatedCalls   map[string]bool

	needMoreRepros chan chan bool
	hubReproQueue  chan *Crash
	reproRequest   chan chan map[string]bool

	// For checking that files that we are using are not changing under us.
	// Maps file name to modification time.
	usedFiles map[string]time.Time

	isSvCoverInit bool
	// svRangeCover[sv_no][sv_range_value][svInstPc] = uint32
	svRangeCover           map[uint32]map[int32]map[uint32]uint64
	svRangeCorpusCover     map[uint32]map[int32]map[uint32]uint64
	svName                 map[uint32]string
	svFieldName            map[uint32]string
	svRanges               map[uint32]map[uint32]int32
	corpusSvExtremum       map[uint32]map[string]int32
	corpusSvExtremumHashes map[uint32]map[string]string
}

const (
	// Just started, nothing done yet.
	phaseInit = iota
	// Corpus is loaded and machine is checked.
	phaseLoadedCorpus
	// Triaged all inputs from corpus.
	// This is when we start querying hub and minimizing persistent corpus.
	phaseTriagedCorpus
	// Done the first request to hub.
	phaseQueriedHub
	// Triaged all new inputs from hub.
	// This is when we start reproducing crashes.
	phaseTriagedHub
)

const currentDBVersion = 4

type Crash struct {
	vmIndex int
	hub     bool // this crash was created based on a repro from hub
	*report.Report
}

func main() {
	// if prog.GitRevision == "" {
	// 	log.Fatalf("Bad syz-manager build. Build with make, run bin/syz-manager.")
	// }
	flag.Parse()
	log.EnableLogCaching(1000, 1<<20)
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}
	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		log.Fatalf("%v", err)
	}
	sysTarget := targets.Get(cfg.TargetOS, cfg.TargetArch)
	if sysTarget == nil {
		log.Fatalf("unsupported OS/arch: %v/%v", cfg.TargetOS, cfg.TargetArch)
	}
	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls)
	if err != nil {
		log.Fatalf("%v", err)
	}
	RunManager(cfg, target, sysTarget, syscalls)
}

func RunManager(cfg *mgrconfig.Config, target *prog.Target, sysTarget *targets.Target, syscalls []int) {
	var vmPool *vm.Pool
	// Type "none" is a special case for debugging/development when manager
	// does not start any VMs, but instead you start them manually
	// and start syz-fuzzer there.
	if cfg.Type != "none" {
		var err error
		vmPool, err = vm.Create(cfg, *flagDebug)
		if err != nil {
			log.Fatalf("%v", err)
		}
	}

	crashdir := filepath.Join(cfg.Workdir, "crashes")
	osutil.MkdirAll(crashdir)

	reporter, err := report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	mgr := &Manager{
		cfg:                    cfg,
		vmPool:                 vmPool,
		target:                 target,
		sysTarget:              sysTarget,
		reporter:               reporter,
		crashdir:               crashdir,
		startTime:              time.Now(),
		stats:                  &Stats{haveHub: cfg.HubClient != ""},
		crashTypes:             make(map[string]bool),
		enabledSyscalls:        syscalls,
		corpus:                 make(map[string]rpctype.RPCInput),
		totalSvCover:           make(map[uint64]uint64),
		totalSvSignal:          make(map[uint32]uint64),
		buckets:                make(map[uint32]map[string]bool),
		disabledHashes:         make(map[string]struct{}),
		memoryLeakFrames:       make(map[string]bool),
		dataRaceFrames:         make(map[string]bool),
		fresh:                  true,
		vmStop:                 make(chan bool),
		hubReproQueue:          make(chan *Crash, 10),
		needMoreRepros:         make(chan chan bool),
		reproRequest:           make(chan chan map[string]bool),
		usedFiles:              make(map[string]time.Time),
		saturatedCalls:         make(map[string]bool),
		isSvCoverInit:          false,
		corpusSvExtremum:       make(map[uint32]map[string]int32),
		corpusSvExtremumHashes: make(map[uint32]map[string]string),
	}

	log.Logf(0, "loading corpus...")
	log.Logf(0, "Workdir: %v", cfg.Workdir)
	mgr.corpusDB, err = db.Open(filepath.Join(cfg.Workdir, "corpus.db"))
	if err != nil {
		log.Fatalf("failed to open corpus database: %v", err)
	}

	// Create HTTP server.
	mgr.initHTTP()
	mgr.collectUsedFiles()

	mgr.target.Static = mgr.target.CalcStaticPriorities()
	log.Logf(0, "initSvCover...")
	mgr.initSvCover()

	// Create RPC server for fuzzers.
	mgr.port, err = startRPCServer(mgr)
	if err != nil {
		log.Fatalf("failed to create rpc server: %v", err)
	}

	if cfg.DashboardAddr != "" {
		mgr.dash = dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey)
	}

	go func() {
		for lastTime := time.Now(); ; {
			time.Sleep(10 * time.Second)
			now := time.Now()
			diff := now.Sub(lastTime)
			lastTime = now
			mgr.mu.Lock()
			if mgr.firstConnect.IsZero() {
				mgr.mu.Unlock()
				continue
			}
			mgr.fuzzingTime += diff * time.Duration(atomic.LoadUint32(&mgr.numFuzzing))
			executed := mgr.stats.execTotal.get()
			crashes := mgr.stats.crashes.get()
			signal := mgr.stats.corpusSignal.get()
			svSignal := mgr.stats.corpusSvSignal.get()
			svCover := mgr.stats.corpusSvCover.get()
			svCorpus := mgr.stats.svCorpus.get()
			mgr.mu.Unlock()
			numReproducing := atomic.LoadUint32(&mgr.numReproducing)
			numFuzzing := atomic.LoadUint32(&mgr.numFuzzing)

			// pc corpus may be large, cuz one input may set several paths
			log.Logf(0, "syzkaller-VMs %v, executed %v, bb %v, edge %v, crashes %v, crashTypes %v, buckets %v, sv corpus %v, reproducing %v, svCoverage %v, svEdge %v",
				numFuzzing, executed, mgr.stats.corpusPcCover.get(), signal, crashes, mgr.stats.crashTypes.get(), len(mgr.buckets), svCorpus, numReproducing, svCover, svSignal)
		}
	}()

	if *flagBench != "" {
		f, err := os.OpenFile(*flagBench, os.O_WRONLY|os.O_CREATE|os.O_EXCL, osutil.DefaultFilePerm)
		if err != nil {
			log.Fatalf("failed to open bench file: %v", err)
		}
		go func() {
			for {
				time.Sleep(time.Minute)
				vals := mgr.stats.all()
				mgr.mu.Lock()
				if mgr.firstConnect.IsZero() {
					mgr.mu.Unlock()
					continue
				}
				mgr.minimizeCorpus()
				vals["corpus"] = uint64(len(mgr.corpus))
				vals["uptime"] = uint64(time.Since(mgr.firstConnect)) / 1e9
				vals["fuzzing"] = uint64(mgr.fuzzingTime) / 1e9
				mgr.mu.Unlock()

				data, err := json.MarshalIndent(vals, "", "  ")
				if err != nil {
					log.Fatalf("failed to serialize bench data")
				}
				if _, err := f.Write(append(data, '\n')); err != nil {
					log.Fatalf("failed to write bench data")
				}
			}
		}()
	}

	if mgr.dash != nil {
		go mgr.dashboardReporter()
	}

	osutil.HandleInterrupts(vm.Shutdown)
	if mgr.vmPool == nil {
		log.Logf(0, "no VMs started (type=none)")
		log.Logf(0, "you are supposed to start syz-fuzzer manually as:")
		log.Logf(0, "syz-fuzzer -manager=manager.ip:%v [other flags as necessary]", mgr.port)
		<-vm.Shutdown
		return
	}
	mgr.vmLoop()
}

type RunResult struct {
	idx   int
	crash *Crash
	err   error
}

type ReproResult struct {
	instances []int
	report0   *report.Report // the original report we started reproducing
	res       *repro.Result
	stats     *repro.Stats
	err       error
	hub       bool // repro came from hub
}

// Manager needs to be refactored (#605).
// nolint: gocyclo
func (mgr *Manager) vmLoop() {
	log.Logf(0, "booting test machines...")
	log.Logf(0, "wait for the connection from test machine...")
	instancesPerRepro := 4
	vmCount := mgr.vmPool.Count()
	if instancesPerRepro > vmCount {
		instancesPerRepro = vmCount
	}
	bootInstance := make(chan int)
	go func() {
		for i := 0; i < vmCount; i++ {
			bootInstance <- i
			time.Sleep(10 * time.Second)
		}
	}()
	var instances []int
	runDone := make(chan *RunResult, 1)
	pendingRepro := make(map[*Crash]bool)
	reproducing := make(map[string]bool)
	reproInstances := 0
	var reproQueue []*Crash
	reproDone := make(chan *ReproResult, 1)
	stopPending := false
	shutdown := vm.Shutdown
	for shutdown != nil || len(instances) != vmCount {
		mgr.mu.Lock()
		phase := mgr.phase
		mgr.mu.Unlock()

		for crash := range pendingRepro {
			if reproducing[crash.Title] {
				continue
			}
			delete(pendingRepro, crash)
			if !mgr.needRepro(crash) {
				continue
			}
			log.Logf(1, "loop: add to repro queue '%v'", crash.Title)
			reproducing[crash.Title] = true
			reproQueue = append(reproQueue, crash)
		}

		log.Logf(1, "loop: phase=%v shutdown=%v instances=%v/%v %+v repro: pending=%v reproducing=%v queued=%v",
			phase, shutdown == nil, len(instances), vmCount, instances,
			len(pendingRepro), len(reproducing), len(reproQueue))

		canRepro := func() bool {
			return phase >= phaseTriagedHub &&
				len(reproQueue) != 0 && reproInstances+instancesPerRepro <= vmCount
		}

		if shutdown != nil {
			for canRepro() && len(instances) >= instancesPerRepro {
				last := len(reproQueue) - 1
				crash := reproQueue[last]
				reproQueue[last] = nil
				reproQueue = reproQueue[:last]
				vmIndexes := append([]int{}, instances[len(instances)-instancesPerRepro:]...)
				instances = instances[:len(instances)-instancesPerRepro]
				reproInstances += instancesPerRepro
				atomic.AddUint32(&mgr.numReproducing, 1)
				log.Logf(1, "loop: starting repro of '%v' on instances %+v", crash.Title, vmIndexes)
				go func() {
					res, stats, err := repro.Run(crash.Output, mgr.cfg, mgr.reporter, mgr.vmPool, vmIndexes)
					reproDone <- &ReproResult{
						instances: vmIndexes,
						report0:   crash.Report,
						res:       res,
						stats:     stats,
						err:       err,
						hub:       crash.hub,
					}
				}()
			}
			for !canRepro() && len(instances) != 0 {
				last := len(instances) - 1
				idx := instances[last]
				instances = instances[:last]
				log.Logf(1, "loop: starting instance %v", idx)
				go func() {
					crash, err := mgr.runInstance(idx)
					runDone <- &RunResult{idx, crash, err}
				}()
			}
		}

		var stopRequest chan bool
		if !stopPending && canRepro() {
			stopRequest = mgr.vmStop
		}

	wait:
		select {
		case idx := <-bootInstance:
			instances = append(instances, idx)
		case stopRequest <- true:
			log.Logf(1, "loop: issued stop request")
			stopPending = true
		case res := <-runDone:
			log.Logf(1, "loop: instance %v finished, crash=%v", res.idx, res.crash != nil)
			if res.err != nil && shutdown != nil {
				log.Logf(0, "%v", res.err)
			}
			stopPending = false
			instances = append(instances, res.idx)
			// On shutdown qemu crashes with "qemu: terminating on signal 2",
			// which we detect as "lost connection". Don't save that as crash.
			if shutdown != nil && res.crash != nil {
				needRepro := mgr.saveCrash(res.crash)
				if needRepro {
					log.Logf(1, "loop: add pending repro for '%v'", res.crash.Title)
					pendingRepro[res.crash] = true
				}
			}
		case res := <-reproDone:
			atomic.AddUint32(&mgr.numReproducing, ^uint32(0))
			crepro := false
			title := ""
			if res.res != nil {
				crepro = res.res.CRepro
				title = res.res.Report.Title
			}
			log.Logf(1, "loop: repro on %+v finished '%v', repro=%v crepro=%v desc='%v'",
				res.instances, res.report0.Title, res.res != nil, crepro, title)
			if res.err != nil {
				log.Logf(0, "repro failed: %v", res.err)
			}
			delete(reproducing, res.report0.Title)
			instances = append(instances, res.instances...)
			reproInstances -= instancesPerRepro
			if res.res == nil {
				if !res.hub {
					mgr.saveFailedRepro(res.report0, res.stats)
				}
			} else {
				mgr.saveRepro(res.res, res.stats, res.hub)
			}
		case <-shutdown:
			log.Logf(1, "loop: shutting down...")
			shutdown = nil
		case crash := <-mgr.hubReproQueue:
			log.Logf(1, "loop: get repro from hub")
			pendingRepro[crash] = true
		case reply := <-mgr.needMoreRepros:
			reply <- phase >= phaseTriagedHub &&
				len(reproQueue)+len(pendingRepro)+len(reproducing) == 0
			goto wait
		case reply := <-mgr.reproRequest:
			repros := make(map[string]bool)
			for title := range reproducing {
				repros[title] = true
			}
			reply <- repros
			goto wait
		}
	}
}

func (mgr *Manager) loadCorpus() {
	// By default we don't re-minimize/re-smash programs from corpus,
	// it takes lots of time on start and is unnecessary.
	// However, on version bumps we can selectively re-minimize/re-smash.
	minimized, smashed := true, true
	switch mgr.corpusDB.Version {
	case 0:
		// Version 0 had broken minimization, so we need to re-minimize.
		minimized = false
		fallthrough
	case 1:
		// Version 1->2: memory is preallocated so lots of mmaps become unnecessary.
		minimized = false
		fallthrough
	case 2:
		// Version 2->3: big-endian hints.
		smashed = false
		fallthrough
	case 3:
		// Version 3->4: to shake things up.
		minimized = false
		fallthrough
	case currentDBVersion:
	}
	syscalls := make(map[int]bool)
	for _, id := range mgr.checkResult.EnabledCalls[mgr.cfg.Sandbox] {
		syscalls[id] = true
	}
	broken, tooLong := 0, 0
	for key, rec := range mgr.corpusDB.Records {
		p, err := mgr.target.Deserialize(rec.Val, prog.NonStrict)
		if err != nil {
			mgr.corpusDB.Delete(key)
			broken++
			continue
		}
		if len(p.Calls) > prog.MaxCalls {
			mgr.corpusDB.Delete(key)
			tooLong++
			continue
		}

		disabled := false
		for _, c := range p.Calls {
			if !syscalls[c.Meta.ID] {
				disabled = true
				break
			}
		}
		if disabled {
			// This program contains a disabled syscall.
			// We won't execute it, but remember its hash so
			// it is not deleted during minimization.
			mgr.disabledHashes[hash.String(rec.Val)] = struct{}{}
			continue
		}
		mgr.candidates = append(mgr.candidates, rpctype.RPCCandidate{
			Prog:      rec.Val,
			Minimized: minimized,
			Smashed:   smashed,
		})
	}
	mgr.fresh = len(mgr.corpusDB.Records) == 0
	log.Logf(0, "%-24v: %v (deleted %v broken, %v too long)",
		"corpus", len(mgr.candidates), broken, tooLong)

	// Now this is ugly.
	// We duplicate all inputs in the corpus and shuffle the second part.
	// This solves the following problem. A fuzzer can crash while triaging candidates,
	// in such case it will also lost all cached candidates. Or, the input can be somewhat flaky
	// and doesn't give the coverage on first try. So we give each input the second chance.
	// Shuffling should alleviate deterministically losing the same inputs on fuzzer crashing.
	mgr.candidates = append(mgr.candidates, mgr.candidates...)
	shuffle := mgr.candidates[len(mgr.candidates)/2:]
	rand.Shuffle(len(shuffle), func(i, j int) {
		shuffle[i], shuffle[j] = shuffle[j], shuffle[i]
	})
	if mgr.phase != phaseInit {
		panic(fmt.Sprintf("loadCorpus: bad phase %v", mgr.phase))
	}
	mgr.phase = phaseLoadedCorpus
}

func (mgr *Manager) runInstance(index int) (*Crash, error) {
	mgr.checkUsedFiles()
	inst, err := mgr.vmPool.Create(index)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance: %v", err)
	}
	defer inst.Close()

	fwdAddr, err := inst.Forward(mgr.port)
	if err != nil {
		return nil, fmt.Errorf("failed to setup port forwarding: %v", err)
	}

	fuzzerBin, err := inst.Copy(mgr.cfg.SyzFuzzerBin)
	if err != nil {
		return nil, fmt.Errorf("failed to copy binary: %v", err)
	}

	// If SyzExecutorCmd is provided, it means that syz-executor is already in
	// the image, so no need to copy it.
	executorCmd := targets.Get(mgr.cfg.TargetOS, mgr.cfg.TargetArch).SyzExecutorCmd
	if executorCmd == "" {
		executorCmd, err = inst.Copy(mgr.cfg.SyzExecutorBin)
		if err != nil {
			return nil, fmt.Errorf("failed to copy binary: %v", err)
		}
	}

	var err0 error
	var svrangefile string
	var svpairsfile string

	svrangefile, err0 = inst.Copy(mgr.cfg.SvRangeJSONFile)
	if err0 != nil {
		return nil, fmt.Errorf("failed to copy SvRangeJSONFile: %v", err0)
	}
	log.Logf(0, "svrangefile %v", svrangefile)

	svpairsfile, err0 = inst.Copy(mgr.cfg.SvPairsJSONFile)
	if err0 != nil {
		return nil, fmt.Errorf("failed to copy SvPairsJSONFile: %v", err0)
	}
	log.Logf(0, "svpairsfile %v", svpairsfile)

	fuzzerV := 0
	procs := mgr.cfg.Procs
	if *flagDebug {
		fuzzerV = 100
		// zbd debug
		procs = 1
	}

	// Run the fuzzer binary.
	start := time.Now()
	atomic.AddUint32(&mgr.numFuzzing, 1)
	defer atomic.AddUint32(&mgr.numFuzzing, ^uint32(0))
	cmd := instance.FuzzerCmd(fuzzerBin, executorCmd, fmt.Sprintf("vm-%v", index),
		mgr.cfg.TargetOS, mgr.cfg.TargetArch, fwdAddr, mgr.cfg.Sandbox, procs, fuzzerV,
		mgr.cfg.Cover, *flagDebug, false, false)
	outc, errc, err := inst.Run(time.Hour, mgr.vmStop, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run fuzzer: %v", err)
	}

	rep := inst.MonitorExecution(outc, errc, mgr.reporter, vm.ExitTimeout)
	if rep == nil {
		// This is the only "OK" outcome.
		log.Logf(0, "vm-%v: running for %v, restarting", index, time.Since(start))
		return nil, nil
	}
	crash := &Crash{
		vmIndex: index,
		hub:     false,
		Report:  rep,
	}
	return crash, nil
}

func (mgr *Manager) emailCrash(crash *Crash) {
	if len(mgr.cfg.EmailAddrs) == 0 {
		return
	}
	args := []string{"-s", "syzkaller: " + crash.Title}
	args = append(args, mgr.cfg.EmailAddrs...)
	log.Logf(0, "sending email to %v", mgr.cfg.EmailAddrs)

	cmd := exec.Command("mailx", args...)
	cmd.Stdin = bytes.NewReader(crash.Report.Report)
	if _, err := osutil.Run(10*time.Minute, cmd); err != nil {
		log.Logf(0, "failed to send email: %v", err)
	}
}

func (mgr *Manager) saveCrash(crash *Crash) bool {
	if crash.Type == report.MemoryLeak {
		mgr.mu.Lock()
		mgr.memoryLeakFrames[crash.Frame] = true
		mgr.mu.Unlock()
	}
	if crash.Type == report.DataRace {
		mgr.mu.Lock()
		mgr.dataRaceFrames[crash.Frame] = true
		mgr.mu.Unlock()
	}
	if crash.Suppressed {
		log.Logf(0, "vm-%v: suppressed crash %v", crash.vmIndex, crash.Title)
		mgr.stats.crashSuppressed.inc()
		return false
	}
	corrupted := ""
	if crash.Corrupted {
		corrupted = " [corrupted]"
	}
	log.Logf(0, "vm-%v: crash: %v%v", crash.vmIndex, crash.Title, corrupted)
	if err := mgr.reporter.Symbolize(crash.Report); err != nil {
		log.Logf(0, "failed to symbolize report: %v", err)
	}

	mgr.stats.crashes.inc()
	mgr.mu.Lock()
	if !mgr.crashTypes[crash.Title] {
		mgr.crashTypes[crash.Title] = true
		mgr.stats.crashTypes.inc()
	}
	mgr.mu.Unlock()

	if mgr.dash != nil {
		if crash.Type == report.MemoryLeak {
			return true
		}
		dc := &dashapi.Crash{
			BuildID:     mgr.cfg.Tag,
			Title:       crash.Title,
			Corrupted:   crash.Corrupted,
			Maintainers: crash.Maintainers,
			Log:         crash.Output,
			Report:      crash.Report.Report,
		}
		resp, err := mgr.dash.ReportCrash(dc)
		if err != nil {
			log.Logf(0, "failed to report crash to dashboard: %v", err)
		} else {
			// Don't store the crash locally, if we've successfully
			// uploaded it to the dashboard. These will just eat disk space.
			return resp.NeedRepro
		}
	}

	sig := hash.Hash([]byte(crash.Title))
	id := sig.String()
	dir := filepath.Join(mgr.crashdir, id)
	osutil.MkdirAll(dir)
	if err := osutil.WriteFile(filepath.Join(dir, "description"), []byte(crash.Title+"\n")); err != nil {
		log.Logf(0, "failed to write crash: %v", err)
	}
	// Save up to 100 reports. If we already have 100, overwrite the oldest one.
	// Newer reports are generally more useful. Overwriting is also needed
	// to be able to understand if a particular bug still happens or already fixed.
	oldestI := 0
	var oldestTime time.Time
	for i := 0; i < 100; i++ {
		info, err := os.Stat(filepath.Join(dir, fmt.Sprintf("log%v", i)))
		if err != nil {
			oldestI = i
			if i == 0 {
				go mgr.emailCrash(crash)
			}
			break
		}
		if oldestTime.IsZero() || info.ModTime().Before(oldestTime) {
			oldestI = i
			oldestTime = info.ModTime()
		}
	}
	osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("log%v", oldestI)), crash.Output)
	if len(mgr.cfg.Tag) > 0 {
		osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("tag%v", oldestI)), []byte(mgr.cfg.Tag))
	}
	if len(crash.Report.Report) > 0 {
		osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("report%v", oldestI)), crash.Report.Report)
	}

	return mgr.needLocalRepro(crash)
}

const maxReproAttempts = 3

func (mgr *Manager) needLocalRepro(crash *Crash) bool {
	if !mgr.cfg.Reproduce || crash.Corrupted {
		return false
	}
	if mgr.checkResult == nil || (mgr.checkResult.Features[host.FeatureLeak].Enabled &&
		crash.Type != report.MemoryLeak) {
		// Leak checking is very slow, don't bother reproducing other crashes.
		return false
	}
	sig := hash.Hash([]byte(crash.Title))
	dir := filepath.Join(mgr.crashdir, sig.String())
	if osutil.IsExist(filepath.Join(dir, "repro.prog")) {
		return false
	}
	for i := 0; i < maxReproAttempts; i++ {
		if !osutil.IsExist(filepath.Join(dir, fmt.Sprintf("repro%v", i))) {
			return true
		}
	}
	return false
}

func (mgr *Manager) needRepro(crash *Crash) bool {
	if crash.hub {
		return true
	}
	if mgr.dash == nil {
		return mgr.needLocalRepro(crash)
	}
	if crash.Type == report.MemoryLeak {
		return true
	}
	cid := &dashapi.CrashID{
		BuildID:   mgr.cfg.Tag,
		Title:     crash.Title,
		Corrupted: crash.Corrupted,
	}
	needRepro, err := mgr.dash.NeedRepro(cid)
	if err != nil {
		log.Logf(0, "dashboard.NeedRepro failed: %v", err)
	}
	return needRepro
}

func (mgr *Manager) saveFailedRepro(rep *report.Report, stats *repro.Stats) {
	if rep.Type == report.MemoryLeak {
		// Don't send failed leak repro attempts to dashboard
		// as we did not send the crash itself.
		return
	}
	if mgr.dash != nil {
		cid := &dashapi.CrashID{
			BuildID: mgr.cfg.Tag,
			Title:   rep.Title,
		}
		if err := mgr.dash.ReportFailedRepro(cid); err != nil {
			log.Logf(0, "failed to report failed repro to dashboard: %v", err)
		} else {
			return
		}
	}
	dir := filepath.Join(mgr.crashdir, hash.String([]byte(rep.Title)))
	osutil.MkdirAll(dir)
	for i := 0; i < maxReproAttempts; i++ {
		name := filepath.Join(dir, fmt.Sprintf("repro%v", i))
		if !osutil.IsExist(name) {
			saveReproStats(name, stats)
			break
		}
	}
}

func (mgr *Manager) saveRepro(res *repro.Result, stats *repro.Stats, hub bool) {
	rep := res.Report
	if err := mgr.reporter.Symbolize(rep); err != nil {
		log.Logf(0, "failed to symbolize repro: %v", err)
	}
	opts := fmt.Sprintf("# %+v\n", res.Opts)
	prog := res.Prog.Serialize()

	// Append this repro to repro list to send to hub if it didn't come from hub originally.
	if !hub {
		progForHub := []byte(fmt.Sprintf("# %+v\n# %v\n# %v\n%s",
			res.Opts, res.Report.Title, mgr.cfg.Tag, prog))
		mgr.mu.Lock()
		mgr.newRepros = append(mgr.newRepros, progForHub)
		mgr.mu.Unlock()
	}

	var cprogText []byte
	if res.CRepro {
		cprog, err := csource.Write(res.Prog, res.Opts)
		if err == nil {
			formatted, err := csource.Format(cprog)
			if err == nil {
				cprog = formatted
			}
			cprogText = cprog
		} else {
			log.Logf(0, "failed to write C source: %v", err)
		}
	}

	if mgr.dash != nil {
		// Note: we intentionally don't set Corrupted for reproducers:
		// 1. This is reproducible so can be debugged even with corrupted report.
		// 2. Repro re-tried 3 times and still got corrupted report at the end,
		//    so maybe corrupted report detection is broken.
		// 3. Reproduction is expensive so it's good to persist the result.
		dc := &dashapi.Crash{
			BuildID:     mgr.cfg.Tag,
			Title:       res.Report.Title,
			Maintainers: res.Report.Maintainers,
			Log:         res.Report.Output,
			Report:      res.Report.Report,
			ReproOpts:   res.Opts.Serialize(),
			ReproSyz:    res.Prog.Serialize(),
			ReproC:      cprogText,
		}
		if _, err := mgr.dash.ReportCrash(dc); err != nil {
			log.Logf(0, "failed to report repro to dashboard: %v", err)
		} else {
			// Don't store the crash locally, if we've successfully
			// uploaded it to the dashboard. These will just eat disk space.
			return
		}
	}

	dir := filepath.Join(mgr.crashdir, hash.String([]byte(rep.Title)))
	osutil.MkdirAll(dir)

	if err := osutil.WriteFile(filepath.Join(dir, "description"), []byte(rep.Title+"\n")); err != nil {
		log.Logf(0, "failed to write crash: %v", err)
	}
	osutil.WriteFile(filepath.Join(dir, "repro.prog"), append([]byte(opts), prog...))
	if len(mgr.cfg.Tag) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.tag"), []byte(mgr.cfg.Tag))
	}
	if len(rep.Output) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.log"), rep.Output)
	}
	if len(rep.Report) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.report"), rep.Report)
	}
	if len(cprogText) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.cprog"), cprogText)
	}
	saveReproStats(filepath.Join(dir, "repro.stats"), stats)
}

func saveReproStats(filename string, stats *repro.Stats) {
	text := ""
	if stats != nil {
		text = fmt.Sprintf("Extracting prog: %v\nMinimizing prog: %v\n"+
			"Simplifying prog options: %v\nExtracting C: %v\nSimplifying C: %v\n\n\n%s",
			stats.ExtractProgTime, stats.MinimizeProgTime,
			stats.SimplifyProgTime, stats.ExtractCTime, stats.SimplifyCTime, stats.Log)
	}
	osutil.WriteFile(filename, []byte(text))
}

func (mgr *Manager) getMinimizedCorpus() (corpus, repros [][]byte) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.minimizeCorpus()
	corpus = make([][]byte, 0, len(mgr.corpus))
	for _, inp := range mgr.corpus {
		corpus = append(corpus, inp.Prog)
	}
	repros = mgr.newRepros
	mgr.newRepros = nil
	return
}

func (mgr *Manager) addNewCandidates(progs [][]byte) {
	candidates := make([]rpctype.RPCCandidate, len(progs))
	for i, inp := range progs {
		candidates[i] = rpctype.RPCCandidate{
			Prog:      inp,
			Minimized: false, // don't trust programs from hub
			Smashed:   false,
		}
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.candidates = append(mgr.candidates, candidates...)
	if mgr.phase == phaseTriagedCorpus {
		mgr.phase = phaseQueriedHub
	}
}

func (mgr *Manager) minimizeCorpus() {
	if mgr.phase < phaseLoadedCorpus || len(mgr.corpus) <= mgr.lastMinCorpus*103/100 {
		return
	}
	inputs := make([]signal.Context, 0, len(mgr.corpus))
	for sig, inp := range mgr.corpus {
		if strings.Contains(sig, "_dup") {
			continue
		}
		if strings.Contains(sig, "_extremum") {
			continue
		}
		inputs = append(inputs, signal.Context{
			Signal:   inp.Signal.Deserialize(),
			SvSignal: inp.SvSignal.Deserialize(),
			SvCover:  inp.SvCover.Deserialize(),
			Context:  inp,
		})
	}
	newCorpus := make(map[string]rpctype.RPCInput)
	// Note: inputs are unsorted (based on map iteration).
	// This gives some intentional non-determinism during minimization.
	for _, ctx := range signal.Minimize(inputs) {
		inp := ctx.(rpctype.RPCInput)
		newCorpus[hash.String(inp.Prog)] = inp
	}
	// for debug and evaluation
	// for sig, inp := range mgr.corpus {
	// 	if strings.Contains(sig, "_dup") {
	// 		newCorpus[sig] = inp
	// 	}
	// }
	//
	// for extremum inputs
	for sig, inp := range mgr.corpus {
		if strings.Contains(sig, "_extremum") {
			for _, item := range mgr.corpusSvExtremumHashes {
				if item["min"] == sig || item["max"] == sig {
					newCorpus[sig] = inp
					break
				}
			}
		}
	}
	log.Logf(1, "minimized corpus: %v -> %v", len(mgr.corpus), len(newCorpus))
	mgr.corpus = newCorpus
	mgr.lastMinCorpus = len(newCorpus)

	// From time to time we get corpus explosion due to different reason:
	// generic bugs, per-OS bugs, problems with fallback coverage, kcov bugs, etc.
	// This has bad effect on the instance and especially on instances
	// connected via hub. Do some per-syscall sanity checking to prevent this.
	for call, info := range mgr.collectSyscallInfoUnlocked() {
		if mgr.cfg.Cover {
			// If we have less than 1K inputs per this call,
			// accept all new inputs unconditionally.
			if info.count < 1000 {
				continue
			}
			// If we have more than 3K already, don't accept any more.
			// Between 1K and 3K look at amount of coverage we are getting from these programs.
			// Empirically, real coverage for the most saturated syscalls is ~30-60
			// per program (even when we have a thousand of them). For explosion
			// case coverage tend to be much lower (~0.3-5 per program).
			if info.count < 3000 && len(info.pcCov)/info.count >= 10 {
				continue
			}
		} else {
			// If we don't have real coverage, signal is weak.
			// If we have more than several hundreds, there is something wrong.
			if info.count < 300 {
				continue
			}
		}
		if mgr.saturatedCalls[call] {
			continue
		}
		mgr.saturatedCalls[call] = true
		log.Logf(0, "coverage for %v has saturated, not accepting more inputs", call)
	}

	// Don't minimize persistent corpus until fuzzers have triaged all inputs from it.
	if mgr.phase < phaseTriagedCorpus {
		return
	}
	for key := range mgr.corpusDB.Records {
		_, ok1 := mgr.corpus[key]
		_, ok2 := mgr.disabledHashes[key]
		if !ok1 && !ok2 {
			mgr.corpusDB.Delete(key)
		}
	}
	mgr.corpusDB.BumpVersion(currentDBVersion)
}

type CallCov struct {
	count int
	pcCov cover.PcCover
	svCov signal.SvCover
}

func (mgr *Manager) collectSyscallInfo() map[string]*CallCov {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	return mgr.collectSyscallInfoUnlocked()
}

func (mgr *Manager) collectSyscallInfoUnlocked() map[string]*CallCov {
	if mgr.checkResult == nil {
		return nil
	}
	calls := make(map[string]*CallCov)
	for _, call := range mgr.checkResult.EnabledCalls[mgr.cfg.Sandbox] {
		calls[mgr.target.Syscalls[call].Name] = new(CallCov)
	}
	for _, inp := range mgr.corpus {
		if calls[inp.Call] == nil {
			calls[inp.Call] = new(CallCov)
		}
		cc := calls[inp.Call]
		cc.count++
		cc.pcCov.Merge(inp.PcCover)
		cc.svCov.Merge(inp.ProgSvCover.Deserialize())
	}
	return calls
}

func (mgr *Manager) fuzzerConnect() ([]rpctype.RPCInput, BugFrames) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	mgr.minimizeCorpus()
	corpus := make([]rpctype.RPCInput, 0, len(mgr.corpus))
	for sig, inp := range mgr.corpus {
		if strings.Contains(sig, "_dup") {
			continue
		}
		corpus = append(corpus, inp)
	}
	memoryLeakFrames := make([]string, 0, len(mgr.memoryLeakFrames))
	for frame := range mgr.memoryLeakFrames {
		memoryLeakFrames = append(memoryLeakFrames, frame)
	}
	dataRaceFrames := make([]string, 0, len(mgr.dataRaceFrames))
	for frame := range mgr.dataRaceFrames {
		dataRaceFrames = append(dataRaceFrames, frame)
	}
	return corpus, BugFrames{memoryLeaks: memoryLeakFrames, dataRaces: dataRaceFrames}
}

func (mgr *Manager) machineChecked(a *rpctype.CheckArgs) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if len(mgr.cfg.EnabledSyscalls) != 0 && len(a.DisabledCalls[mgr.cfg.Sandbox]) != 0 {
		disabled := make(map[string]string)
		for _, dc := range a.DisabledCalls[mgr.cfg.Sandbox] {
			disabled[mgr.target.Syscalls[dc.ID].Name] = dc.Reason
		}
		for _, id := range mgr.enabledSyscalls {
			name := mgr.target.Syscalls[id].Name
			if reason := disabled[name]; reason != "" {
				log.Logf(0, "disabling %v: %v", name, reason)
			}
		}
	}
	if a.Error != "" {
		log.Fatalf("machine check: %v", a.Error)
	}
	log.Logf(0, "machine check:")
	log.Logf(0, "%-24v: %v/%v", "syscalls",
		len(a.EnabledCalls[mgr.cfg.Sandbox]), len(mgr.target.Syscalls))
	for _, feat := range a.Features.Supported() {
		log.Logf(0, "%-24v: %v", feat.Name, feat.Reason)
	}
	mgr.checkResult = a
	mgr.loadCorpus()
	mgr.firstConnect = time.Now()
}

func (mgr *Manager) newInput(inp rpctype.RPCInput, sign signal.Signal, svSignal signal.Signal, svCover signal.SvCover, svExtremum signal.SvExtremum) bool {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	sig := ""
	needAdd := false
	// update SvExtremum values
	if svExtremum != nil && len(svExtremum) != 0 {
		if inp.IsNewSvSeed == 5 {
			sig = hash.String(inp.Prog) + "_extremum"
		} else {
			sig = hash.String(inp.Prog)
		}
		// update svExtremum values
		for svNo, item := range svExtremum {
			if _, ok := mgr.corpusSvExtremum[svNo]; !ok {
				mgr.corpusSvExtremum[svNo] = make(map[string]int32)
				mgr.corpusSvExtremum[svNo]["min"] = 2147483647  // MAXINT32
				mgr.corpusSvExtremum[svNo]["max"] = -2147483648 // MININT32
				mgr.corpusSvExtremum[svNo]["update"] = 0
			}
			if _, ok := mgr.corpusSvExtremumHashes[svNo]; !ok {
				mgr.corpusSvExtremumHashes[svNo] = make(map[string]string)
				mgr.corpusSvExtremumHashes[svNo]["min"] = ""
				mgr.corpusSvExtremumHashes[svNo]["max"] = ""
			}
			if svValue, ok := item["min"]; ok {
				if svValue < mgr.corpusSvExtremum[svNo]["min"] {
					mgr.corpusSvExtremum[svNo]["min"] = svValue
					mgr.corpusSvExtremumHashes[svNo]["min"] = sig
					mgr.corpusSvExtremum[svNo]["update"]++
					needAdd = true
				}
			}
			if svValue, ok := item["max"]; ok {
				if svValue > mgr.corpusSvExtremum[svNo]["max"] {
					mgr.corpusSvExtremum[svNo]["max"] = svValue
					mgr.corpusSvExtremumHashes[svNo]["max"] = sig
					mgr.corpusSvExtremum[svNo]["update"]++
					needAdd = true
				}
			}
		}
		if needAdd == true && inp.IsNewSvSeed == 5 {
			if _, ok := mgr.corpus[sig]; !ok {
				mgr.corpus[sig] = inp
				mgr.corpusDB.Save(sig, inp.Prog, 0)
				if err := mgr.corpusDB.Flush(); err != nil {
					log.Logf(0, "failed to save corpus database: %v", err)
				}
			}
		}
	}
	if inp.IsNewSvSeed == 5 {
		return needAdd
	}

	if mgr.saturatedCalls[inp.Call] {
		return false
	}
	sig = hash.String(inp.Prog)

	if _, ok := mgr.buckets[inp.PathHash]; !ok {
		mgr.buckets[inp.PathHash] = make(map[string]bool)
	}
	if _, ok := mgr.buckets[inp.PathHash][sig]; !ok {
		mgr.buckets[inp.PathHash][sig] = true
	}
	// found new PcCover
	if old, ok := mgr.corpus[sig]; ok {
		// The input is already present, but possibly with diffrent signal/coverage/call.
		// just for debug and evaluation
		// oldTmp := old
		// oldTmp.PcCoverChanges = 9999999
		// mgr.corpus[sig+"_dup"] = oldTmp
		sign.Merge(old.Signal.Deserialize())
		svSignal.Merge(old.SvSignal.Deserialize())
		svCover.Merge(old.SvCover.Deserialize())
		old.Signal = sign.Serialize()
		old.SvSignal = svSignal.Serialize()
		old.SvCover = svCover.Serialize()
		if inp.IsNewSvSeed != 2 && inp.IsNewSvSeed != 4 {
			old.PcCoverChanges = old.PcCoverChanges + 1
		} else {
			old.SvCoverChanges = old.SvCoverChanges + 1
		}

		var pcCov cover.PcCover
		pcCov.Merge(old.PcCover)
		pcCov.Merge(inp.PcCover)
		old.PcCover = pcCov.Serialize()
		mgr.corpus[sig] = old
	} else {
		mgr.corpus[sig] = inp
		mgr.corpusDB.Save(sig, inp.Prog, 0)
		if err := mgr.corpusDB.Flush(); err != nil {
			log.Logf(0, "failed to save corpus database: %v", err)
		}
	}

	// assess prio for every new input in this bucket
	// Harmonic mean for prog prio
	// prog prio = (sum:{rangePrio} for all sv)
	// if rangeHitTime > mean:{rangeHitTime}, rangePrio = 0
	// else rangePrio = (mean:{rangeHitTime} - rangeHitTime)/sum:{rangeHitTime}) for all range
	// if inp.PathHash == 0 || inp.PathHash == 0xdeadbeef {
	// 	return true
	// }
	// for s := range mgr.buckets[inp.PathHash] {
	// 	p := mgr.corpus[s]
	// 	progSvCover := p.ProgSvCover.Deserialize()
	// 	hitRanges := make(map[uint32]map[int32]bool)
	// 	for k := range progSvCover {
	// 		svCov := uint32(k & 0xffffffff)
	// 		sv_range_no := svCov & 0xffff
	// 		sv_no := (svCov >> 16) & 0x7fff
	// 		sv_range_value := mgr.svRanges[sv_no][sv_range_no]
	// 		if _, ok := hitRanges[sv_no]; !ok {
	// 			hitRanges[sv_no] = make(map[int32]bool)
	// 		}
	// 		hitRanges[sv_no][sv_range_value] = true
	// 	}
	// 	var svPrio float32
	// 	svPrio = 0.0
	// 	// log.Logf(0, "init svPrio")
	// 	for sv_no, rs := range mgr.svRangeCover {
	// 		var cnt uint32
	// 		var sum uint64
	// 		sum = 0
	// 		cnt = 0
	// 		for sv_range_value := range rs {
	// 			if mgr.svRangeCover[sv_no][sv_range_value][0] == 0 {
	// 				continue
	// 			}
	// 			cnt++
	// 			sum += mgr.svRangeCover[sv_no][sv_range_value][0]
	// 		}
	// 		if sum == 0 || cnt == 0 {
	// 			continue
	// 		}
	// 		var mean float32
	// 		mean = float32(sum*1.0) / float32(cnt)
	// 		for sv_range_value := range hitRanges[sv_no] {
	// 			if float32(mgr.svRangeCover[sv_no][sv_range_value][0]) >= mean {
	// 				continue
	// 			}
	// 			svPrio += ((mean - float32(mgr.svRangeCover[sv_no][sv_range_value][0])) / float32(sum) * 10000000)
	// 			// log.Logf(0, "sum: %v  mean: %v  cur: %v increase: %v  svPrio: %v", sum, mean, mgr.svRangeCover[sv_no][sv_range_value][0], (mean-float32(mgr.svRangeCover[sv_no][sv_range_value][0]))/float32(sum)*10000000, svPrio)
	// 		}
	// 	}
	// 	p.SvPrio = int64(svPrio)
	// 	if p.SvPrio == 0 {
	// 		p.SvPrio = 1
	// 	}
	// 	mgr.corpus[s] = p
	// }
	return true
}

func (mgr *Manager) updateMutationInfo(corpusMutationCnt map[string]uint32, corpusHintCnt map[string]uint32, totalSvCover map[uint64]uint64, totalSvSignal map[uint32]uint64) {
	// timeStr1 := time.Now().Format("2006/01/02 15:04:05 ")
	// fmt.Printf("%v [+] updateMutationInfo start in syz-manager\n", timeStr1)
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	for sig, cnt := range corpusMutationCnt {
		if p, ok := mgr.corpus[sig]; ok {
			// log.Logf(0, "p.Mutation += %v", cnt)
			p.Mutation += cnt
			mgr.corpus[sig] = p
		}
	}
	for sig, cnt := range corpusHintCnt {
		if p, ok := mgr.corpus[sig]; ok {
			// log.Logf(0, "p.Mutation += %v", cnt)
			p.Hinted += cnt
			mgr.corpus[sig] = p
		}
	}

	for k, cnt := range totalSvCover {
		if k&0xffff000000000000 == 0xffff000000000000 {
			continue
		}
		svInstPc := uint32(k >> 32)
		svCov := uint32(k & 0xffffffff)
		sv_range_no := svCov & 0xffff
		sv_no := (svCov >> 16) & 0x7fff
		sv_range_value := mgr.svRanges[sv_no][sv_range_no]
		if _, ok := mgr.svRangeCover[sv_no][sv_range_value][svInstPc]; ok {
			mgr.svRangeCover[sv_no][sv_range_value][svInstPc] += cnt
		} else {
			mgr.svRangeCover[sv_no][sv_range_value][svInstPc] = cnt
		}
		// mgr.svRangeCover[sv_no][sv_range_value][0] store the total hitTime
		if _, ok1 := mgr.svRangeCover[sv_no][sv_range_value][0]; ok1 {
			mgr.svRangeCover[sv_no][sv_range_value][0] += cnt
		} else {
			mgr.svRangeCover[sv_no][sv_range_value][0] = cnt
		}
		if p, ok := mgr.totalSvCover[k]; ok {
			// log.Logf(0, "p.Mutation += %v", cnt)
			p += cnt
			mgr.totalSvCover[k] = p
		} else {
			mgr.totalSvCover[k] = cnt
		}
	}
	for k, cnt := range totalSvSignal {
		if p, ok := mgr.totalSvSignal[k]; ok {
			// log.Logf(0, "p.Mutation += %v", cnt)
			p += cnt
			mgr.totalSvSignal[k] = p
		} else {
			mgr.totalSvSignal[k] = cnt
		}
	}
	// timeStr2 := time.Now().Format("2006/01/02 15:04:05 ")
	// fmt.Printf("%v [+] updateMutationInfo end in syz-manager\n", timeStr2)
	// for _, p := range serv.corpus {
	// 	log.Logf(0, "serv.corpus[sig]= %v", p.Mutation)
	// }
}

func (mgr *Manager) candidateBatch(size int) []rpctype.RPCCandidate {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	var res []rpctype.RPCCandidate
	for i := 0; i < size && len(mgr.candidates) > 0; i++ {
		last := len(mgr.candidates) - 1
		res = append(res, mgr.candidates[last])
		mgr.candidates[last] = rpctype.RPCCandidate{}
		mgr.candidates = mgr.candidates[:last]
	}
	if len(mgr.candidates) == 0 {
		mgr.candidates = nil
		if mgr.phase == phaseLoadedCorpus {
			if mgr.cfg.HubClient != "" {
				mgr.phase = phaseTriagedCorpus
				go mgr.hubSyncLoop()
			} else {
				mgr.phase = phaseTriagedHub
			}
		} else if mgr.phase == phaseQueriedHub {
			mgr.phase = phaseTriagedHub
		}
	}
	return res
}

func (mgr *Manager) rotateCorpus() bool {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	return mgr.phase == phaseTriagedHub
}

func (mgr *Manager) collectUsedFiles() {
	if mgr.vmPool == nil {
		return
	}
	addUsedFile := func(f string) {
		if f == "" {
			return
		}
		stat, err := os.Stat(f)
		if err != nil {
			log.Fatalf("failed to stat %v: %v", f, err)
		}
		mgr.usedFiles[f] = stat.ModTime()
	}
	cfg := mgr.cfg
	addUsedFile(cfg.SyzFuzzerBin)
	addUsedFile(cfg.SyzExecprogBin)
	addUsedFile(cfg.SyzExecutorBin)
	addUsedFile(cfg.SSHKey)
	if vmlinux := filepath.Join(cfg.KernelObj, mgr.sysTarget.KernelObject); osutil.IsExist(vmlinux) {
		addUsedFile(vmlinux)
	}
	if cfg.Image != "9p" {
		addUsedFile(cfg.Image)
	}
}

func (mgr *Manager) checkUsedFiles() {
	for f, mod := range mgr.usedFiles {
		stat, err := os.Stat(f)
		if err != nil {
			log.Fatalf("failed to stat %v: %v", f, err)
		}
		if mod != stat.ModTime() {
			log.Fatalf("file %v that syz-manager uses has been modified by an external program\n"+
				"this can lead to arbitrary syz-manager misbehavior\n"+
				"modification time has changed: %v -> %v\n"+
				"don't modify files that syz-manager uses. exiting to prevent harm",
				f, mod, stat.ModTime())
		}
	}
}

func (mgr *Manager) dashboardReporter() {
	webAddr := publicWebAddr(mgr.cfg.HTTP)
	var lastFuzzingTime time.Duration
	var lastCrashes, lastExecs uint64
	for {
		time.Sleep(time.Minute)
		mgr.mu.Lock()
		if mgr.firstConnect.IsZero() {
			mgr.mu.Unlock()
			continue
		}
		crashes := mgr.stats.crashes.get()
		execs := mgr.stats.execTotal.get()
		req := &dashapi.ManagerStatsReq{
			Name:        mgr.cfg.Name,
			Addr:        webAddr,
			UpTime:      time.Since(mgr.firstConnect),
			Corpus:      uint64(len(mgr.corpus)),
			Cover:       mgr.stats.corpusSignal.get(),
			FuzzingTime: mgr.fuzzingTime - lastFuzzingTime,
			Crashes:     crashes - lastCrashes,
			Execs:       execs - lastExecs,
		}
		mgr.mu.Unlock()

		if err := mgr.dash.UploadManagerStats(req); err != nil {
			log.Logf(0, "failed to upload dashboard stats: %v", err)
			continue
		}
		mgr.mu.Lock()
		lastFuzzingTime += req.FuzzingTime
		lastCrashes += req.Crashes
		lastExecs += req.Execs
		mgr.mu.Unlock()
	}
}

func publicWebAddr(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err == nil && port != "" {
		if host, err := os.Hostname(); err == nil {
			addr = net.JoinHostPort(host, port)
		}
		if GCE, err := gce.NewContext(); err == nil {
			addr = net.JoinHostPort(GCE.ExternalIP, port)
		}
	}
	return "http://" + addr
}

func (mgr *Manager) initSvCover() error {
	var sv_ranges []SvType
	if mgr.isSvCoverInit == true {
		return nil
	}
	bytes, err := ioutil.ReadFile(mgr.cfg.SvRangeJSONFile)
	if err != nil {
		fmt.Println("ReadFile: ", err.Error())
		return err
	}
	if err := json.Unmarshal(bytes, &sv_ranges); err != nil {
		fmt.Println("Unmarshal: ", err.Error())
		return err
	}

	mgr.svRangeCover = make(map[uint32]map[int32]map[uint32]uint64)
	mgr.svRanges = make(map[uint32]map[uint32]int32)
	mgr.svName = make(map[uint32]string)
	mgr.svFieldName = make(map[uint32]string)
	for _, svInfo := range sv_ranges {
		// log.Logf(0, "init for svNo: %v", svInfo.Id)
		mgr.svName[svInfo.Id] = svInfo.Name
		mgr.svFieldName[svInfo.Id] = svInfo.FieldName
		mgr.svRangeCover[svInfo.Id] = make(map[int32]map[uint32]uint64)
		mgr.svRanges[svInfo.Id] = make(map[uint32]int32)
		for no, value := range svInfo.Values {
			mgr.svRangeCover[svInfo.Id][value] = make(map[uint32]uint64)
			mgr.svRanges[svInfo.Id][uint32(no)] = value
		}
	}
	mgr.isSvCoverInit = true
	return nil
}

