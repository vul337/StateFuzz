// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/html"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/signal"

	// "github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/prog"
)

func (mgr *Manager) initHTTP() {
	http.HandleFunc("/", mgr.httpSummary)
	http.HandleFunc("/config", mgr.httpConfig)
	http.HandleFunc("/syscalls", mgr.httpSyscalls)
	http.HandleFunc("/corpus", mgr.httpCorpus)
	http.HandleFunc("/svcorpus", mgr.httpSvCorpus)
	http.HandleFunc("/crash", mgr.httpCrash)
	http.HandleFunc("/cover", mgr.httpCover)
	http.HandleFunc("/svcover", mgr.httpSvCover)
	http.HandleFunc("/svcorpuscover", mgr.httpSvCorpusCover)
	http.HandleFunc("/svextremum", mgr.httpSvExtremum)
	http.HandleFunc("/inputsvcover", mgr.httpInputSvCover)
	http.HandleFunc("/persvcover", mgr.httpPerSvCover)
	http.HandleFunc("/persvcorpuscover", mgr.httpPerSvCorpusCover)
	http.HandleFunc("/prio", mgr.httpPrio)
	http.HandleFunc("/file", mgr.httpFile)
	http.HandleFunc("/report", mgr.httpReport)
	http.HandleFunc("/rawcover", mgr.httpRawCover)
	http.HandleFunc("/totalsvcover", mgr.httpTotalSvCover)
	http.HandleFunc("/totalsvsignal", mgr.httpTotalSvSignal)
	http.HandleFunc("/input", mgr.httpInput)
	// Browsers like to request this, without special handler this goes to / handler.
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {})

	ln, err := net.Listen("tcp4", mgr.cfg.HTTP)
	if err != nil {
		log.Fatalf("failed to listen on %v: %v", mgr.cfg.HTTP, err)
	}
	log.Logf(0, "serving http on http://%v", ln.Addr())
	go func() {
		err := http.Serve(ln, nil)
		log.Fatalf("failed to serve http: %v", err)
	}()
}

func (mgr *Manager) httpSummary(w http.ResponseWriter, r *http.Request) {
	data := &UISummaryData{
		Name:  mgr.cfg.Name,
		Log:   log.CachedLogOutput(),
		Stats: mgr.collectStats(),
	}

	var err error
	if data.Crashes, err = mgr.collectCrashes(mgr.cfg.Workdir); err != nil {
		http.Error(w, fmt.Sprintf("failed to collect crashes: %v", err), http.StatusInternalServerError)
		return
	}

	if err := summaryTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err),
			http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpConfig(w http.ResponseWriter, r *http.Request) {
	data, err := json.MarshalIndent(mgr.cfg, "", "\t")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to encode json: %v", err),
			http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func (mgr *Manager) httpSyscalls(w http.ResponseWriter, r *http.Request) {
	data := &UISyscallsData{
		Name: mgr.cfg.Name,
	}
	for c, cc := range mgr.collectSyscallInfo() {
		data.Calls = append(data.Calls, UICallType{
			Name:    c,
			Inputs:  cc.count,
			PcCover: len(cc.pcCov),
			SvCover: len(cc.svCov),
		})
	}
	sort.Slice(data.Calls, func(i, j int) bool {
		return data.Calls[i].Name < data.Calls[j].Name
	})
	if err := syscallsTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err),
			http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) collectStats() []UIStat {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	rawStats := mgr.stats.all()
	// head := prog.GitRevisionBase
	stats := []UIStat{
		// {Name: "revision", Value: fmt.Sprint(head[:8]), Link: vcs.LogLink(vcs.SyzkallerRepo, head)},
		{Name: "config", Value: mgr.cfg.Name, Link: "/config"},
		{Name: "uptime", Value: fmt.Sprint(time.Since(mgr.startTime) / 1e9 * 1e9)},
		{Name: "fuzzing", Value: fmt.Sprint(mgr.fuzzingTime / 60e9 * 60e9)},
		{Name: "corpus", Value: fmt.Sprint(len(mgr.buckets)), Link: "/corpus"},
		{Name: "sv corpus", Value: fmt.Sprint(rawStats["sv corpus"]), Link: "/svcorpus"},
		{Name: "triage queue", Value: fmt.Sprint(len(mgr.candidates))},
		{Name: "pc cover", Value: fmt.Sprint(rawStats["pc cover"]), Link: "/cover"},
		{Name: "sv cover", Value: fmt.Sprint(rawStats["sv cover"]), Link: "/svcover"},
		{Name: "sv extremum", Value: "link", Link: "/svextremum"},
		{Name: "signal", Value: fmt.Sprint(rawStats["signal"])},
	}
	delete(rawStats, "sv corpus")
	delete(rawStats, "pc cover")
	delete(rawStats, "signal")
	delete(rawStats, "sv cover")
	if mgr.checkResult != nil {
		stats = append(stats, UIStat{
			Name:  "syscalls",
			Value: fmt.Sprint(len(mgr.checkResult.EnabledCalls[mgr.cfg.Sandbox])),
			Link:  "/syscalls",
		})
	}

	secs := uint64(1)
	if !mgr.firstConnect.IsZero() {
		secs = uint64(time.Since(mgr.firstConnect))/1e9 + 1
	}
	intStats := convertStats(rawStats, secs)
	sort.Slice(intStats, func(i, j int) bool {
		return intStats[i].Name < intStats[j].Name
	})
	stats = append(stats, intStats...)
	return stats
}

func convertStats(stats map[string]uint64, secs uint64) []UIStat {
	var intStats []UIStat
	for k, v := range stats {
		val := fmt.Sprintf("%v", v)
		if x := v / secs; x >= 10 {
			val += fmt.Sprintf(" (%v/sec)", x)
		} else if x := v * 60 / secs; x >= 10 {
			val += fmt.Sprintf(" (%v/min)", x)
		} else {
			x := v * 60 * 60 / secs
			val += fmt.Sprintf(" (%v/hour)", x)
		}
		intStats = append(intStats, UIStat{Name: k, Value: val})
	}
	return intStats
}

func (mgr *Manager) httpCrash(w http.ResponseWriter, r *http.Request) {
	crashID := r.FormValue("id")
	crash := readCrash(mgr.cfg.Workdir, crashID, nil, mgr.startTime, true)
	if crash == nil {
		http.Error(w, "failed to read crash info", http.StatusInternalServerError)
		return
	}
	if err := crashTemplate.Execute(w, crash); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpCorpus(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	data := UICorpus{
		Call: r.FormValue("call"),
	}
	for sig, inp := range mgr.corpus {
		// if inp.IsNewSvSeed == 2 {
		// 	continue
		// }
		if data.Call != "" && data.Call != inp.Call {
			continue
		}
		p, err := mgr.target.Deserialize(inp.Prog, prog.NonStrict)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to deserialize program: %v", err), http.StatusInternalServerError)
			return
		}
		data.Inputs = append(data.Inputs, &UIInput{
			Sig:   sig,
			Short: p.String(),
			// PcCover:        len(inp.PcCover),
			PcCover:        len(inp.ProgPcCover),
			SvCover:        len(inp.ProgSvCover.Elems),
			TimeStamp:      inp.TimeStamp,
			IsNewSvSeed:    inp.IsNewSvSeed,
			PathHash:       inp.PathHash,
			ParentSig:      inp.ParentSig,
			Mutation:       inp.Mutation,
			Hinted:         inp.Hinted,
			PcCoverChanges: inp.PcCoverChanges,
			SvCoverChanges: inp.SvCoverChanges,
			SvPrio:         inp.SvPrio,
		})
	}
	sort.Slice(data.Inputs, func(i, j int) bool {
		a, b := data.Inputs[i], data.Inputs[j]
		if a.PathHash != b.PathHash {
			return a.PathHash > b.PathHash
		} else if a.IsNewSvSeed > b.IsNewSvSeed {
			return a.IsNewSvSeed > b.IsNewSvSeed
		} else if a.TimeStamp != b.TimeStamp {
			return a.TimeStamp > b.TimeStamp
		} else if a.PcCover != b.PcCover {
			return a.PcCover > b.PcCover
		}
		return a.Short < b.Short
	})

	if err := corpusTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpSvCorpus(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	data := UICorpus{
		Call: r.FormValue("call"),
	}
	for sig, inp := range mgr.corpus {
		if inp.IsNewSvSeed != 2 && inp.IsNewSvSeed != 4 {
			continue
		}
		if data.Call != "" && data.Call != inp.Call {
			continue
		}
		p, err := mgr.target.Deserialize(inp.Prog, prog.NonStrict)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to deserialize program: %v", err), http.StatusInternalServerError)
			return
		}
		data.Inputs = append(data.Inputs, &UIInput{
			Sig:         sig,
			Short:       p.String(),
			PcCover:     len(inp.ProgPcCover),
			SvCover:     len(inp.ProgSvCover.Elems),
			TimeStamp:   inp.TimeStamp,
			IsNewSvSeed: inp.IsNewSvSeed,
			PathHash:    inp.PathHash,
			ParentSig:   inp.ParentSig,
		})
	}
	sort.Slice(data.Inputs, func(i, j int) bool {
		a, b := data.Inputs[i], data.Inputs[j]
		if a.PathHash != b.PathHash {
			return a.PathHash > b.PathHash
		} else if a.TimeStamp != b.TimeStamp {
			return a.TimeStamp > b.TimeStamp
		} else if a.PcCover != b.PcCover {
			return a.PcCover > b.PcCover
		}
		return a.Short < b.Short
	})

	if err := svCorpusTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpCover(w http.ResponseWriter, r *http.Request) {
	if !mgr.cfg.Cover {
		mgr.mu.Lock()
		defer mgr.mu.Unlock()
		mgr.httpCoverFallback(w, r)
	}
	// Note: initCover is executed without mgr.mu because it takes very long time
	// (but it only reads config and it protected by initCoverOnce).
	if err := initCover(mgr.cfg.KernelObj, mgr.sysTarget.KernelObject,
		mgr.cfg.KernelSrc, mgr.cfg.KernelBuildSrc, mgr.cfg.TargetVMArch, mgr.cfg.TargetOS); err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
		return
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.httpCoverCover(w, r)
}

type SvType struct {
	Name      string
	FieldName string
	Id        uint32
	Values    []int32
}

func (mgr *Manager) httpSvCover(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	data := UISvCoverData{
		Name: mgr.cfg.Name,
	}

	if err := mgr.initSvCover(); err != nil {
		http.Error(w, fmt.Sprintf("failed to init sv coverage: %v", err), http.StatusInternalServerError)
	}

	// var sv_range_no uint32
	// var sv_range_value int32
	// var sv_no uint32
	// var pc uint32
	// var svInstPc uint32
	// // var rw_type uint32
	// for _, inp := range mgr.corpus {
	// 	for _, svCov := range inp.SvCover.Elems {
	// 		svInstPc = uint32(svCov >> 32)
	// 		pc = uint32(svCov & 0xffffffff)
	// 		sv_range_no = pc & 0xffff
	// 		sv_no = (pc >> 16) & 0x7fff
	// 		sv_range_value = mgr.svRanges[sv_no][sv_range_no]
	// 		// log.Logf(0, "pc %x, sv_no %x, sv_range_no %x, sv_range_value %x", svCov, sv_no, sv_range_no, sv_range_value)
	// 		// rw_type = svCov >> 31
	// 		if _, ok := mgr.svRangeCover[sv_no][sv_range_value][svInstPc]; ok {
	// 			mgr.svRangeCover[sv_no][sv_range_value][svInstPc]++
	// 		} else {
	// 			mgr.svRangeCover[sv_no][sv_range_value][svInstPc] = 1
	// 		}
	// 	}
	// }

	for svNo, svRange := range mgr.svRangeCover {
		var hit_num uint32
		hit_num = 0
		for _, i := range svRange {
			if len(i) > 0 {
				hit_num += 1
			}
		}
		data.SVs = append(data.SVs, UISvCoverType{
			SvNo:        svNo,
			SvName:      mgr.svName[svNo],
			SvFieldName: mgr.svFieldName[svNo],
			HitNum:      hit_num,
			AllNum:      uint32(len(svRange)),
		})
	}

	sort.Slice(data.SVs, func(i, j int) bool {
		a, b := data.SVs[i], data.SVs[j]
		if a.SvNo != b.SvNo {
			return a.SvNo < b.SvNo
		}
		return a.SvName < b.SvName
	})

	if err := svCoverTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpSvCorpusCover(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	data := UISvCoverData{
		Name: mgr.cfg.Name,
	}

	if err := mgr.initSvCover(); err != nil {
		http.Error(w, fmt.Sprintf("failed to init sv coverage: %v", err), http.StatusInternalServerError)
	}

	mgr.svRangeCorpusCover = make(map[uint32]map[int32]map[uint32]uint64)
	var sv_range_no uint32
	var sv_range_value int32
	var sv_no uint32
	var pc uint32
	var svInstPc uint32
	// var rw_type uint32
	for _, inp := range mgr.corpus {
		for _, svCov := range inp.ProgSvCover.Elems {
			svInstPc = uint32(svCov >> 32)
			pc = uint32(svCov & 0xffffffff)
			sv_range_no = pc & 0xffff
			sv_no = (pc >> 16) & 0x7fff
			sv_range_value = mgr.svRanges[sv_no][sv_range_no]
			if _, ok := mgr.svRangeCorpusCover[sv_no]; !ok {
				mgr.svRangeCorpusCover[sv_no] = make(map[int32]map[uint32]uint64)
			}
			if _, ok := mgr.svRangeCorpusCover[sv_no][sv_range_value]; !ok {
				mgr.svRangeCorpusCover[sv_no][sv_range_value] = make(map[uint32]uint64)
			}
			// log.Logf(0, "pc %x, sv_no %x, sv_range_no %x, sv_range_value %x", svCov, sv_no, sv_range_no, sv_range_value)
			// rw_type = svCov >> 31
			if _, ok := mgr.svRangeCorpusCover[sv_no][sv_range_value][svInstPc]; ok {
				mgr.svRangeCorpusCover[sv_no][sv_range_value][svInstPc]++
			} else {
				mgr.svRangeCorpusCover[sv_no][sv_range_value][svInstPc] = 1
			}
		}
	}

	for svNo, svRange := range mgr.svRangeCorpusCover {
		var hit_num uint32
		hit_num = 0
		for _, i := range svRange {
			if len(i) > 0 {
				hit_num += 1
			}
		}
		data.SVs = append(data.SVs, UISvCoverType{
			SvNo:        svNo,
			SvName:      mgr.svName[svNo],
			SvFieldName: mgr.svFieldName[svNo],
			HitNum:      hit_num,
			AllNum:      uint32(len(svRange)),
		})
	}

	sort.Slice(data.SVs, func(i, j int) bool {
		a, b := data.SVs[i], data.SVs[j]
		if a.SvNo != b.SvNo {
			return a.SvNo < b.SvNo
		}
		return a.SvName < b.SvName
	})

	if err := svCorpusCoverTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpSvExtremum(w http.ResponseWriter, r *http.Request) {
	data := UISvExtremumData{
		Name: mgr.cfg.Name,
	}
	mgr.mu.Lock()
	for svNo, item := range mgr.corpusSvExtremum {
		data.SvExtremums = append(data.SvExtremums, UISvExtremumType{
			SvNo:        svNo,
			SvName:      mgr.svName[svNo],
			SvFieldName: mgr.svFieldName[svNo],
			Max:         item["max"],
			MaxSig:      mgr.corpusSvExtremumHashes[svNo]["max"],
			Min:         item["min"],
			MinSig:      mgr.corpusSvExtremumHashes[svNo]["min"],
			Update:      item["update"],
		})
	}
	mgr.mu.Unlock()

	sort.Slice(data.SvExtremums, func(i, j int) bool {
		a, b := data.SvExtremums[i], data.SvExtremums[j]
		if a.SvNo != b.SvNo {
			return a.SvNo < b.SvNo
		}
		return a.SvName < b.SvName
	})

	if err := svExtremumTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpPerSvCover(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	data := UIPerSvRangeData{}

	svNoStr := r.FormValue("sv")

	svNo, err0 := strconv.ParseUint(svNoStr, 10, 32)
	if err0 != nil {
		http.Error(w, fmt.Sprintf("can't convert svId to uint32: %v", err0), http.StatusInternalServerError)
		return
	}

	sv, ok := mgr.svRangeCover[uint32(svNo)]
	if !ok {
		http.Error(w, "can't find the sv Id", http.StatusInternalServerError)
		return
	}

	for value, hitPcs := range sv {
		var hitPcMap []UIHitPcMapType
		for pc, time := range hitPcs {
			hitPcMap = append(hitPcMap, UIHitPcMapType{
				SvInstPc: pc,
				HitTime:  time,
			})
		}
		data.Ranges = append(data.Ranges, UIPerSvRangeType{
			Value:    value,
			HitPcMap: hitPcMap,
		})
	}

	sort.Slice(data.Ranges, func(i, j int) bool {
		a, b := data.Ranges[i], data.Ranges[j]
		return a.Value < b.Value
	})

	if err := perSvCoverTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpPerSvCorpusCover(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	data := UIPerSvRangeData{}

	svNoStr := r.FormValue("sv")

	svNo, err0 := strconv.ParseUint(svNoStr, 10, 32)
	if err0 != nil {
		http.Error(w, fmt.Sprintf("can't convert svId to uint32: %v", err0), http.StatusInternalServerError)
		return
	}

	sv, ok := mgr.svRangeCorpusCover[uint32(svNo)]
	if !ok {
		http.Error(w, "can't find the sv Id", http.StatusInternalServerError)
		return
	}

	for value, hitPcs := range sv {
		var hitPcMap []UIHitPcMapType
		for pc, time := range hitPcs {
			hitPcMap = append(hitPcMap, UIHitPcMapType{
				SvInstPc: pc,
				HitTime:  time,
			})
		}
		data.Ranges = append(data.Ranges, UIPerSvRangeType{
			Value:    value,
			HitPcMap: hitPcMap,
		})
	}

	sort.Slice(data.Ranges, func(i, j int) bool {
		a, b := data.Ranges[i], data.Ranges[j]
		return a.Value < b.Value
	})

	if err := perSvCoverTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpCoverCover(w http.ResponseWriter, r *http.Request) {
	var progs []cover.Prog
	if sig := r.FormValue("input"); sig != "" {
		inp := mgr.corpus[sig]
		progs = append(progs, cover.Prog{
			Data: string(inp.Prog),
			// PCs:  coverToPCs(inp.PcCover, mgr.cfg.TargetVMArch),
			PCs: coverToPCs(inp.ProgPcCover, mgr.cfg.TargetVMArch),
		})
	} else {
		call := r.FormValue("call")
		for _, inp := range mgr.corpus {
			if call != "" && call != inp.Call {
				continue
			}
			progs = append(progs, cover.Prog{
				Data: string(inp.Prog),
				// PCs:  coverToPCs(inp.PcCover, mgr.cfg.TargetVMArch),
				PCs: coverToPCs(inp.ProgPcCover, mgr.cfg.TargetVMArch),
			})
		}
	}
	if err := reportGenerator.Do(w, progs); err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
		return
	}
	runtime.GC()
}

// SvCoverInfo : record single SvCover
type SvCoverInfo struct {
	SvNo         uint32
	SvName       string
	SvFieldName  string
	SvRangeValue int32
	SvInstPc     uint32
	RwType       uint8
}

func (mgr *Manager) svCoverToCover(sign signal.SvSerial) []SvCoverInfo {
	svs := make([]SvCoverInfo, 0, len(sign.Elems))
	var sv_range_no uint32
	var sv_range_value int32
	var sv_no uint32
	var sv_name string
	var sv_field_name string
	var pc uint32
	var svInstPc uint32
	var rwType uint8

	for _, svCov := range sign.Elems {
		svInstPc = uint32(svCov >> 32)
		pc = uint32(svCov & 0xffffffff)
		sv_range_no = pc & 0xffff
		sv_no = (pc >> 16) & 0x7fff
		rwType = uint8((pc >> 16) >> 15)
		sv_range_value = mgr.svRanges[sv_no][sv_range_no]
		sv_name = mgr.svName[sv_no]
		sv_field_name = mgr.svFieldName[sv_no]
		// log.Logf(0, "svCoverToCover: svCov: %x, sv_name %v, sv_no %x, sv_range_no %x, sv_range_value %x", svCov, sv_name, sv_no, sv_range_no, sv_range_value)
		svs = append(svs, SvCoverInfo{
			SvNo:         sv_no,
			SvName:       sv_name,
			SvFieldName:  sv_field_name,
			SvRangeValue: sv_range_value,
			SvInstPc:     svInstPc,
			RwType:       rwType,
		})
	}
	return svs
}

func (mgr *Manager) httpInputSvCover(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	data := UIInputSvCoverData{}

	var svs []SvCoverInfo

	if sig := r.FormValue("input"); sig != "" {
		if inp, ok := mgr.corpus[sig]; ok {
			svs = mgr.svCoverToCover(inp.ProgSvCover)
		}
	}

	for _, sv := range svs {
		data.SvCovers = append(data.SvCovers, UIInputSvCoverType{
			SvNo:         sv.SvNo,
			SvName:       sv.SvName,
			SvFieldName:  sv.SvFieldName,
			SvRangeValue: sv.SvRangeValue,
			SvInstPc:     sv.SvInstPc,
			RwType:       sv.RwType,
		})
	}

	sort.Slice(data.SvCovers, func(i, j int) bool {
		a, b := data.SvCovers[i], data.SvCovers[j]
		if a.SvNo != b.SvNo {
			return a.SvNo < b.SvNo
		} else if a.SvInstPc != b.SvInstPc {
			return a.SvInstPc < b.SvInstPc
		}
		return a.SvRangeValue < b.SvRangeValue
	})

	if err := inputSvCoverTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpCoverFallback(w http.ResponseWriter, r *http.Request) {
	var maxSignal signal.Signal
	var maxSvSignal signal.Signal
	var maxSvCover signal.SvCover
	for _, inp := range mgr.corpus {
		maxSignal.Merge(inp.Signal.Deserialize())
		maxSvSignal.Merge(inp.SvSignal.Deserialize())
		maxSvCover.Merge(inp.SvCover.Deserialize())
	}
	calls := make(map[int][]int)
	for s := range maxSignal {
		id, errno := prog.DecodeFallbackSignal(uint32(s))
		calls[id] = append(calls[id], errno)
	}
	for d := range maxSvSignal {
		id, errno := prog.DecodeFallbackSignal(uint32(d))
		calls[id] = append(calls[id], errno)
	}
	for d := range maxSvCover {
		id, errno := prog.DecodeFallbackSignal(uint32(d))
		calls[id] = append(calls[id], errno)
	}
	data := &UIFallbackCoverData{}
	for _, id := range mgr.checkResult.EnabledCalls[mgr.cfg.Sandbox] {
		errnos := calls[id]
		sort.Ints(errnos)
		successful := 0
		for len(errnos) != 0 && errnos[0] == 0 {
			successful++
			errnos = errnos[1:]
		}
		data.Calls = append(data.Calls, UIFallbackCall{
			Name:       mgr.target.Syscalls[id].Name,
			Successful: successful,
			Errnos:     errnos,
		})
	}
	sort.Slice(data.Calls, func(i, j int) bool {
		return data.Calls[i].Name < data.Calls[j].Name
	})

	if err := fallbackCoverTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpPrio(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	callName := r.FormValue("call")
	call := mgr.target.SyscallMap[callName]
	if call == nil {
		http.Error(w, fmt.Sprintf("unknown call: %v", callName), http.StatusInternalServerError)
		return
	}

	var corpus []*prog.Prog
	for _, inp := range mgr.corpus {
		p, err := mgr.target.Deserialize(inp.Prog, prog.NonStrict)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to deserialize program: %v", err), http.StatusInternalServerError)
			return
		}
		corpus = append(corpus, p)
	}

	//prios := mgr.target.CalculatePriorities(corpus)
	res := mgr.target.CalcResourcePriorities()
	dep := mgr.target.CalcGlobalPriorities()
	static := mgr.target.Static
	dynamic := mgr.target.CalcDynamicPrio(corpus)
	prios := make([][]float32, len(mgr.target.Syscalls))
	for i := range prios {
		prios[i] = make([]float32, len(mgr.target.Syscalls))
	}
	for i, prio := range static {
		for j, p := range prio {
			prios[i][j] = p + dynamic[i][j]
		}
	}

	data := &UIPrioData{Call: callName}
	for i, p := range prios[call.ID] {
		// data.Prios = append(data.Prios, UIPrio{mgr.target.Syscalls[i].Name, p})
		data.Prios = append(data.Prios, UIPrio{
			Prio:        p,
			Call:        mgr.target.Syscalls[i].Name,
			PrioRes:     res[call.ID][i],
			PrioDep:     dep[call.ID][i],
			PrioStatic:  static[call.ID][i],
			PrioDynamic: dynamic[call.ID][i],
		})
	}
	sort.Slice(data.Prios, func(i, j int) bool {
		return data.Prios[i].Prio > data.Prios[j].Prio
	})

	if err := prioTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpFile(w http.ResponseWriter, r *http.Request) {
	file := filepath.Clean(r.FormValue("name"))
	if !strings.HasPrefix(file, "crashes/") && !strings.HasPrefix(file, "corpus/") {
		http.Error(w, "oh, oh, oh!", http.StatusInternalServerError)
		return
	}
	file = filepath.Join(mgr.cfg.Workdir, file)
	f, err := os.Open(file)
	if err != nil {
		http.Error(w, "failed to open the file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.Copy(w, f)
}

func (mgr *Manager) httpInput(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	inp, ok := mgr.corpus[r.FormValue("sig")]
	if !ok {
		http.Error(w, "can't find the input", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(inp.Prog)
}

func (mgr *Manager) httpReport(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	crashID := r.FormValue("id")
	desc, err := ioutil.ReadFile(filepath.Join(mgr.crashdir, crashID, "description"))
	if err != nil {
		http.Error(w, "failed to read description file", http.StatusInternalServerError)
		return
	}
	tag, _ := ioutil.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.tag"))
	prog, _ := ioutil.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.prog"))
	cprog, _ := ioutil.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.cprog"))
	rep, _ := ioutil.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.report"))

	commitDesc := ""
	if len(tag) != 0 {
		commitDesc = fmt.Sprintf(" on commit %s.", trimNewLines(tag))
	}
	fmt.Fprintf(w, "Syzkaller hit '%s' bug%s.\n\n", trimNewLines(desc), commitDesc)
	if len(rep) != 0 {
		fmt.Fprintf(w, "%s\n\n", rep)
	}
	if len(prog) == 0 && len(cprog) == 0 {
		fmt.Fprintf(w, "The bug is not reproducible.\n")
	} else {
		fmt.Fprintf(w, "Syzkaller reproducer:\n%s\n\n", prog)
		if len(cprog) != 0 {
			fmt.Fprintf(w, "C reproducer:\n%s\n\n", cprog)
		}
	}
}

func (mgr *Manager) httpRawCover(w http.ResponseWriter, r *http.Request) {
	// Note: initCover is executed without mgr.mu because it takes very long time
	// (but it only reads config and it protected by initCoverOnce).
	if err := initCover(mgr.cfg.KernelObj, mgr.sysTarget.KernelObject, mgr.cfg.KernelSrc,
		mgr.cfg.KernelBuildSrc, mgr.cfg.TargetArch, mgr.cfg.TargetOS); err != nil {
		http.Error(w, initCoverError.Error(), http.StatusInternalServerError)
		return
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	var pcCov cover.PcCover
	// var svCov cover.SvCover
	for _, inp := range mgr.corpus {
		pcCov.Merge(inp.PcCover)
		//	svCov.Merge(inp.SvCover)
	}
	covArray := make([]uint32, 0, len(pcCov))
	for pc := range pcCov {
		covArray = append(covArray, pc)
	}
	pcs := coverToPCs(covArray, mgr.cfg.TargetVMArch)
	sort.Slice(pcs, func(i, j int) bool {
		return pcs[i] < pcs[j]
	})

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	buf := bufio.NewWriter(w)
	for _, pc := range pcs {
		fmt.Fprintf(buf, "0x%x\n", pc)
	}
	buf.Flush()
}

func (mgr *Manager) httpTotalSvCover(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	data := UITotalSvCoverData{}

	for k, cnt := range mgr.totalSvCover {
		data.TotalSvCovers = append(data.TotalSvCovers, UITotalSvCoverType{
			SvCover: k,
			HitTime: cnt,
		})
	}

	sort.Slice(data.TotalSvCovers, func(i, j int) bool {
		a, b := data.TotalSvCovers[i], data.TotalSvCovers[j]
		return a.SvCover < b.SvCover
	})

	if err := totalSvCoverTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpTotalSvSignal(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	data := UITotalSvSignalData{}

	for k, cnt := range mgr.totalSvSignal {
		data.TotalSvSignals = append(data.TotalSvSignals, UITotalSvSignalType{
			SvSignal: k,
			HitTime:  cnt,
		})
	}

	sort.Slice(data.TotalSvSignals, func(i, j int) bool {
		a, b := data.TotalSvSignals[i], data.TotalSvSignals[j]
		return a.SvSignal < b.SvSignal
	})

	if err := totalSvSignalTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) collectCrashes(workdir string) ([]*UICrashType, error) {
	// Note: mu is not locked here.
	reproReply := make(chan map[string]bool)
	mgr.reproRequest <- reproReply
	repros := <-reproReply

	crashdir := filepath.Join(workdir, "crashes")
	dirs, err := osutil.ListDir(crashdir)
	if err != nil {
		return nil, err
	}
	var crashTypes []*UICrashType
	for _, dir := range dirs {
		crash := readCrash(workdir, dir, repros, mgr.startTime, false)
		if crash != nil {
			crashTypes = append(crashTypes, crash)
		}
	}
	sort.Slice(crashTypes, func(i, j int) bool {
		return strings.ToLower(crashTypes[i].Description) < strings.ToLower(crashTypes[j].Description)
	})
	return crashTypes, nil
}

func readCrash(workdir, dir string, repros map[string]bool, start time.Time, full bool) *UICrashType {
	if len(dir) != 40 {
		return nil
	}
	crashdir := filepath.Join(workdir, "crashes")
	descFile, err := os.Open(filepath.Join(crashdir, dir, "description"))
	if err != nil {
		return nil
	}
	defer descFile.Close()
	descBytes, err := ioutil.ReadAll(descFile)
	if err != nil || len(descBytes) == 0 {
		return nil
	}
	desc := string(trimNewLines(descBytes))
	stat, err := descFile.Stat()
	if err != nil {
		return nil
	}
	modTime := stat.ModTime()
	descFile.Close()

	files, err := osutil.ListDir(filepath.Join(crashdir, dir))
	if err != nil {
		return nil
	}
	var crashes []*UICrash
	reproAttempts := 0
	hasRepro, hasCRepro := false, false
	reports := make(map[string]bool)
	for _, f := range files {
		if strings.HasPrefix(f, "log") {
			index, err := strconv.ParseUint(f[3:], 10, 64)
			if err == nil {
				crashes = append(crashes, &UICrash{
					Index: int(index),
				})
			}
		} else if strings.HasPrefix(f, "report") {
			reports[f] = true
		} else if f == "repro.prog" {
			hasRepro = true
		} else if f == "repro.cprog" {
			hasCRepro = true
		} else if f == "repro.report" {
		} else if f == "repro0" || f == "repro1" || f == "repro2" {
			reproAttempts++
		}
	}

	if full {
		for _, crash := range crashes {
			index := strconv.Itoa(crash.Index)
			crash.Log = filepath.Join("crashes", dir, "log"+index)
			if stat, err := os.Stat(filepath.Join(workdir, crash.Log)); err == nil {
				crash.Time = stat.ModTime()
				crash.Active = crash.Time.After(start)
			}
			tag, _ := ioutil.ReadFile(filepath.Join(crashdir, dir, "tag"+index))
			crash.Tag = string(tag)
			reportFile := filepath.Join("crashes", dir, "report"+index)
			if osutil.IsExist(filepath.Join(workdir, reportFile)) {
				crash.Report = reportFile
			}
		}
		sort.Slice(crashes, func(i, j int) bool {
			return crashes[i].Time.After(crashes[j].Time)
		})
	}

	triaged := reproStatus(hasRepro, hasCRepro, repros[desc], reproAttempts >= maxReproAttempts)
	return &UICrashType{
		Description: desc,
		LastTime:    modTime,
		Active:      modTime.After(start),
		ID:          dir,
		Count:       len(crashes),
		Triaged:     triaged,
		Crashes:     crashes,
	}
}

func reproStatus(hasRepro, hasCRepro, reproducing, nonReproducible bool) string {
	status := ""
	if hasRepro {
		status = "has repro"
		if hasCRepro {
			status = "has C repro"
		}
	} else if reproducing {
		status = "reproducing"
	} else if nonReproducible {
		status = "non-reproducible"
	}
	return status
}

func trimNewLines(data []byte) []byte {
	for len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	return data
}

type UISummaryData struct {
	Name    string
	Stats   []UIStat
	Crashes []*UICrashType
	Log     string
}

type UISyscallsData struct {
	Name  string
	Calls []UICallType
}

type UISvCoverData struct {
	Name string
	SVs  []UISvCoverType
}

type UISvExtremumData struct {
	Name        string
	SvExtremums []UISvExtremumType
}

type UICrashType struct {
	Description string
	LastTime    time.Time
	Active      bool
	ID          string
	Count       int
	Triaged     string
	Crashes     []*UICrash
}

type UICrash struct {
	Index  int
	Time   time.Time
	Active bool
	Log    string
	Report string
	Tag    string
}

type UIStat struct {
	Name  string
	Value string
	Link  string
}

type UISvCoverType struct {
	SvNo        uint32
	SvName      string
	SvFieldName string
	HitNum      uint32
	AllNum      uint32
}

type UISvExtremumType struct {
	SvNo        uint32
	SvName      string
	SvFieldName string
	Max         int32
	Min         int32
	Update      int32
	MaxSig      string
	MinSig      string
}

type UIPerSvRangeData struct {
	Ranges []UIPerSvRangeType
}

type UIInputSvCoverData struct {
	SvCovers []UIInputSvCoverType
}

type UITotalSvCoverData struct {
	TotalSvCovers []UITotalSvCoverType
}

type UITotalSvSignalData struct {
	TotalSvSignals []UITotalSvSignalType
}

type UIHitPcMapType struct {
	SvInstPc uint32
	HitTime  uint64
}

type UIPerSvRangeType struct {
	// [sv_range_value] = hit_time
	Value    int32
	HitPcMap []UIHitPcMapType
}

type UIInputSvCoverType struct {
	SvNo         uint32
	SvName       string
	SvFieldName  string
	SvRangeValue int32
	SvInstPc     uint32
	RwType       uint8
}

type UITotalSvCoverType struct {
	SvCover uint64
	HitTime uint64
}

type UITotalSvSignalType struct {
	SvSignal uint32
	HitTime  uint64
}

type UICallType struct {
	Name    string
	Inputs  int
	PcCover int
	SvCover int
}

type UICorpus struct {
	Call   string
	Inputs []*UIInput
}

type UIInput struct {
	Sig            string
	Short          string
	PcCover        int
	SvCover        int
	TimeStamp      int64
	IsNewSvSeed    int8
	PathHash       uint32
	ParentSig      string
	Mutation       uint32
	Hinted         uint32
	PcCoverChanges uint32
	SvCoverChanges uint32
	SvPrio         int64
}

var summaryTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>{{.Name }} syzkaller</title>
	{{HEAD}}
</head>
<body>
<b>{{.Name }} syzkaller</b>
<br>

<table class="list_table">
	<caption>Stats:</caption>
	{{range $s := $.Stats}}
	<tr>
		<td class="stat_name">{{$s.Name}}</td>
		<td class="stat_value">
			{{if $s.Link}}
				<a href="{{$s.Link}}">{{$s.Value}}</a>
			{{else}}
				{{$s.Value}}
			{{end}}
		</td>
	</tr>
	{{end}}
</table>

<table class="list_table">
	<caption>Crashes:</caption>
	<tr>
		<th><a onclick="return sortTable(this, 'Description', textSort)" href="#">Description</a></th>
		<th><a onclick="return sortTable(this, 'Count', numSort)" href="#">Count</a></th>
		<th><a onclick="return sortTable(this, 'Last Time', textSort, true)" href="#">Last Time</a></th>
		<th><a onclick="return sortTable(this, 'Report', textSort)" href="#">Report</a></th>
	</tr>
	{{range $c := $.Crashes}}
	<tr>
		<td class="title"><a href="/crash?id={{$c.ID}}">{{$c.Description}}</a></td>
		<td class="stat {{if not $c.Active}}inactive{{end}}">{{$c.Count}}</td>
		<td class="time {{if not $c.Active}}inactive{{end}}">{{formatTime $c.LastTime}}</td>
		<td>
			{{if $c.Triaged}}
				<a href="/report?id={{$c.ID}}">{{$c.Triaged}}</a>
			{{end}}
		</td>
	</tr>
	{{end}}
</table>

<b>Log:</b>
<br>
<textarea id="log_textarea" readonly rows="20" wrap=off>
{{.Log}}
</textarea>
<script>
	var textarea = document.getElementById("log_textarea");
	textarea.scrollTop = textarea.scrollHeight;
</script>
</body></html>
`)

var syscallsTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>{{.Name }} syzkaller syscalls</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>Per-syscall coverage:</caption>
	<tr>
		<th><a onclick="return sortTable(this, 'Syscall', textSort)" href="#">Syscall</a></th>
		<th><a onclick="return sortTable(this, 'Inputs', numSort)" href="#">Inputs</a></th>
		<th><a onclick="return sortTable(this, 'Pc Coverage', numSort)" href="#">Pc Coverage</a></th>
		<th><a onclick="return sortTable(this, 'Sv Coverage', numSort)" href="#">Sv Coverage</a></th>
		<th>Prio</th>
	</tr>
	{{range $c := $.Calls}}
	<tr>
		<td>{{$c.Name}}</td>
		<td><a href='/corpus?call={{$c.Name}}'>{{$c.Inputs}}</a></td>
		<td><a href='/cover?call={{$c.Name}}'>{{$c.PcCover}}</a></td>
		<td>{{$c.SvCover}}</td>
		<td><a href='/prio?call={{$c.Name}}'>prio</a></td>
	</tr>
	{{end}}
</table>
</body></html>
`)

var crashTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>{{.Description}}</title>
	{{HEAD}}
</head>
<body>
<b>{{.Description}}</b>

{{if .Triaged}}
Report: <a href="/report?id={{.ID}}">{{.Triaged}}</a>
{{end}}

<table class="list_table">
	<tr>
		<th>#</th>
		<th>Log</th>
		<th>Report</th>
		<th>Time</th>
		<th>Tag</th>
	</tr>
	{{range $c := $.Crashes}}
	<tr>
		<td>{{$c.Index}}</td>
		<td><a href="/file?name={{$c.Log}}">log</a></td>
		<td>
			{{if $c.Report}}
				<a href="/file?name={{$c.Report}}">report</a></td>
			{{end}}
		</td>
		<td class="time {{if not $c.Active}}inactive{{end}}">{{formatTime $c.Time}}</td>
		<td class="tag {{if not $c.Active}}inactive{{end}}" title="{{$c.Tag}}">{{formatShortHash $c.Tag}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

var corpusTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>syzkaller corpus</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>Corpus{{if $.Call}} for {{$.Call}}{{end}}:</caption>
	<tr>
		<th>Sig</th>
		<th>IsNewSvSeed</th>
		<th>Pc Coverage</th>
		<th>Sv Coverage</th>
		<th>Program</th>
		<th>TimeStamp</th>
		<th>IsNewSvSeed</th>
		<th>PathHash</th>
		<th>ParentSig</th>
		<th>Mutation</th>
		<th>Hinted</th>
		<th>SvPrio</th>
		<th>PcCoverChanges</th>
		<th>SvCoverChanges</th>
	</tr>
	{{range $inp := $.Inputs}}
	<tr>
		<td>{{$inp.Sig}}</td>
		<td>{{$inp.IsNewSvSeed}}</td>
		<td><a href='/cover?input={{$inp.Sig}}'>{{$inp.PcCover}}</a></td>
		<td><a href="/inputsvcover?input={{$inp.Sig}}">{{$inp.SvCover}}</a></td>
		<td><a href="/input?sig={{$inp.Sig}}">{{$inp.Short}}</a></td>
		<td>{{$inp.TimeStamp}}</td>
		<td>{{$inp.IsNewSvSeed}}</td>
		<td>{{$inp.PathHash}}</td>
		<td>{{$inp.ParentSig}}</td>
		<td>{{$inp.Mutation}}</td>
		<td>{{$inp.Hinted}}</td>
		<td>{{$inp.SvPrio}}</td>
		<td>{{$inp.PcCoverChanges}}</td>
		<td>{{$inp.SvCoverChanges}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

var svCorpusTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>syzkaller sv corpus</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>Corpus{{if $.Call}} for {{$.Call}}{{end}}:</caption>
	<tr>
		<th>Pc Coverage</th>
		<th>Sv Coverage</th>
		<th>Program</th>
		<th>TimeStamp</th>
		<th>PathHash</th>
	</tr>
	{{range $inp := $.Inputs}}
	<tr>
		<td><a href='/cover?input={{$inp.Sig}}'>{{$inp.PcCover}}</a></td>
		<td><a href="/inputsvcover?input={{$inp.Sig}}">{{$inp.SvCover}}</a></td>
		<td><a href="/input?sig={{$inp.Sig}}">{{$inp.Short}}</a></td>
		<td>{{$inp.TimeStamp}}</a></td>
		<td>{{$inp.PathHash}}</a></td>
	</tr>
	{{end}}
</table>
</body></html>
`)

var svCoverTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>syzkaller sv coverage</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>state-variable coverage:</caption>
	<tr>
		<th><a onclick="return sortTable(this, 'Sv ID', numSort)" href="#">Sv ID</a></th>
		<th>Sv Name</th>
		<th>Sv Field Name</th>
		<th>Hit Ranges</th>
		<th>All Ranges</th>
	</tr>
	{{range $c := $.SVs}}
	<tr>
		<td>{{$c.SvNo}}</td>
		<td><a href='/persvcover?sv={{$c.SvNo}}'>{{$c.SvName}}</a></td>
		<td><a href='/persvcover?sv={{$c.SvNo}}'>{{$c.SvFieldName}}</a></td>
		<td>{{$c.HitNum}}</td>
		<td>{{$c.AllNum}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

var svCorpusCoverTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>syzkaller corpus sv coverage</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>state-variable coverage:</caption>
	<tr>
		<th><a onclick="return sortTable(this, 'Sv ID', numSort)" href="#">Sv ID</a></th>
		<th>Sv Name</th>
		<th>Sv Field Name</th>
		<th>Hit Ranges</th>
		<th>All Ranges</th>
	</tr>
	{{range $c := $.SVs}}
	<tr>
		<td>{{$c.SvNo}}</td>
		<td><a href='/persvcorpuscover?sv={{$c.SvNo}}'>{{$c.SvName}}</a></td>
		<td><a href='/persvcorpuscover?sv={{$c.SvNo}}'>{{$c.SvFieldName}}</a></td>
		<td>{{$c.HitNum}}</td>
		<td>{{$c.AllNum}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

var svExtremumTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>syzkaller sv extremums</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>state-variable coverage:</caption>
	<tr>
		<th><a onclick="return sortTable(this, 'Sv ID', numSort)" href="#">Sv ID</a></th>
		<th>Sv Name</th>
		<th>Sv Field Name</th>
		<th>Max</th>
		<th>Min</th>
		<th>MaxSig</th>
		<th>MinSig</th>
		<th>Update</th>
	</tr>
	{{range $c := $.SvExtremums}}
	<tr>
		<td>{{$c.SvNo}}</td>
		<td><a href='/persvcover?sv={{$c.SvNo}}'>{{$c.SvName}}</a></td>
		<td><a href='/persvcover?sv={{$c.SvNo}}'>{{$c.SvFieldName}}</a></td>
		<td>{{$c.Max}}</td>
		<td>{{$c.Min}}</td>
		<td>{{$c.MaxSig}}</td>
		<td>{{$c.MinSig}}</td>
		<td>{{$c.Update}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

var inputSvCoverTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>syzkaller sv coverage</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>Per-input state-variable coverage:</caption>
	<tr>
		<th>svName</th>
		<th>svFieldName</th>
		<th>svCover</th>
		<th>svInstPc</th>
		<th>RWType</th>
	</tr>
	{{range $c := $.SvCovers}}
	<tr>
		<td>{{$c.SvName}}</td>
		<td>{{$c.SvFieldName}}</td>
		<td>{{$c.SvRangeValue}}</td>
		<td>{{$c.SvInstPc}}</td>
		<td>{{$c.RwType}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

var totalSvCoverTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>syzkaller total sv coverage</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>total state-variable coverage:</caption>
	<tr>
		<th>SvCover</th>
		<th>HitTime</th>
	</tr>
	{{range $c := $.TotalSvCovers}}
	<tr>
		<td>{{$c.SvCover}}</td>
		<td>{{$c.HitTime}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

var totalSvSignalTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>syzkaller total sv signal</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>total state-variable signal:</caption>
	<tr>
		<th>SvSignal</th>
		<th>HitTime</th>
	</tr>
	{{range $c := $.TotalSvSignals}}
	<tr>
		<td>{{$c.SvSignal}}</td>
		<td>{{$c.HitTime}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

var perSvCoverTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>syzkaller sv coverage</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>Per-state-variable coverage:</caption>
	<tr>
		<th>Range Value</th>
		<th>Hit Time</th>
	</tr>
	{{range $c := $.Ranges}}
	<tr>
		<td>x <= {{$c.Value}}</td>
		<td>{{range $d := $c.HitPcMap}} | {{$d.SvInstPc}}:{{$d.HitTime}} {{end}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

type UIPrioData struct {
	Call  string
	Prios []UIPrio
}

type UIPrio struct {
	Call        string
	PrioRes     float32
	PrioDep     float32
	PrioStatic  float32
	PrioDynamic float32
	Prio        float32
}

var prioTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>syzkaller priorities</title>
	{{HEAD}}
</head>
<body>
<table class="list_table">
	<caption>Priorities for {{$.Call}}:</caption>
	<tr>
		<th><a onclick="return sortTable(this, 'Prio', floatSort)" href="#">Prio</a></th>
		<th><a onclick="return sortTable(this, 'Call', textSort)" href="#">Call</a></th>
		<th><a onclick="return sortTable(this, 'PrioRes', floatSort)" href="#">PrioRes</a></th>
		<th><a onclick="return sortTable(this, 'PrioDep', floatSort)" href="#">PrioDep</a></th>
		<th><a onclick="return sortTable(this, 'PrioStatic', floatSort)" href="#">PrioStatic</a></th>
		<th><a onclick="return sortTable(this, 'PrioDynamic', floatSort)" href="#">PrioDynamic</a></th>
	</tr>
	{{range $p := $.Prios}}
	<tr>
		<td>{{printf "%.4f" $p.Prio}}</td>
		<td><a href='/prio?call={{$p.Call}}'>{{$p.Call}}</a></td>
		<td>{{printf "%.4f" $p.PrioRes}}</td>
		<td>{{printf "%.4f" $p.PrioDep}}</td>
		<td>{{printf "%.4f" $p.PrioStatic}}</td>
		<td>{{printf "%.4f" $p.PrioDynamic}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

type UIFallbackCoverData struct {
	Calls []UIFallbackCall
}

type UIFallbackCall struct {
	Name       string
	Successful int
	Errnos     []int
}

var fallbackCoverTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>syzkaller coverage</title>
	{{HEAD}}
</head>
<body>
<table class="list_table">
	<tr>
		<th>Call</th>
		<th>Successful</th>
		<th>Errnos</th>
	</tr>
	{{range $c := $.Calls}}
	<tr>
		<td>{{$c.Name}}</td>
		<td>{{if $c.Successful}}{{$c.Successful}}{{end}}</td>
		<td>{{range $e := $c.Errnos}}{{$e}}&nbsp;{{end}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

