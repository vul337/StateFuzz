#include <llvm/Pass.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Operator.h>
#include <llvm/IR/TypeFinder.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/CFG.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/StringMap.h>

#include "StateVariableAnalysis.h"
#include "CallGraph.h"
#include "Annotation.h"

using namespace llvm;
using namespace std;

#define DALog llvm::errs()
// #define DEBUG 1

extern stringsetMap CallMap;
extern std::map<std::string, int> myCallerCountMap;
extern std::map<std::string, int> myCalleeCountMap;
extern std::map<std::string, std::string> idValueMap;
extern stringsetMap sys_calleemap;
extern strset sys_calleeset;
extern stringsetMap sysLIdMap; 
extern stringsetMap sysSIdMap;
extern std::map<std::string, IdInstMap> sysLInstMap;
extern std::map<std::string, IdInstMap> sysSInstMap;
extern std::string syscaller;
extern stringsetMap depmap;
extern strset LIdset;
extern strset SIdset;
extern std::vector<std::pair<std::string, int>> call_stack;
extern strset sysfunc;
extern stringsetMap LIdMap; 
extern stringsetMap SIdMap;
extern std::map<std::string, IdInstMap> LInstMap;
extern std::map<std::string, IdInstMap> SInstMap;
extern strset SvCandidates;
extern strset SuspicionSvCandidates;
extern int SvConditionBranches;
extern strset globalSIdSet;

extern std::set<std::string> sv_black_list = {"struct.rb_node,0,0","struct.kuid_t,0,0","struct.trace_event_raw_ion_dma_map_cmo_class,0,1","struct.trace_event_raw_ion_dma_map_cmo_class,0,2","struct.drm_prime_attachment,0,1","struct.task_struct,0,161","struct.timespec,0,1","struct.sigset_t,0,0","struct.task_struct,0,1","struct.task_struct,0,4","struct.ion_buffer,0,8","struct.task_struct,0,54","struct.pgprot_t,0,0","struct.file,0,7","struct.ion_dma_buf_attachment,0,3","struct.timespec,0,0","struct.scatterlist,0,1","struct.scatterlist,0,0","struct.scatterlist,0,3","struct.scatterlist,0,2","struct.scatterlist,0,4","struct.trace_event_data_offsets_ion_dma_map_cmo_class,0,0","struct.trace_event_data_offsets_ion_dma_map_cmo_class,0,1","struct.trace_event_data_offsets_ion_access_cmo_class,0,0","struct.trace_event_data_offsets_ion_access_cmo_class,0,1","var._file_table.llvm.get_empty_filp.old_max","struct.vb2_vmalloc_attachment,0,1","struct.scm_desc,0,1","struct.scm_desc,0,0","struct.sg_table,0,2","struct.sg_table,0,1","struct.msm_iommu_map,0,9","struct.msm_iommu_map,0,8","struct.msm_iommu_map,0,4","struct.mempool_s,0,2","struct.arch_spinlock_t,0,0","struct.arch_spinlock_t,0,1","struct.dma_buf,0,0","struct._q6asm.llvm.anon,0,3","struct.apr_hdr,0,9","struct.timeval,0,0","struct.dentry,0,0","struct.inode,0,13","struct.inode,0,11","struct.wait_queue_entry,0,0","struct.dma_buf_attachment,0,4","struct.trace_event_raw_ion_access_cmo_class,0,1","struct.trace_event_raw_ion_access_cmo_class,0,2","struct.inode,0,0","struct.inode,0,1","struct.inode,0,4","struct.qstr,0,0,0,0","struct.qstr,0,0,0,1","struct.file,0,8","struct.page,0,5","struct.kgid_t,0,0","struct.seqcount,0,0","struct.address_space,0,12","struct.msm_iommu_map,0,5","struct.rb_node,0,1","struct.rb_node,0,2","struct.rb_root,0,0","struct.work_struct,0,2","struct.drm_prime_attachment,0,0","struct.ion_buffer,0,9","struct.msm_iommu_meta,0,4","struct.address_space,0,0","struct.address_space,0,9","struct.file,0,2","struct.file,0,3","struct.device,0,9","struct.msm_gem_object,0,7","struct.msm_gem_object,0,8","struct.file,0,16","struct.file,0,19","struct.path,0,1","struct.qstr,0,1","struct.sg_table,0,0","struct.device,0,16","struct.msm_iommu_map,0,3","struct.msm_iommu_map,0,2","struct.mempool_s,0,3","struct.dma_buf,0,3","struct.dma_buf,0,13","struct.dma_buf,0,12","struct.ab_dram_dma_buf_attachment,0,1","struct.dentry,0,8","struct.dentry,0,9","struct.dentry,0,5","struct.dentry,0,3","struct.dma_buf_attachment,0,3","struct.dma_buf_attachment,0,0","struct.dma_buf_attachment,0,1","struct.ion_dma_buf_attachment,0,1","struct.ion_dma_buf_attachment,0,0","struct.inode,0,8","struct.inode,0,9","struct.dentry,0,11","struct.timespec64,0,0","struct.timespec64,0,1"};
std::set<std::string> sv_black_list_funs = {"acpi_register_gsi","readl","readq","writel","__fput","___bpf_prog_run","kref_put_mutex","kref_put_lock","send_cmd_from_kernel","kthread","mutex_unlock","mutex_lock_nested","_raw_spin_unlock_irq","_raw_spin_lock_irq","trace_add_disk_randomness","trace_add_input_randomness","trace_call_function_entry","trace_call_function_exit","trace_call_function_single_entry","trace_call_function_single_exit","trace_cpu_frequency","trace_cpu_idle_rcuidle","trace_deferred_error_apic_entry","trace_deferred_error_apic_exit","trace_drm_vblank_event","trace_emulate_vsyscall","trace_error_apic_entry","trace_error_apic_exit","trace_finish_task_reaping","trace_irq_work_entry","trace_irq_work_exit","trace_kvm_ack_irq","trace_kvm_apic_ipi","trace_kvm_entry","trace_kvm_fast_mmio","trace_kvm_fpu","trace_kvm_hv_notify_acked_sint","trace_kvm_hv_stimer_callback","trace_kvm_hv_stimer_cleanup","trace_kvm_hv_synic_send_eoi","trace_kvm_hv_timer_state","trace_kvm_inj_virq","trace_kvm_ioapic_delayed_eoi_inj","trace_kvm_mmu_walker_error","trace_kvm_pml_full","trace_kvm_userspace_exit","trace_local_timer_entry","trace_local_timer_exit","trace_mark_victim","trace_mm_compaction_kcompactd_sleep","trace_mm_vmscan_direct_reclaim_end","trace_mm_vmscan_kswapd_sleep","trace_pm_qos_add_request","trace_pm_qos_remove_request","trace_pm_qos_update_request","trace_reschedule_entry","trace_reschedule_exit","trace_rtc_alarm_irq_enable","trace_rtc_irq_set_freq","trace_rtc_irq_set_state","trace_sched_kthread_stop_ret","trace_sched_wake_idle_without_ipi","trace_skip_task_reaping","trace_softirq_entry","trace_softirq_exit","trace_softirq_raise","trace_spurious_apic_entry","trace_spurious_apic_exit","trace_start_task_reaping","trace_svc_wake_up","trace_svcrdma_decode_short","trace_svcrdma_encode_pzr","trace_svcrdma_encode_read","trace_svcrdma_encode_reply","trace_svcrdma_encode_write","trace_svcrdma_err_chunk","trace_svcrdma_err_vers","trace_thermal_apic_entry","trace_thermal_apic_exit","trace_threshold_apic_entry","trace_threshold_apic_exit","trace_tick_stop","trace_ucsi_notify","trace_vector_reserve","trace_vector_reserve_managed","trace_wake_reaper","trace_wil6210_irq_misc","trace_wil6210_irq_misc_thread","trace_wil6210_irq_pseudo","trace_wil6210_irq_rx","trace_wil6210_irq_tx","trace_writeback_congestion_wait","trace_writeback_pages_written","trace_writeback_wait_iff_congested","trace_x86_platform_ipi_entry","trace_x86_platform_ipi_exit","trace_rtc_irq_set_freq","trace_rtc_alarm_irq_enable","trace_rseq_update","trace_rtc_set_offset"};

void printTypeRecursive(Type *targetType, bool first, std::vector<std::string> &tyVec) {
    bool hasStructElement;

    hasStructElement = false;

    std::string type_str;
    llvm::raw_string_ostream rso(type_str);
    targetType->print(rso);
    std::vector<std::string>::iterator tyVec_iter;
    tyVec_iter = std::find(tyVec.begin(), tyVec.end(), rso.str());
    if ( tyVec_iter != tyVec.end()) {
#ifdef DEBUG
        DALog << "Dup when handleTypeRecursive for type " << rso.str() << "\n";
#endif
        return;
    } else {
#ifdef DEBUG
        DALog << "handleTypeRecursive for type " << rso.str() << "\n";
#endif
    }
    if (!first && targetType->isPointerTy()) {
#ifdef DEBUG
        DALog << "!first && targetType->isPointerTy(), return\n";
#endif
      return;
    }
    if (targetType->isPointerTy()) {
#ifdef DEBUG
        DALog << "strip pointer\n";
#endif
        printTypeRecursive(targetType->getContainedType(0), true, tyVec);
    }
    if(targetType->isStructTy()) {
        StructType * STy = dyn_cast<StructType>(targetType);
        if (STy == nullptr || (STy->isLiteral()) || !(STy->hasName()) || targetType->getStructName().empty()) {
#ifdef DEBUG
                DALog << "STy == nullptr || !(STy->isLiteral()) || !(STy->hasName()) || targetType->getStructName().empty()\n";
                DALog <<  (STy == nullptr) << " || " << (STy->isLiteral()) << " || " << !(STy->hasName()) << " || " << targetType->getStructName().empty() << "\n";
#endif
            return;
        }
        string src_st_name = targetType->getStructName().str();
        if(src_st_name.find(".anon") != string::npos) {
            // OK, this is anonymous struct or union.
#ifdef DEBUG
            DALog << *targetType << "\n";
#endif
            for(unsigned int curr_no=0; curr_no<targetType->getStructNumElements(); curr_no++) {
                // print by adding space
#ifdef DEBUG
                DALog << "getStructNumElements: \n";
                DALog << *(targetType->getStructElementType(curr_no)) << "\n";
#endif
                printTypeRecursive(targetType->getStructElementType(curr_no), false, tyVec);
            }
        }
        else {
            // for regular structure, we also print it's elements' types recursively
#ifdef DEBUG
            DALog << *targetType << "\n";
#endif
            for(unsigned int curr_no=0; curr_no<targetType->getStructNumElements(); curr_no++) {
                // print by adding space
#ifdef DEBUG
                DALog << "getStructNumElements: \n";
                DALog << *(targetType->getStructElementType(curr_no)) << "\n";
#endif
                if (targetType->getStructElementType(curr_no)->isStructTy() || 
                  isa<ArrayType>(targetType->getStructElementType(curr_no))) {
                    hasStructElement = true;
                    break;
                }
            }
            if (hasStructElement)
            {
                for (unsigned int curr_no = 0;
                     curr_no < targetType->getStructNumElements();
                     curr_no++) {
                    // print by adding space
                    if (targetType->getStructElementType(curr_no)
                          ->isStructTy())
                        printTypeRecursive(targetType->getStructElementType(curr_no), false, tyVec);
                    else if (ArrayType *AT = dyn_cast<ArrayType>(targetType->getStructElementType(curr_no)))
                    {
#ifdef DEBUG
                        DALog << "ArrayType: " << *AT << "\n";
#endif
                        printTypeRecursive(targetType->getStructElementType(curr_no), false, tyVec);
                    }
                }
            }
        }
        // Regular structure, print normally.
#ifdef DEBUG
        DALog << *targetType << "\n";
#endif
        for (unsigned int curr_no = 0;
          curr_no < targetType->getStructNumElements(); curr_no++) {
            if (targetType->getStructElementType(curr_no)->isStructTy())
                continue;
            string SId;
            SId = src_st_name + ",0," + to_string(curr_no);
            if (sv_black_list.count(SId) != 0)
                continue;
            SIdset.insert(SId);
            if (idValueMap.count(SId) != 0)
                continue;
            idValueMap[SId] = "op_name_str";
            DALog << "[+] Found Id: " << SId << " | Load pointer value: unknown " << "| Type: " << *(targetType->getStructElementType(curr_no)) << "\n";
#ifdef DEBUG
            DALog << "SIdset length: " << SIdset.size() << "\n";
#endif
        }
#ifdef DEBUG
        DALog << "End memcpy call\n";
#endif        
        tyVec.push_back(rso.str());
    }
}

// dump accessed variables and structs for every function
void dumpIdMap() {
	ofstream LIdMapfile;
	LIdMapfile.open("./result/LIdMap.txt");
	LIdMapfile << LIdMap.size() << "\n";
	for (auto &l : LIdMap) {
		LIdMapfile << l.first << ":" << l.second.size() << "\n";
		for (auto &id : l.second)
			LIdMapfile << id << " ; ";
		LIdMapfile << "\n";
	}
	LIdMapfile.close();

	ofstream SIdMapfile;
	SIdMapfile.open("./result/SIdMap.txt");
	SIdMapfile << SIdMap.size() << "\n";
	for (auto &l : SIdMap) {
		SIdMapfile << l.first << ":" << l.second.size() << "\n";
		for (auto &id : l.second)
			SIdMapfile << id << " ; ";
		SIdMapfile << "\n";
	}
	SIdMapfile.close();
}


void erase_notsysfunc()
{
	sysfunc.erase("sys_ni_syscall");
  	sysfunc.erase("sys_copyarea");
	sysfunc.erase("sys_fillrect");
  	sysfunc.erase("sys_imageblit");
}

// dump syscall entry functions
void dumpsysfunc() {
	ofstream sysfuncfile;
  	sysfuncfile.open("./result/sysfunc.txt");
	sysfuncfile << sysfunc.size() << "\n";
	for (auto &f : sysfunc) {
		if (f.find("__x64_sys_") != f.npos || f.find("__x64_SyS_") != f.npos)
			sysfuncfile << f.substr(10, f.size() - 10) << "\n";
		else
			sysfuncfile << f.substr(4, f.size() - 4) << "\n";
	}
	sysfuncfile.close();
}

// dump callmap
void dumpCallMap() {
	ofstream CallMapfile;
	CallMapfile.open("./result/CallMap.txt");
	CallMapfile << CallMap.size() << "\n";
	for (auto &l : CallMap) {
		CallMapfile << l.first << ":" << l.second.size() << "\n";
		for (auto &id : l.second)
        {
			CallMapfile << id << " ; ";
        }
		CallMapfile << "\n";
	}
	CallMapfile.close();
}


// travel callgraph recursively
void circle_callee(std::string caller, int layer){
    // skip trace_event MACRO, may cause false negative (but rare)
#ifdef DEBUG
    DALog << "circle_callee for function: " << caller << "\n";
#endif
    if (caller.find("trace_")==0)
        return;
    if (layer > MAXCALLDEPTH) return;
    if(CallMap.count(caller) != 0){
        for(auto &f : CallMap[caller])
        {
#ifdef DEBUG
            DALog << "current callee: " << f << "\n";
#endif
            if (f.find("trace_")==0) {
#ifdef DEBUG
                DALog << "avoid noisy: trace_, return\n";
#endif
                continue;
            }
            if (CallMap.count(f) != 0 && CallMap[f].size() > MAXCALLEENUM) {
#ifdef DEBUG
                DALog << "avoid noisy MAXCALLEENUM, return\n";
#endif
                // avoid noisy
                continue;
            }
            if (sv_black_list_funs.count(f) != 0) {
#ifdef DEBUG
                DALog << "avoid noisy: sv_black_list_funs, return\n";
#endif
                continue;
            }
			if (sys_calleeset.count(f) == 0 && f != syscaller)
            {
#ifdef DEBUG
                DALog << "(sys_calleeset.count(f) == 0 && f != syscaller)\n";
#endif
                if (myCallerCountMap.count(f) == 0 || myCallerCountMap[f] < MAXREF)
                {
#ifdef DEBUG
                    DALog << "(myCallerCountMap.count(f) == 0 || myCallerCountMap[f] < MAXREF)\n";
#endif
                    if (myCalleeCountMap.count(f) == 0 || myCalleeCountMap[f] < MAXCALLNUM)
                    {
#ifdef DEBUG
                        DALog << "Caller:" << caller << "< MAXREF, insert Callee: " << f << ": ";
                        if (myCallerCountMap.count(f) != 0)
                            DALog << myCallerCountMap[f] <<"\n";
                        else
                            DALog << "\n";
                        DALog << "Caller:" << caller << "< MAXCALLNUM, insert Callee: " << f << ": ";
                        if (myCalleeCountMap.count(f) != 0)
                            DALog << myCalleeCountMap[f] <<"\n";
                        else
                            DALog << "\n";
#endif
				        sys_calleeset.insert(f);
                        call_stack.push_back({f, layer});
                        circle_callee(f, layer+1);
                    }
                }
#ifdef DEBUG
                else
                {
                    DALog << ">= MAXREF, not insert Callee: " << f << ": " << myCallerCountMap[f] << "\n";
                    DALog << ">= MAXCALLNUM, not insert Callee: " << f << ": " << myCalleeCountMap[f] << "\n";
                }
#endif
		    }
        }
	}
}

// tool function, just like str.split in python
std::vector<std::string> split(std::string str,std::string pattern)
{
    #ifdef DEBUG
        DALog << "spliting string: " << str << " with " << pattern << "\n";
    #endif

    std::string::size_type pos;
    std::vector<std::string> result;
    str+=pattern;//扩展字符串以方便操作
    int size=str.size();

    for(int i=0; i<size; i++)
    {
        pos=str.find(pattern,i);
        if(pos<size)
        {
            std::string s=str.substr(i,pos-i);
            result.push_back(s);
            i=pos+pattern.size()-1;
        }
    }
    return result;
}

// merge IdMap for every syscall
void createsysIdMap() {
  // load CallMap for ioctl
  ifstream ioctl_top_function_file;
  string line, s_name, top_funstr, lid_str, sid_str;
  std::vector<std::string> result;
  std::vector<std::string> sec_result;
  std::vector<std::string> trd_result;
  strset top_fun_set;
  strset lid_tmp_set, sid_tmp_set;
  stringsetMap sysInitSIdMap;
  stringsetMap sysInitLIdMap;

  sysInitLIdMap.clear();
  sysInitSIdMap.clear();

  // parse top level functions for interfaces
  ioctl_top_function_file.open("./result/ioctl_TopFunc.txt");
  if (!ioctl_top_function_file.is_open()) {
    // cout << "Error opening ioctl_top_function_file";
    exit(1);
  }
  while (!ioctl_top_function_file.eof()) {
      top_fun_set.clear();
      getline(ioctl_top_function_file, line);
      // ioctl$dev_tty1_22027 Top Level Functions: f ----- LIds: var.l ----- SIds:  var.vt_dont_switch
#ifdef DEBUG
          DALog << "getline: " << line << "\n";
#endif
      if (strstr(line.c_str(), "Top Level Functions:"))
      {
        result = split(line, " Top Level Functions: ");
        s_name = result[0];
        sysfunc.insert(s_name);
#ifdef DEBUG
            DALog << "get syscall name: " << s_name << "\n";
#endif
        sec_result = split(result[1], "----- LIds: ");
        top_funstr = sec_result[0];
        trd_result = split(sec_result[1], "----- SIds: ");
        lid_str = trd_result[0];
        sid_str = trd_result[1];
        lid_tmp_set.clear();
        sid_tmp_set.clear();
        if (top_funstr.length() > 0) {
            result = split(top_funstr, " ");
            for (int i = 0; i < result.size(); i++) {
              top_fun_set.insert(result[i]);
            }
            CallMap[s_name] = top_fun_set;
        }
        if (lid_str.length() > 0) {
            result = split(lid_str, "} {");
            for (int i = 0; i < result.size(); i++) {
              std::string full_lid_item_str = result[i];
              if (full_lid_item_str.find_first_of("{") != full_lid_item_str.npos)
                full_lid_item_str = full_lid_item_str.replace(full_lid_item_str.find_first_of("{"), 1, "");
              if (full_lid_item_str.find_last_of("}") != full_lid_item_str.npos)
                full_lid_item_str = full_lid_item_str.replace(full_lid_item_str.find_last_of("}"), 1, "");
              std::vector<std::string> r = split(full_lid_item_str, " | Load pointer value:");
              if (sv_black_list.count(r[0]) != 0)
                continue;
              DALog << "[+] Found Id: " << full_lid_item_str << "\n";
              lid_tmp_set.insert(r[0]);
            }
            if (sysInitLIdMap.count(s_name) != 0)
            {
                for (auto &lid : lid_tmp_set) {
                    if (sysInitLIdMap[s_name].count(lid) == 0)
                        sysInitLIdMap[s_name].insert(lid);
                }
            } else {
                sysInitLIdMap.insert({s_name, lid_tmp_set});
            }
        }
        if (sid_str.length() > 0) {
            result = split(sid_str, "} {");
            for (int i = 0; i < result.size(); i++) {
              std::string full_sid_item_str = result[i];
              if (full_sid_item_str.find_first_of("{") != full_sid_item_str.npos)
                full_sid_item_str = full_sid_item_str.replace(full_sid_item_str.find_first_of("{"), 1, "");
              if (full_sid_item_str.find_last_of("}") != full_sid_item_str.npos)
                full_sid_item_str = full_sid_item_str.replace(full_sid_item_str.find_last_of("}"), 1, "");
              std::vector<std::string> r = split(full_sid_item_str, " | Store pointer value:");
              if (sv_black_list.count(r[0]) != 0)
                continue;
              DALog << "[+] Found Id: " << full_sid_item_str << "\n";
              sid_tmp_set.insert(r[0]);
            }
            if (sysInitSIdMap.count(s_name) != 0)
            {
                for (auto &sid : sid_tmp_set) {
                    if (sysInitSIdMap[s_name].count(sid) == 0)
                        sysInitSIdMap[s_name].insert(sid);
                }
            } else {
                sysInitSIdMap.insert({s_name, sid_tmp_set});
            }
        }
      }
  }
  ioctl_top_function_file.close();

  // build sysIdMap
  for (auto &s : sysfunc){
	strset sysLIdset;
	strset sysSIdset;
    sysLIdset.clear();
    sysSIdset.clear();
    IdInstMap sysSIdInstMap;
    IdInstMap sysLIdInstMap;
    sysSIdInstMap.clear();
    sysLIdInstMap.clear();
    // construct the direct sysIdset
	if (LIdMap.count(s) != 0) { // ensure LIdMap has sysfunc s, then LIdMap[s] isn't empty
		sysLIdset = LIdMap[s];
        sysLIdInstMap = LInstMap[s];
    }
	if (SIdMap.count(s) != 0) { // ensure SIdMap has sysfunc s, then LIdMap[s] isn't empty
		sysSIdset = SIdMap[s];
        sysSIdInstMap = SInstMap[s];
    }

	// add callee's id
	if (CallMap.count(s) != 0) { // ensure sysfunc s has direct callee
		sys_calleeset = CallMap[s];
        for (auto &callee : CallMap[s]) {
            if ((myCallerCountMap.count(callee) != 0 && myCallerCountMap[callee] >= MAXREF) || callee == "send_cmd_from_kernel") {
            #ifdef DEBUG
                DALog << "erase >= MAXREF Callee: " << callee << ": " << myCallerCountMap[callee] << "\n";
            #endif
                sys_calleeset.erase(callee);
            }
            else if ((myCalleeCountMap.count(callee) != 0 && myCalleeCountMap[callee] >= MAXCALLNUM)) {
            #ifdef DEBUG
                DALog << "erase >= MAXCALLNUM Callee: " << callee << ": " << myCalleeCountMap[callee] << "\n";
            #endif
                sys_calleeset.erase(callee);
            }
        }
		syscaller = s;
		for (auto &callee : CallMap[s])
			if (callee != s) // delete callee that is same as caller
            {
                call_stack.clear();
                call_stack.push_back({callee, 1});
                circle_callee(callee, 1);
            #ifdef DEBUG
                DALog << "CallStack for Caller:" << s << "\n";
                for (auto &call_item : call_stack) {
                    for (int i=0; i<call_item.second; i++)
                        DALog << " ";
                    DALog << call_item.first << "\n";
                }
            #endif
            }
        sys_calleemap.insert({s, sys_calleeset});
		// construct sysLIdMap and sysSIdMap
		for(auto &f : sys_calleemap[s]){
			if (LIdMap.count(f) != 0){
                for(auto &Lid: LIdMap[f]) {
                    if (sv_black_list.count(Lid) != 0)
                        continue;
                    if(sysLIdset.insert(Lid).second)
                        sysLIdInstMap[Lid] = LInstMap[f][Lid];
                }
				// sysLIdset.insert(LIdMap[f].begin(), LIdMap[f].end());
                // sysLIdInstMap.insert(LInstMap[f].begin(), LInstMap[f].end());
            }
			if (SIdMap.count(f) != 0){
                for (auto &Sid : SIdMap[f]) {
                    if (sysSIdset.insert(Sid).second)
                        sysSIdInstMap[Sid] = SInstMap[f][Sid];
                }
                // sysSIdset.insert(SIdMap[f].begin(), SIdMap[f].end());
                // sysSIdInstMap.insert(SInstMap[f].begin(), SInstMap[f].end());
            }
		}
	}

    if (sysInitLIdMap.count(s) != 0) {
        for (auto &lid : sysInitLIdMap[s]) {
            if (sysLIdset.count(lid) == 0)
                sysLIdset.insert(lid);
        }
    }
	if (sysLIdset.size() > 0){
		sysLIdMap.insert({s, sysLIdset});
        sysLInstMap.insert({s, sysLIdInstMap});
    }

    if (sysInitSIdMap.count(s) != 0) {
        for (auto &sid : sysInitSIdMap[s]) {
            if (sysSIdset.count(sid) == 0)
                sysSIdset.insert(sid);
        }
    }
	if (sysSIdset.size() > 0){
		sysSIdMap.insert({s, sysSIdset});
        sysSInstMap.insert({s, sysSIdInstMap});
    }
  }
}

// dump callmap for every syscall
void dumpsyscallee() {
	ofstream syscalleefile;
	syscalleefile.open("./result/syscallee.txt");
	syscalleefile << sys_calleemap.size() << "\n";
	for (auto &l : sys_calleemap) {
		syscalleefile << l.first << ":" << l.second.size() << "\n";
		for (auto &id : l.second)
			syscalleefile << id << " ; ";
		syscalleefile << "\n";
	}
	syscalleefile.close();
}

void dumpsysIdMap() {
	ofstream sysLIdMapfile;
	sysLIdMapfile.open("./result/sysLIdMap.txt");
	sysLIdMapfile << sysLIdMap.size() << "\n";
	for (auto &l : sysLIdMap) {
		sysLIdMapfile << l.first << ":" << l.second.size() << "\n";
		for (auto &id : l.second)
			sysLIdMapfile << id << ";";
		sysLIdMapfile << "\n";
	}
	sysLIdMapfile.close();

	ofstream sysSIdMapfile;
	sysSIdMapfile.open("./result/sysSIdMap.txt");
	sysSIdMapfile << sysSIdMap.size() << "\n";
	for (auto &l : sysSIdMap) {
		sysSIdMapfile << l.first << ":" << l.second.size() << "\n";
		for (auto &id : l.second)
			sysSIdMapfile << id << ";";
		sysSIdMapfile << "\n";
	}
	sysSIdMapfile.close();
}

void sysIdCount() {
	map<string, int> sysLIdCountMap;
	for (auto &l : sysLIdMap)
		for (auto &id : l.second)
			if (sysLIdCountMap.count(id) == 0)
				sysLIdCountMap[id] = 1;
			else
				sysLIdCountMap[id]++;

	map<string, int> sysSIdCountMap;
	for (auto &l : sysSIdMap)
		for (auto &id : l.second)
			if (sysSIdCountMap.count(id) == 0)
				sysSIdCountMap[id] = 1;
			else
				sysSIdCountMap[id]++;

	ofstream sysIdCountfile;
	sysIdCountfile.open("./result/sysIdCount.txt");
	int structdep = 0;
	for (auto &l : sysLIdCountMap)
		if (sysSIdCountMap.count(l.first) != 0) {
			structdep++;
			sysIdCountfile << l.first << ":" << l.second << ":" << sysSIdCountMap[l.first] << "\n";
		}
	sysIdCountfile << structdep << "\n";
	sysIdCountfile.close();
}

void printsoureinfo(Instruction *Inst) {
  if (Inst == nullptr) {
      DALog << "[!] printsoureinfo a nullptr!\n";
      return;
  }
  if (DILocation *Loc = Inst->getDebugLoc()) { // Here I is an LLVM instruction
    unsigned Line = Loc->getLine();
    StringRef File = Loc->getFilename();
    StringRef Dir = Loc->getDirectory();
    // bool ImplicitCode = Loc->isImplicitCode();
    DALog << Dir << "/" << File << ": line " << Line << "\n";
  } else
    DALog << "NO MATCHED SOURCE INFO\n";
}

// map[Loadsyscall]set[Storesyscall]
// void createdepmap() {
//   for (const auto &lm : sysLIdMap){
// 	strset depset;
// 	for (auto &Lid : lm.second)
// 		for (const auto &sm : sysSIdMap)
// 			if (sm.second.count(Lid) != 0)
//             {
//                 DALog << "find dep: lm sm " << lm.first << " "<< sm.first <<  " LId-SId: " << Lid << "\n";
//             }
//     }
// }

void createdepmap() {
  for (const auto &lm : sysLIdMap){
	strset depset;
	for (auto &Lid : lm.second)
        for (const auto &sm : sysSIdMap)
            if (sm.second.count(Lid) != 0)
            {
                DALog << "find dep: lm sm " << lm.first << " "<< sm.first <<  " LId-SId: " << Lid << "\n";
#ifdef DEBUG
                // DALog << "LoadInst: " << *(sysLInstMap[lm.first][Lid]) << " source location: ";
                printsoureinfo(sysLInstMap[lm.first][Lid]);
                DALog << "StoreInst source location: ";
                printsoureinfo(sysSInstMap[sm.first][Lid]);
#endif
            }
    }
}

void dumpdepmap() {
  ofstream depfile;
  depfile.open("./result/depmap.txt");
  int sysc = 0;
  for (auto &deps :depmap) {
  	if (0)
		depfile << " \"" << deps.first << "\": \n[";
	else 
		depfile << " \"" << deps.first << "\":" << deps.second.size() << "\n[";
	int depc = 0;
	for (auto &dep : deps.second) {
		depc++;
		if (depc == 1)
			depfile << "\"" << dep << "\"";
		else 
			depfile << ", \"" << dep << "\"";
	}
	depfile << "]\n";
  }
  depfile.close();
}

void dumpdepjson() {
  ofstream dependency;
  dependency.open("./result/implicit_dependencies.json");
  dependency << "{";
  int sysc = 0;
  for (auto &deps :depmap) {
  	sysc++;
  	if (sysc == 1) {
  		dependency << "\"" << deps.first << "\": [";
  	}
	else {
		dependency << ", \"" << deps.first << "\": [";
	}
	int depc = 0;
	for (auto &dep : deps.second) {
		depc++;
		if (depc == 1) {
			dependency << "\"" << dep << "\"";
		}
		else {
			dependency << ", \"" << dep << "\"";
		}
	}
	dependency << "]";
  }
  dependency << "}";
  dependency.close();
}

// map[storesyscall]map[loadsyscall]int, int is the count of same struct
// dump real global_dependencies.json
void dumpdepcountjson() {
  map<string, map<string, int>> depcountmap;
  for (const auto &sm : sysSIdMap) {
  	map<string, int> structcountmap;
  	for (const auto &lm : sysLIdMap) {
		int count = 0;
		for (auto &Sid : sm.second)
			if (lm.second.count(Sid) != 0)
				count++;
		if (count > 0) {
            if (lm.first.find("__x64_sys_") == 0 || lm.first.find("__x64_SyS_") == 0)
			    structcountmap[lm.first.substr(10, lm.first.size() - 10)] = count;
            else if (lm.first.find("sys_") == 0 || lm.first.find("SyS_") == 0)
                structcountmap[lm.first.substr(4, lm.first.size() - 4)] = count;
            else
                structcountmap[lm.first] = count;
        }
	}
	if (structcountmap.size() > 0) {
        if (sm.first.find("__x64_sys_") == 0 || sm.first.find("__x64_SyS_") == 0)
            depcountmap.insert({sm.first.substr(10, sm.first.size() - 10), structcountmap});
        else if (sm.first.find("sys_") == 0 || sm.first.find("SyS_") == 0)
            depcountmap.insert({sm.first.substr(4, sm.first.size() - 4), structcountmap});
        else
            depcountmap.insert({sm.first, structcountmap});
    }
  }

  ofstream depcount;
  depcount.open("./result/depcount.json");
  depcount << "{";
  int sysc = 0;
  for (auto &deps : depcountmap) {
  	sysc++;
  	if (sysc == 1)
  		depcount << "\"" << deps.first << "\": {";
	else
		depcount << ", \"" << deps.first << "\": {";
	int depc = 0;
	for (auto &dep : deps.second) {
		depc++;
		if (depc == 1) 
			depcount << "\"" << dep.first << "\": " << dep.second;
		else 
			depcount << ", \"" << dep.first << "\": " << dep.second;
	}
	depcount << "}";
  }
  depcount << "}";
  depcount.close();
}

void dumpbcfile() {
  ofstream llbcfile;
  llbcfile.open("./result/llbcfile.txt");
  llbcfile << InputFilenames.size() << "\n";
  for (unsigned i = 0; i < InputFilenames.size(); ++i)
  	llbcfile << InputFilenames[i] << "'\n";
  llbcfile.close();
}


bool inCondition(llvm::Value *v, int level) {
    bool flag = false;
    if (level > 6)
        return false;
    for (Value::user_iterator it = v->user_begin(), ie = v->user_end();
                it != ie; ++it) {
        if (isa<ICmpInst>(*it)) {
            SvConditionBranches++;
            flag = true;
        }
        if (inCondition(*it, level+1))
            flag = true;
    }
    return flag;
}

void findSuspicionSvCandidates() {

    for (auto &s : sysSIdMap) {
        for (auto &sid : s.second) {
            if (globalSIdSet.count(sid) == 0)
                globalSIdSet.insert(sid);
        }
    }

    DALog << "start findSuspicionSvCandidates\n";
    DALog << "sysLIdMap.size: " << sysLIdMap.size() << " sysSIdMap.size: " << sysSIdMap.size() << "\n";
    for (auto &l : sysLIdMap) {
        for (auto &s : sysSIdMap) {
            if (l.first == s.first) {
                // DALog << " + " << l.first << " ==== " << s.first << "\n";
                for (auto &lid : l.second) {
                    // can be written
                    if (globalSIdSet.count(lid) == 0)
                        continue;
                    // DALog << "lid: " << lid << "\n";
                    // can not be written by this interface
                    if (s.second.count(lid) == 0) {
                        if (SuspicionSvCandidates.count(lid) == 0) 
                            SuspicionSvCandidates.insert(lid);
                    }
                }
                /*
                for (auto &sid : s.second) {
                    if (l.second.count(sid) == 0) {
                        if (SuspicionSvCandidates.count(sid) != 0)
                            SuspicionSvCandidates.insert(sid);
                    }
                }
                */
            }
        }
    }
}

bool LinuxSVA::runOnFunction(Function *F, GlobalVariable *G) {
    return false;
}

bool LinuxSVA::doModulePass(Module *M) {

    for (auto &F : *M) {
        for (auto &BB : F) {
            for (auto &I : BB) {
                if (StoreInst *S = dyn_cast<StoreInst>(&I)) {
	    			std::string SId = getStoreId(S);
                    if (
                      (SId[0]=='s'&&SId[1]=='t'&&SId[2]=='r'&&SId[3]=='u'&&SId[4]=='c'&&SId[5]=='t'&&SId[6]=='.')
                      || (SId[0]=='v'&&SId[1]=='a'&&SId[2]=='r'&&SId[3]=='.')
                    ) {
                        if (SuspicionSvCandidates.count(SId) == 0)
                            continue;
                        // DALog << "[ ] found SuspicionSvCandidates: " << (SId) << " " << (*S) << "\n";
                        if (inCondition(&I, 0)) {
                          if (SvCandidates.count(SId) == 0)
                            SvCandidates.insert(SId);
                        }
                    }
                } else if (LoadInst *L = dyn_cast<LoadInst>(&I)) {
                  std::string LId = getLoadId(L);
                  if ((LId[0]=='s'&&LId[1]=='t'&&LId[2]=='r'&&LId[3]=='u'&&LId[4]=='c'&&LId[5]=='t'&&LId[6]=='.')
                  || (LId[0]=='v'&&LId[1]=='a'&&LId[2]=='r'&&LId[3]=='.'))
	    		    {
                        if (SuspicionSvCandidates.count(LId) == 0)
                            continue;
                        // DALog << "[ ] found SuspicionSvCandidates: " << (LId) << " " << (*L) << "\n";
                        if (inCondition(&I, 0)) {
                            if (SvCandidates.count(LId) == 0) {
                              SvCandidates.insert(LId);
                            }
                        }
                    }
                }
            }
        }
    }
    return false;

}

bool LinuxSVA::doInitialization(Module *M) {
    return false;
}

bool LinuxSVA::doFinalization(Module *M) {
    return false;
}
