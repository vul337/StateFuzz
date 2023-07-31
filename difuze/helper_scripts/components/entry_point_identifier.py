from base_component import *
import os


class EntryPointIdentifier(Component):
    """
        This component tries to find entry point functions from provided bitcode file and hdr file list.
    """
    def __init__(self, value_dict):
        ep_finder_bin = None
        ep_config = None
        llvm_bc_out = None
        entry_point_out = None
        if 'llvm_bc_out' in value_dict:
            llvm_bc_out = value_dict['llvm_bc_out']
        if 'ep_finder_bin' in value_dict:
            ep_finder_bin = value_dict['ep_finder_bin']
        if 'hdr_file_list' in value_dict:
            ep_config = value_dict['hdr_file_list']
        if 'entry_point_out' in value_dict:
            entry_point_out = value_dict['entry_point_out']
        self.ep_finder_bin = ep_finder_bin
        self.ep_config_file = ep_config
        self.llvm_bc_out = llvm_bc_out
        self.entry_point_out = entry_point_out

    def setup(self):
        if not os.path.exists(self.llvm_bc_out) or not os.path.isdir(self.llvm_bc_out):
            return "Provided LLVM Bitcode directory:" + str(self.llvm_bc_out) + " does not exist."
        if not os.path.exists(self.ep_finder_bin):
            return "Provided ep finder bin path:" + str(self.ep_finder_bin) + " does not exist."
        if self.entry_point_out is None or os.path.isdir(self.entry_point_out):
            return "Provided entry point out file path:" + str(self.entry_point_out) + " is invalid."
        return None

    def perform(self):
        log_info("Running EntryPointIdentifier..")
        ret_val = _generate_entry_points(self.ep_finder_bin, self.llvm_bc_out, self.entry_point_out,
                                         entry_point_file=self.ep_config_file)
        if ret_val:
            log_success("Successfully generated all the possible entry points into file:", self.entry_point_out)
        else:
            log_error("EntryPointIdentifier failed.")
        return ret_val

    def get_name(self):
        return "EntryPointIdentifier"

    def is_critical(self):
        # Yes, this is critical.
        return True


BASE_FOLDER_NAME = "llvm_link_final"
FINAL_BC_FILE = "final_to_check.bc"


def _find_all_interesting_dirs(base_dir):
    to_ret = []
    check_p = os.path.join(base_dir, BASE_FOLDER_NAME)
    # add all bc files into to_process_files
    if os.path.exists(check_p):
        to_ret.append(check_p)
    else:
        to_ret.append(base_dir)
            
    for curr_dir in os.listdir(base_dir):
        curr_dir_fp = os.path.join(base_dir, curr_dir)
        if os.path.isdir(curr_dir_fp):
            child_dirs = _find_all_interesting_dirs(curr_dir_fp)
            to_ret.extend(child_dirs)
    return to_ret


def _process_entry_out(output_file, target_bc_file, analysis_funcs, out_cache, visited_funcs):
    fp = open(output_file, 'r')
    all_lines = fp.readlines()
    for curr_li in all_lines:
        curr_li = curr_li.strip()
        if curr_li:
            # match correct final bc file
            if len(curr_li.split(":")) >= 3:
                c_file_name = curr_li.split(":")[-1]
                idx = os.path.dirname(c_file_name).rfind("/drivers/")
                src_dir_name = os.path.dirname(c_file_name)[idx:]
                if BASE_FOLDER_NAME in output_file:
                    if not output_file.split('/' + BASE_FOLDER_NAME)[0].endswith(src_dir_name):
                        continue
                else:
                    idx = output_file.rfind("/")
                    if not output_file[:idx].endswith(src_dir_name):
                        continue
            if curr_li not in out_cache:
                out_cache.append(curr_li)
                target_suffix = ''
                func_name = curr_li.split(':')[1]
                if func_name not in visited_funcs:
                    visited_funcs[func_name] = 0
                else:
                    visited_funcs[func_name] = visited_funcs[func_name] + 1
                    target_suffix = '_' + str(visited_funcs[func_name])
                analysis_funcs.append(curr_li + ':' + func_name + target_suffix + '.txt' + ':' + target_bc_file)
    fp.close()


def _generate_entry_points(entry_point_bin, llvm_bin_out, out_analysis_script, entry_point_file=None):

    # got all interesting dirs
    interesting_dirs = _find_all_interesting_dirs(llvm_bin_out)
    if os.path.exists(entry_point_file):
        log_success("Entry point file present:" + entry_point_file)
    else:
        log_warning("No entry point file.")
    out_analysis_funcs = []
    out_analysis_cache = []
    visited_funcs = {}
    for curr_int_dir in interesting_dirs:
        final_bc_file = os.path.join(curr_int_dir, FINAL_BC_FILE)
        to_process_files = []
        # good we found our final bc file
        if os.path.exists(final_bc_file):
            to_process_files.append(final_bc_file)
        else:
            for curr_fi in os.listdir(curr_int_dir):
                curr_fi_fp = os.path.join(curr_int_dir, curr_fi)
                if os.path.isdir(curr_fi_fp) or not curr_fi.endswith(".llvm.bc"):
                    continue
                to_process_files.append(os.path.join(curr_int_dir, curr_fi))
        for curr_fi in to_process_files:
            log_info("EntryPointIdentifier Processing:" + curr_fi)
            entry_point_out = curr_fi + '.all_entries'
            if os.path.exists(entry_point_file):
                print "entry point cmd: ", entry_point_bin + ' ' + curr_fi + ' ' + entry_point_out + ' ' + ' > /dev/null 2>&1'
                os.system(entry_point_bin + ' ' + curr_fi + ' ' + entry_point_out + ' ' + ' > /dev/null 2>&1')
            else:
                print "entry point cmd: ", entry_point_bin + ' ' + curr_fi + ' ' + entry_point_out + ' > /dev/null 2>&1'
                os.system(entry_point_bin + ' ' + curr_fi + ' ' + entry_point_out + ' > /dev/null 2>&1')
            assert(os.path.exists(entry_point_out))
            _process_entry_out(entry_point_out, curr_fi, out_analysis_funcs, out_analysis_cache, visited_funcs)
    fp = open(out_analysis_script, "w")
    for curr_en in out_analysis_funcs:
        fp.write(curr_en + "\n")
    fp.close()
    return True
