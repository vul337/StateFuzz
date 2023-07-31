import sys
import os
from multiprocessing import Pool, cpu_count


BASE_FOLDER_NAME = "llvm_link_final"
FINAL_BC_FILE = "final_to_check.bc"


def usage():
    print "python svf_find_sv_alias.py /path/to/wpa /path/to/bc_out_dir"
    exit(0)


def log_info(*args):
    log_str = "[*] "
    for curr_a in args:
        log_str = log_str + " " + str(curr_a)
    print log_str


def _find_all_interesting_dirs(base_dir):
    to_ret = []
    check_p = os.path.join(base_dir, BASE_FOLDER_NAME)
    if os.path.exists(check_p):
        to_ret.append(check_p)
    for curr_dir in os.listdir(base_dir):
        curr_dir_fp = os.path.join(base_dir, curr_dir)
        if os.path.isdir(curr_dir_fp):
            child_dirs = _find_all_interesting_dirs(curr_dir_fp)
            to_ret.extend(child_dirs)
    return to_ret


def _do_generate_sv_alias(cmd):
    os.system(cmd)


def _generate_sv_alias(svf_wpa_bin, llvm_bin_out):

    # got all interesting dirs
    interesting_dirs = _find_all_interesting_dirs(llvm_bin_out)
    cmds = []
    for curr_int_dir in interesting_dirs:
        final_bc_file = os.path.join(curr_int_dir, FINAL_BC_FILE)
        to_process_files = []
        # good we found our final bc file
        if os.path.exists(final_bc_file):
            to_process_files.append(final_bc_file)
        else:
            for curr_fi in os.listdir(curr_int_dir):
                to_process_files.append(os.path.join(curr_int_dir, curr_fi))
        for curr_fi in to_process_files:
            log_info("SVF-WPA Processing:" + curr_fi)
            sv_alias_out = curr_fi + '.all_alias'
            # cmd = svf_wpa_bin + " -indCallLimit=100000 -dump-callgraph -ander -vgep -svfg -dump-mssa -dump-race "\
            #       + curr_fi + " > " + sv_alias_out + " 2>&1"
            cmd = svf_wpa_bin + " -indCallLimit=100000 -dump-callgraph -ander -svfg -dump-mssa -dump-race "\
                  + curr_fi + " > " + sv_alias_out + " 2>&1"
            cmds.append(cmd)
    if (cpu_count() > 48):
        cpu_num = cpu_count() - 16
    else:
        cpu_num = cpu_count()
    p = Pool(cpu_num)
    p.map(_do_generate_sv_alias, cmds)
    return


def _generate_sv_alias_nodifuze(svf_wpa_bin, llvm_bin_out):

    # got all interesting dirs
    to_process_files = os.popen("find " + llvm_bin_out + " -name \"*.llvm.bc\"").read().strip().split("\n")

    cmds = []
    for curr_fi in to_process_files:
        log_info("SVF-WPA Processing:" + curr_fi)
        sv_alias_out = curr_fi + '.all_alias'
        # cmd = svf_wpa_bin + " -indCallLimit=100000 -dump-callgraph -ander -vgep -svfg -dump-mssa -dump-race "\
        #       + curr_fi + " > " + sv_alias_out + " 2>&1"
        cmd = svf_wpa_bin + " -indCallLimit=100000 -dump-callgraph -ander -svfg -dump-mssa -dump-race "\
              + curr_fi + " > " + sv_alias_out + " 2>&1"
        cmds.append(cmd)
    if (cpu_count() > 48):
        cpu_num = cpu_count() - 16
    else:
        cpu_num = cpu_count()
    p = Pool(cpu_num)
    p.map(_do_generate_sv_alias, cmds)
    return


def main():
    if (len(sys.argv) < 3):
        usage()
    svf_wpa_bin = sys.argv[1]
    bc_out_dir = sys.argv[2]
    # _generate_sv_alias(svf_wpa_bin, bc_out_dir)
    _generate_sv_alias_nodifuze(svf_wpa_bin, bc_out_dir)


main()

