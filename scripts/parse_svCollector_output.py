import sys
import argparse
import json
import re

debug = 0

p = re.compile("\\.[0-9]+([\\*|,|\\)|$])", re.VERBOSE) 

blacklist = ["struct.bvec_iter,0,0","struct.bvec_iter,0,1","struct.inode,0,23","struct.page,0,1,0,2","struct.page,0,1,0,3","struct.dm_ioctl,0,5","struct.word_at_a_time,0,0","struct.word_at_a_time,0,1","struct.blk_mq_tags,0,5","struct.timer_list,0,2","struct.radix_tree_node,0,3","struct.radix_tree_node,0,2","struct.radix_tree_root,0,1","struct.snd_seq_pool,0,1","struct.bio_list,0,1","struct.bio_list,0,0","struct.percpu_ref,0,1","struct.bio,0,1","struct.bio,0,0","struct.bio,0,2","struct.dev_pm_info,0,15","var._blk-mq.llvm.rcu_read_lock.__warned","struct.kobject,0,7"]

def usage():
    # print "python " + __file__ + " -i /path/to/result/log -o /path/to/sv_list.txt"
    parser.print_help()


def main():
    parser = argparse.ArgumentParser(description="Parse DepAnalyzer Output")
    parser.add_argument('--inputfilepath', '-i', type=str, default='result/test_file.txt',
                        help='The input file path.')
    parser.add_argument('--outputfilepath', '-o', type=str, default='/tmp/sv_list.txt',
                        help='The output file path')
    parser.add_argument('--sysLIdMapfilepath', '-s', type=str, default='',
                        help='The sysLIdMap file path')
    parser.add_argument('--svrangefilepath', '-r', type=str, default='/tmp/sv_range.json',
                        help='The sv_range.json file path')
    parser.add_argument('--printsource', action='store_true', default=False,
                        help='print the load/store source code location.')
    args = parser.parse_args()

    if len(sys.argv) < 3:
        print('The number of args must not < 3.')
        parser.print_help()
        exit(0)

    lines_seen = set() # holds lines already seen
    # f = open(sys.argv[1], "rb")
    # out_f = open(sys.argv[2], "wb")
    f = open(args.inputfilepath, "rb")
    out_f = open(args.outputfilepath, "wb")
    out_f_field_name = open(args.outputfilepath + "_field_name", "wb")
    lines = f.read().strip().split("\n")
    f.close()
    # filter some sv types like pointer
    # [+] Found Id: var._system_keyring.llvm.builtin_trusted_keys, Type: i32
    svs_type_dic = {}
    svs_field_name_dic = {}
    for line_raw in lines:
        if "[+] Found Id:" in line_raw:
            # print line_raw
            line = line_raw.replace("[+] Found Id: ", "")
            # sv_name = line.split(", Type: ")[0]
            if " | Load pointer value: " in line:
                sv_name = line.split(" | Load pointer value: ")[0]
                sv_field_name = line.split(" | Load pointer value: ")[1].split("| Type: ")[0].strip()
                sv_type = line.split("| Type: ")[1]
            elif " | Store pointer value: " in line:
                sv_name = line.split(" | Store pointer value: ")[0]
                sv_field_name = line.split(" | Store pointer value: ")[1].split("| Type: ")[0].strip()
                sv_type = line.split("| Type: ")[1]
            if sv_name not in svs_type_dic:
                svs_type_dic[sv_name] = sv_type
            if sv_name not in svs_field_name_dic:
                svs_field_name_dic[sv_name] = ""
            if svs_field_name_dic[sv_name] != "":
                continue
            if sv_field_name[1:].isdigit() \
                or " getelementptr inbounds " in sv_field_name \
                or "arrayinit" in sv_field_name or "arraydecay" in sv_field_name or "arrayidx" in sv_field_name \
                or sv_field_name == "" or sv_field_name == "unknown":
                continue
            svs_field_name_dic[sv_name] = sv_field_name

    count = 0
    sv_report_count = {}
    for line_raw in lines:
        if count > 0:
            line = line_raw.replace("Inst source location", " loc")
            if out_f not in blacklist:
                out_f.write(line + "\n")
            count -= 1
            continue
        if "lm sm" not in line_raw or "$" not in line_raw:
            continue
        line = line_raw.split("LId-SId: ")[-1]
        new_line = line
        if new_line not in sv_report_count:
            sv_report_count[new_line] = 0
        else:
            sv_report_count[new_line] += 1
        if new_line not in svs_type_dic:
            continue
        if svs_type_dic[new_line].endswith("*"):
            continue
        if line.startswith("lvar."):
            continue
        if line.startswith("var."):
            ops = line.rfind(".")
            new_line = "var" + line[ops:]
        new_line = p.sub(r"\1", new_line)
        if new_line not in lines_seen:  # not a duplicate
            lines_seen.add(new_line)
            if new_line not in blacklist:
                out_f.write(new_line + "\n")
                out_f_field_name.write(new_line + " --- " + svs_field_name_dic[line] + "\n")
            if args.printsource:
                count = 2

    svCandidates = []
    for line_raw in lines:
        if "svCandidate : " not in line_raw:
            continue
        new_line = line_raw.split("svCandidate : ")[-1]
        if svs_type_dic[new_line].endswith("*"):
            continue
        if new_line.startswith("var."):
            ops = new_line.rfind(".")
            new_line = "var" + new_line[ops:]
        if new_line not in svCandidates:  # not a duplicatei
            svCandidates.append(new_line)

    out_f.close()
    out_f_field_name.close()
    sv_black_list = ""
    if args.sysLIdMapfilepath == "":
        print sorted(sv_report_count.items(), key=lambda item: item[1])
    for i in sv_report_count:
        if sv_report_count[i] > 1550:
            sv_black_list += '"' + i + '",'
    if args.sysLIdMapfilepath == "":
        print sv_black_list
    # print len(svCandidates)
    # for i in svCandidates:
    #     print i

    if args.sysLIdMapfilepath == "":
        return
    
    svrange_f = open(args.svrangefilepath, "rb")
    my_json = json.loads(svrange_f.read())
    svrange_f.close()
    sv_map = {}
    for item in my_json:
        name = item["name"]
        sv_map[name] = {}
        sv_map[name]["name"] = item["name"]
        sv_map[name]["id"] = item["id"]
        sv_map[name]["values"] = []

    sysLIdMapf = open(args.sysLIdMapfilepath, "rb")
    sysLIdMap_lines = sysLIdMapf.read().strip().split("\n")
    # global_sv = [781]
    global_sv = []
    noise_var = {}
    for line in sysLIdMap_lines:
        if ";" not in line and ":" in line:
            continue
        lids = line.split(";")
        for lid in lids:
            if lid.startswith("var."):
                ops = lid.rfind(".")
                lid = "var" + lid[ops:]
            lid = p.sub(r"\1", lid)
            if lid not in noise_var:
                noise_var[lid] = 1
            else:
                noise_var[lid] += 1
    # noise_var_sorted = sorted(noise_var.items(), lambda x, y: cmp(x[1], y[1]))
    # print noise_var_sorted

    for line in sysLIdMap_lines:
        if ";" not in line and ":" in line:
            continue
        lids = line.split(";")
        # may be false positive
        if len(lids) > 1000:
            continue
        for lid in lids:
            if lid.startswith("var."):
                ops = lid.rfind(".")
                lid = "var" + lid[ops:]
            lid = p.sub(r"\1", lid)
            if lid == "" or lid not in sv_map or noise_var[lid] >= 60:
            # if lid == "" or lid not in sv_map:
                continue
            for lid2 in lids:
                if lid2.startswith("var."):
                    ops = lid2.rfind(".")
                    lid2 = "var" + lid2[ops:]
                lid2 = p.sub(r"\1", lid2)
                if lid2 == "" or lid2 not in sv_map:
                    if debug:
                        print "[!] lid2 == \"\" or lid2 not in sv_map: {}".format(lid2)
                    continue
                if sv_map[lid2]["id"] not in sv_map[lid]["values"]:
                    # sv_map[lid]["values"].append(lid2)
                    sv_map[lid]["values"].append(sv_map[lid2]["id"])
            for g in global_sv:
                if g not in sv_map[lid]["values"]:
                    sv_map[lid]["values"].append(g)

    sv_pairs = []
    for i in sv_map:
        if len(sv_map[i]["values"]) > 0:
            sv_pairs.append(sv_map[i])
            # print sv_map[i]["name"], len(sv_map[i]["values"])

    print json.dumps(sv_pairs)


main()
