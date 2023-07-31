import sys
import json
import os


sv_list = []

def usage():
    print "python parse_svf_output.py /path/to/svf_find_sv_alias_out_dir"
    exit(0)


def _find_all_interesting_dirs(base_dir):
    to_ret = []
    check_p = os.path.join(base_dir, "llvm_link_final")
    if os.path.exists(check_p):
        to_ret.append(check_p)
    for curr_dir in os.listdir(base_dir):
        curr_dir_fp = os.path.join(base_dir, curr_dir)
        if os.path.isdir(curr_dir_fp):
            child_dirs = _find_all_interesting_dirs(curr_dir_fp)
            to_ret.extend(child_dirs)
    return to_ret


def load_sv():
    sv_f = open("/tmp/sv_list.txt", "rb")
    sv_lines = sv_f.read().strip().split("\n")
    sv_f.close()
    for sv_line in sv_lines:
        sv_list.append(sv_line.strip())
    return

def main():
    debug_mode = False
    if len(sys.argv) < 2:
        usage()
    if len(sys.argv) >= 3:
        if "DEBUG" == sys.argv[2]:
            debug_mode = True

    load_sv()
    input_file_dir = sys.argv[1]
    all_nodes = {}
    sv_alias = {}

    # got all interesting dirs
    # interesting_dirs = _find_all_interesting_dirs(input_file_dir)
    to_process_files = os.popen("find " + input_file_dir + " -name \"*.all_alias\"").read().strip().split("\n")
    for svf_out_file in to_process_files:
        input_file = open(svf_out_file, "rb")
        lines = input_file.read().strip().split("\n")
        input_file.close()
        nodeId = None
        method = ""
        nodeIds = []
        for line in lines:
            # print "current line:", line
            try:
                if line.startswith("======"):
                    continue
                if "pts{" in line:
                    nodeIds = []
                    raw_nodeIds = line.split("pts{")[1][:-2].split(" ")
                    for nodeId in raw_nodeIds:
                        nodeId = nodeId + "-" + svf_out_file
                        nodeIds.append(nodeId)
                    if "LDMU" in line:
                        method = "R"
                    elif "STCHI" in line:
                        method = "W"
                elif "[[" in line and "]]" in line:
                    loc = line.strip().split("[[")[1]
                    if loc.find("@[") != -1:
                        # It is inlined at somewhere, but I don't care where it is inlined at
                        delim = "@["
                    else:
                        # No inlined
                        delim = "]]"
                    source_loc = loc.split(delim)[0].strip() + ":" + method
                    ty = line[line.find("({") + 2:line.find("})")]
                    # ignore memfunction-alias {"memcpy", "memmove", "strcpy"};
                    if ty == "":
                        continue
                    if ty.startswith("var."):
                        ops = ty.rfind(".")
                        ty = "var" + ty[ops:]
                    if len(nodeIds) > 0:
                        # print "nodes: ", nodeIds
                        for nodeId in nodeIds:
                            if nodeId in all_nodes:
                                if all_nodes[nodeId]["type"].startswith("struct.") \
                                  or all_nodes[nodeId]["type"].startswith("var."):
                                    if source_loc not in all_nodes[nodeId]["loc"]:
                                        all_nodes[nodeId]["loc"].append(source_loc)
                                elif ty.startswith("struct.") \
                                  or ty.startswith("var."):
                                    all_nodes[nodeId]["type"] = ty
                                if ty not in all_nodes[nodeId]["alias_type"]:
                                    if ty.startswith("struct."):
                                        # no conflict yet
                                        if all_nodes[nodeId]["alias_type_conflict"] == False:
                                            for i in all_nodes[nodeId]["alias_type"]:
                                                # i!=ty, two types of struct
                                                if i.startswith("struct."):
                                                    all_nodes[nodeId]["alias_type_conflict"] = True
                                                    break
                                    all_nodes[nodeId]["alias_type"].append(ty)

                            else:
                                if ty.startswith("struct.") \
                                  or ty.startswith("var."):
                                    all_nodes[nodeId] = {}
                                    all_nodes[nodeId]["type"] = ty
                                    all_nodes[nodeId]["loc"] = []
                                    all_nodes[nodeId]["alias_type"] = []
                                    all_nodes[nodeId]["alias_type_conflict"] = False
                                    all_nodes[nodeId]["alias_type"].append(ty)
                                    all_nodes[nodeId]["loc"].append(source_loc)
                            # print nodeId, json.dumps(all_nodes[nodeId], indent=4)
                    else:
                        print "[!] NodeIDs is empty", line
                    nodeIds = []

            except Exception as e:
                print str(e)

    for nodeId in all_nodes:
        ty = all_nodes[nodeId]["type"]
        if ty.startswith("lvar.") or ty not in sv_list:
            continue
        # skip conflict node
        if ty.startswith("lvar.") or all_nodes[nodeId]["alias_type_conflict"]:
            continue
        if ty in sv_alias:
            for loc in all_nodes[nodeId]["loc"]:
                if loc not in sv_alias[ty]:
                    sv_alias[ty].append(loc)
        else:
            sv_alias[ty] = []
            sv_alias[ty] = all_nodes[nodeId]["loc"]

    # translate sv_alias to new format
    instrument_points = {}
    for sv in sv_alias:
        for pos in sv_alias[sv]:
            pos_parsed = pos.split(":")
            if len(pos_parsed) < 4:
                continue
            cfile = pos_parsed[0]
            line_no = pos_parsed[1]
            col_no = pos_parsed[2]
            rw = pos_parsed[3]
            if cfile not in instrument_points:
                instrument_points[cfile] = []
            inst_point = {}
            inst_point[pos.replace(cfile, "line")] = sv
            instrument_points[cfile].append(inst_point)            

    if debug_mode:
        print json.dumps(all_nodes, indent=4)
        print json.dumps(sv_alias, indent=4)
        print json.dumps(instrument_points, indent=4).replace("/root/zbd/toolchains/kernel/oneplus6-lzm/private/sdm845/", "").replace("/root/zbd/toolchains/kernel/linux-4.19.149/", "")
    else:
        print json.dumps(instrument_points).replace("/root/zbd/toolchains/kernel/oneplus6-lzm/private/sdm845/", "").replace("/root/zbd/toolchains/kernel/linux-4.19.149/", "")

main()
