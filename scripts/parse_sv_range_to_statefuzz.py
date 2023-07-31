'''
example of sv_ranges:
    "./drivers/connectivity/hi11xx/hi1103/bfgx/bfgx_dev.llvm.bc": {
        "sv": {
            "var.ir_only_mode": {
                "values": [
                    1,
                    0
                ],
                "var_type": "volatile _Bool"
            },
            "struct.sk_buff_head,0,2": {
                "values": [
                    0,
                    1
                ],
                "var_type": "unsigned int"
            }
        },
        "edge_num": 6
    },
    "./drivers/media/v4l2-core/v4l2-mc.llvm.bc": {
    ...
'''

import sys
import json
import re


debug = 0
u_type_set = ["__u32", "__u16", "__u8", "__u64", "unsigned char", "unsigned int", "unsigned short", "unsigned long"]
sv_pair_map = {}

def usage():
    help_text ='''[!] Usage: python parse_sv_range.py /path/to/sv_range.txt /path/to/sv_list.txt /path/to/sv_range.json /path/to/sv_range.json'''
    print help_text

def parse_sv_pairs(line):
    line = line.replace("[+] sv_in_one_check:", "").strip()
    lids = line.split(";")
    for lid in lids:
        lid = lid.strip()
        if lid == "" or lid not in sv_pair_map:
            continue
        for lid2 in lids:
            lid2 = lid2.strip()
            if lid2 == "" or lid2 not in sv_pair_map:
                continue
            if sv_pair_map[lid2]["id"] not in sv_pair_map[lid]["values"]:
                sv_pair_map[lid]["values"].append(sv_pair_map[lid2]["id"])

def main():
    if len(sys.argv) < 3:
        usage()
        exit(-1)

    svs = {}
    sv_ranges_field_name = {}
    sv_f = open(sys.argv[2], "rb")
    sv_field_name_f = open(sys.argv[2]+"_field_name", "rb")
    lines = sv_f.read().strip().split("\n")
    for var_name in lines:
        if var_name.startswith("var."):
            sv_ranges_field_name[var_name] = var_name
    field_name_lines = sv_field_name_f.read().strip().split("\n")
    num = 0

    #
    # parse RecordDecl output
    #
    for line in field_name_lines:
        if "Something error in" in line:
            continue
        sv_name = line.split(" --- ")[0]
        sv_field_name = line.split(" --- ")[1].strip()
        if sv_name in svs:
            print "[!] dup line: " + line
            exit(-1)
        svs[sv_name] = {}
        svs[sv_name]["id"] = num
        svs[sv_name]["values"] = []
        svs[sv_name]["fieldname"] = sv_field_name
        sv_pair_map[sv_name] = {}
        sv_pair_map[sv_name]["id"] = num
        sv_pair_map[sv_name]["name"] = sv_name
        sv_pair_map[sv_name]["values"] = []

        num += 1
        # print line, num
    sv_f.close()

    max_min_set = [2147483647, 18446744073709551615, 4294967295, 2147483647, -2147483648, 9223372036854775807, -9223372036854775808, 536870912, -536870912, 65535]
    MAXINT = 2147483647
    MININT = -2147483648

    #
    # parse sv_range.txt
    #
    f = open(sys.argv[1], "rb")
    lines_seen = set() # holds lines already seen
    lines = f.read().strip().split("\n")
    f.close()
    sv_ranges = {}
    vul_structs = []
    incorrect_svs = []
    sv_cfiles = {}
    candidate_sv_ranges = {}
    # get range1 and range2 from "[range1], [range2]"
    current_filename = ""
    reg = re.compile('\[[\-0-9]*, [\-0-9]*\]', re.S)
    field_name = ""
    for line in lines:
        if "Something error in" in line:
            continue
        if "sym_ranges :  {  }" in line:
            continue
        if " [+] sv_in_one_check:" in line:
            parse_sv_pairs(line)
            continue
        # if "[+] FieldName" in line:
        if line.startswith("[+] Sv Name: ") and " FieldName: " in line:
            # field_name = line.split(": ")[-1]
            sv_name = line.replace("[+] Sv Name: ", "").split(" FieldName: ")[0]
            field_name = line.split(" FieldName: ")[1].split(" FieldType: ")[0]
            sv_ranges_field_name[sv_name] = field_name
            continue
        if not line.startswith("sym_name") and not line.startswith("[+] Sv Name: "):
            current_filename = line.replace(".sv_range", "").replace(".llvm.bc", ".c")
            lines_seen.clear()
            if current_filename not in sv_ranges:
                sv_ranges[current_filename] = {}
                sv_ranges[current_filename]["sv"] = {}
            continue
        if line not in lines_seen:
            lines_seen.add(line)
            if debug:
                print line
            try:
                var_name = line.split(" ")[1]
                var_type = line.split("sym_ranges :  { ")[0].split("sym_name: ")[1].replace(var_name, "").strip()
                ranges = re.findall(reg, line.split("sym_ranges :  { ")[1][:-2])
            except Exception as e:
                sys.stderr.write(str(e) + "\n")
                continue

            if var_name not in sv_cfiles:
                sv_cfiles[var_name] = []
                sv_cfiles[var_name].append(current_filename)
            elif current_filename not in sv_cfiles[var_name]:
                sv_cfiles[var_name].append(current_filename)

            for r in ranges:
                # remove '[' ']'
                nums = r[1:-1].split(", ")
                for n in nums:
                    num = int(n)
                    if num > MAXINT:
                        num = MAXINT
                    elif num < MININT:
                        num = MININT
                    if num in max_min_set:
                        continue
                    if var_name not in sv_ranges[current_filename]["sv"]:
                        sv_ranges[current_filename]["sv"][var_name] = {}
                        if var_name in sv_ranges_field_name and var_name in svs:
                            if not sv_ranges_field_name[var_name].startswith("var.") and \
                              sv_ranges_field_name[var_name] not in svs[var_name]["fieldname"] and svs[var_name]["fieldname"] != "":
                                # we can sure it is incorrect
                                st = var_name.split(",")[0]
                                if st not in vul_structs:
                                    vul_structs.append(st)
                                if var_name not in incorrect_svs:
                                    incorrect_svs.append(var_name)
                                if debug:
                                    print "[!] {} fieldname not match!: IR: {} vs AST: {}".format(var_name, svs[var_name]["fieldname"], sv_ranges_field_name[var_name])
                        sv_ranges[current_filename]["sv"][var_name]["values"] = []
                        sv_ranges[current_filename]["sv"][var_name]["var_type"] = var_type
                        # if num != 0 or var_type not in u_type_set:
                        sv_ranges[current_filename]["sv"][var_name]["values"].append(num)
                        if var_name not in candidate_sv_ranges:
                            candidate_sv_ranges[var_name] = {}
                            candidate_sv_ranges[var_name]["values"] = []
                        if num not in candidate_sv_ranges[var_name]["values"]:
                            candidate_sv_ranges[var_name]["values"].append(num)
                    elif num not in sv_ranges[current_filename]["sv"][var_name]["values"]:
                        # if num != 0 or var_type not in u_type_set:
                        sv_ranges[current_filename]["sv"][var_name]["values"].append(num)
                        if var_name not in candidate_sv_ranges:
                            candidate_sv_ranges[var_name] = {}
                            candidate_sv_ranges[var_name]["values"] = []
                        if num not in candidate_sv_ranges[var_name]["values"]:
                            candidate_sv_ranges[var_name]["values"].append(num)
                    # else:
                    #     if debug:
                    #         print sv_ranges[current_filename]["sv"][var_name]["values"]
                    #         print "duplicate: num {} for var_name {}".format(num, var_name)

    #
    # correct offset of state-variables according to fieldname from IR
    # sort by id
    #
    corrected = []
    if debug:
        print "sv_ranges_field_name: ", sv_ranges_field_name
        print "candidate_sv_ranges len: ", len(candidate_sv_ranges)
        print "candidate_sv_ranges : ", candidate_sv_ranges
        print "possible offset-incorrect structs (size:{}): ".format(len(vul_structs)), vul_structs
    for var_name in sv_ranges_field_name:
        # no sv ranges, useless
        if var_name not in candidate_sv_ranges or len(candidate_sv_ranges[var_name]["values"]) == 0:
            if debug:
                print "# no sv ranges, useless, var_name:", var_name
            continue
        # correct offsets, do nothing
        if var_name.startswith("var."):
            svs[var_name]["values"] = candidate_sv_ranges[var_name]["values"]
            if debug:
                print "# correct offsets, do nothing, var_name:", var_name
            continue
        # correct offsets, do nothing
        if var_name in svs and sv_ranges_field_name[var_name] in svs[var_name]["fieldname"]:
            svs[var_name]["values"] = candidate_sv_ranges[var_name]["values"]
            if debug:
                print "# correct offsets, do nothing, var_name:", var_name
            continue
        # no suspicion in this struct
        if var_name.split(",")[0] not in vul_structs:
            if debug:
                print "# no suspicion in this struct, var_name:", var_name
            continue
        #
        # incorrect offsets
        #
        # print "[+] {} fieldname not match!: IR: {} vs AST: {}".format(var_name, svs[var_name]["fieldname"], sv_ranges_field_name[var_name])
        
        # if "arrayidx" in svs[var_name]["fieldname"] or svs[var_name]["fieldname"] == "":
        #     continue
        st_name = var_name.split(",")[0]
        # traverse
        for i in svs:
            if "arrayidx" in svs[i]["fieldname"] or svs[i]["fieldname"] == "":
                continue
            if sv_ranges_field_name[var_name] in svs[i]["fieldname"]:
                if debug:
                    print "[+] found matched {} for {}. fieldname: {} - {}".format(i, var_name, svs[i]["fieldname"], sv_ranges_field_name[var_name])
                st_name_i = i.split(",")[0]
                # additional check about structure names
                if st_name == st_name_i:
                    # correct offset found.
                    if len(svs[i]["values"]) == 0:
                        svs[i]["values"] = candidate_sv_ranges[var_name]["values"]
                        if debug:
                            print "{} is corrected with {}".format(var_name, i)
                        corrected.append(var_name)
                    else:
                        print "[!] {} sv: {} is used for correcting more than once.".format(var_name, i)
                        continue
                    break

    if debug:
        print "svs len: ", len(svs)
        for i in incorrect_svs:
            if i not in corrected and len(candidate_sv_ranges[i]["values"]):
                print "{} not be corrected yet".format(i)

    svs_sorted = sorted(svs.items(), lambda x, y: cmp(x[1]["id"], y[1]["id"]))
    if debug:
        print json.dumps(svs_sorted, indent=4)


    #
    # dump everything
    #
    MAXINT = 2147483647
    res = []
    for item in svs_sorted:
        # if len(item[1]["values"]) == 0:
        #     continue
        tmp = {}
        tmp["id"] = item[1]["id"]
        tmp["name"] = item[0]
        tmp["values"] = []
        tmp["fieldname"] = item[1]["fieldname"]
        for value in item[1]["values"]:
            tmp["values"].append(value)
        if MAXINT not in tmp["values"]:
            tmp["values"].append(MAXINT)
        # avoid noise
        if len(tmp["values"]) > 20:
            tmp["values"] = []
            tmp["values"].append(MAXINT)
        # if MAXINT not in tmp["values"]:
        #     tmp["values"].append(MAXINT)
        # if len(tmp["values"]) == 1:
        #     tmp["values"].append(-1)
        #     tmp["values"].append(0)
        #     tmp["values"].append(1)
        tmp["values"].sort()
        res.append(tmp)
        # s = "{id} {length}".format(id=item[1]["id"], length=len(item[1]["values"]))
        # for value in item[1]["values"]:
        #     s += " " + str(value)
        # print s
    # print json.dumps(res, indent=4)
    sv_range_outfile = open(sys.argv[3], "wb")
    json.dump(res, sv_range_outfile)
    sv_range_outfile.close()


    sv_pairs = []
    for i in sv_pair_map:
        if len(sv_pair_map[i]["values"]) > 0:
            sv_pairs.append(sv_pair_map[i])

    sv_pairs_outfile = open(sys.argv[4], "wb")
    json.dump(sv_pairs, sv_pairs_outfile)
    sv_pairs_outfile.close()


main()
