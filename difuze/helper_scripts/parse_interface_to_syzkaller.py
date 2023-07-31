#-*-coding:utf-8-*-
import sys
import json
import os

# can not use sys_ioctl$ which causes "syscall sys_ioctl is unsupported on all arches" error

debug = 0
# todo: parse sys_read sys_write for syzkaller

printed_line = []
enable_syscalls = []
int_types = ["i8", "i16", "i32", "i64"]
entry_funcs = {}
# dev_cmd_type
ioctl_handled_tuples = []

def ir_to_sys(s):
    s = s.strip()
    if debug:
        print "[+] ir_to_sys: ", repr(s)
    if s[-1] == '*':
        isPtr = True
        return "ptr64[in, {s}]".format(s=ir_to_sys(s[:-1]))
    s = s.replace("%struct.", "").replace("%union.anon.", "union_anon_")
    s = s.replace("%union.", "")
    s = s.replace(".", "_").replace("-", "_")
    if s == "i8":
        s = "int8"
    elif s == "i16":
        s = "int16"
    elif s == "i32":
        s = "int32"
    elif s== "i64" or s == "double" or s == "float":
        s = "int64"
    if s[0] == "[" and s[-1] == "]" and " x " in s:
        s = s[1:-1]
        s_num = s.split(" x ")[0]
        s_type = s.split(" x ")[1].replace("i8", "int8").replace("i16", "int16").replace("i32", "int32").replace("i64", "int64")
        s = "array[{type}, {num}]".format(type=s_type, num=s_num)
        # s = s.replace("i8", "int8").replace("i16", "int16").replace("i32", "int32")
    if debug:
        print "[+] new ir_to_sys: ", s
    return s


def parse_file(curr_dir, curr_file, curr_out_dir):
    print "parsing: ", curr_file, "to :", curr_out_dir
    json_file_fd = open(os.path.join(curr_dir, curr_file), "rb")
    ep_name = curr_file[:-5]
    output_syz_file = os.path.join(curr_out_dir, ep_name + ".txt")
    output_syzconst_file = os.path.join(curr_out_dir, ep_name + "_arm64.const")
    print output_syz_file, output_syzconst_file
    output_syz_file_fd = open(output_syz_file, "wb")
    # output_syzconst_file_fd = open(output_syzconst_file, "wb")

    lines = json_file_fd.read().strip()
    difuze_output = json.loads(lines)
    printed_struct = {}

    # print difuze_output
    # print json.dumps(difuze_output, indent=4)
    if difuze_output["entry_point_name"] not in entry_funcs:
        return
    entry_type = entry_funcs[difuze_output["entry_point_name"]]
    device_name = difuze_output["device_name"]
    if device_name == "UNIDENTIFIED":
        return
    if device_name.startswith("/dev/"):
        device_name = device_name[5:]
    device_name_dir = device_name
    device_name = device_name.replace('/', '_').replace("%d","0").replace(":","_")
    commands = difuze_output["commands"]
    preprocessed_files = difuze_output["all_pre_processed_files"]

    # 去重
    new_commands = []
    for cmd in commands:
        if cmd not in new_commands:
            new_commands.append(cmd)
    commands = new_commands

    # print resource
    fd_device = "fd_{}".format(device_name.replace("-", "_"))
    if "resource {}[fd]".format(fd_device) not in printed_line:
        output_syz_file_fd.write("resource {}[fd]".format(fd_device) + "\n")
        printed_line.append("resource {}[fd]".format(fd_device))

    # print syz_open_dev
    if "syz_open_dev$dev_{}".format(device_name.replace("-", "_")) not in printed_line:
        output_syz_file_fd.write("syz_open_dev$dev_{}(dev ptr64[in, string[\"/dev/{}\"]], id intptr, flags flags[open_flags]) {}".format(device_name.replace("-", "_").replace("%d", "0"), device_name_dir, fd_device) + "\n")
        printed_line.append("syz_open_dev$dev_{}".format(device_name.replace("-", "_")))
        enable_syscalls.append("syz_open_dev$dev_{}".format(device_name.replace("-", "_")))
    
    # print close
    if "close$dev_{}".format(device_name.replace("-", "_")) not in printed_line:
        output_syz_file_fd.write("close$dev_{}(fd {})".format(device_name.replace("-", "_").replace("%d", "0"), fd_device) + "\n")
        printed_line.append("close$dev_{}".format(device_name.replace("-", "_")))
        enable_syscalls.append("close$dev_{}".format(device_name.replace("-", "_")))

    device_name = device_name.replace("-", "_")
    # print read/write
    if entry_type == "FileWrite":
        output_syz_file_fd.write("write$dev_{dev} (fd {fd}, buf buffer[in], count len[buf])".format(dev=device_name, fd=fd_device))
        printed_line.append("write$dev_{}".format(device_name.replace("-", "_")))
        enable_syscalls.append("write$dev_{}".format(device_name.replace("-", "_")))
        return
    if entry_type == "FileRead":
        output_syz_file_fd.write("read$dev_{dev} (fd {fd}, buf buffer[out], count len[buf])".format(dev=device_name, fd=fd_device))
        printed_line.append("read$dev_{}".format(device_name.replace("-", "_")))
        enable_syscalls.append("read$dev_{}".format(device_name.replace("-", "_")))
        return
    if entry_type == "DEVOPEN" or entry_type == "DEVRELEASE":
        return
    # print ioctl
    ioctl_cnt = 0
    for cmd in commands:
        cmd_info = cmd["cmd_info"]
        cmd_val = cmd_info["cmd_val"]
        possible_types = cmd_info["possible_types"]
        if debug:
            print device_name, cmd_val, possible_types
        if len(possible_types) == 0:
            ioctl_tuple = "ioctl$dev_{dev}_{cmd_val}".format(dev=device_name, cmd_val=str(int(cmd_val, 16)))
            if debug:
                print "ioctl_tuple: ", ioctl_tuple
            if ioctl_tuple in ioctl_handled_tuples:
                if debug:
                    print "[+] "  + ioctl_tuple + " in ioctl_handled_tuples, discard"
                continue
            else:
                if debug:
                    print "[+] ioctl_handled_tuples.append: ", ioctl_tuple
                ioctl_handled_tuples.append(ioctl_tuple)
            ioctl_call = "ioctl$dev_{dev}_{cmd_val}_{cmd_no}(fd {fd}, cmd const[{cmd_val}], tmp_arg)".format(dev=device_name, cmd_val=str(int(cmd_val, 16)), cmd_no=str(ioctl_cnt), fd=fd_device)
            # ioctl_call = "ioctl$dev_{dev}_{cmd_val}(fd {fd}, cmd const[{cmd_val}], tmp_arg)".format(dev=device_name, cmd_val=str(int(cmd_val, 16)), fd=fd_device)
            ioctl_call = ioctl_call.replace("tmp_arg", "arg ptr64[in, int64]")
            output_syz_file_fd.write(ioctl_call + "\n")
            if debug:
                print "enable_syscalls.append: {}".format(ioctl_call.split("(fd")[0].strip())
            enable_syscalls.append(ioctl_call.split("(fd")[0].strip())
            # print ioctl_call
            # output_syzconst_file_fd.write(ioctl_const + "\n")
            ioctl_cnt += 1
            ioctl_call = "ioctl$dev_{dev}_{cmd_val}_{cmd_no}(fd {fd}, cmd const[{cmd_val}], tmp_arg)".format(dev=device_name, cmd_val=str(int(cmd_val, 16)), cmd_no=str(ioctl_cnt), fd=fd_device)
            ioctl_call = ioctl_call.replace("tmp_arg", "arg intptr")
            output_syz_file_fd.write(ioctl_call + "\n")
            enable_syscalls.append(ioctl_call.split("(fd")[0].strip())
            ioctl_cnt += 1
            continue
        for i in xrange(len(possible_types)):
            ioctl_call = "ioctl$dev_{dev}_{cmd_val}_{cmd_no}(fd {fd}, cmd const[{cmd_val}], tmp_arg)".format(dev=device_name,cmd_val=str(int(cmd_val, 16)),cmd_no=str(ioctl_cnt), fd=fd_device)
            # ioctl_call = "ioctl$dev_{dev}_{cmd_val}(fd {fd}, cmd const[{cmd_val}], tmp_arg)".format(dev=device_name,cmd_val=str(int(cmd_val, 16)), fd=fd_device)
            # ioctl_const = "CMD_{cmd_no} = {cmd_val}".format(cmd_no=ioctl_cnt, cmd_val=int(cmd_val, 16))
            j = possible_types[i]["type_info"][0].strip()
            ioctl_tuple = "ioctl$dev_{dev}_{cmd_val}_{type}".format(dev=device_name, cmd_val=str(int(cmd_val, 16)), type=j)
            ioctl_tuple_min = "ioctl$dev_{dev}_{cmd_val}".format(dev=device_name, cmd_val=str(int(cmd_val, 16)))
            if ioctl_tuple in ioctl_handled_tuples:
                continue
            else:
                ioctl_handled_tuples.append(ioctl_tuple)
                ioctl_handled_tuples.append(ioctl_tuple_min)
            if j == "i8":
                ioctl_call = ioctl_call.replace("tmp_arg", "arg ptr64[in, int8]")
            elif j == "i16":
                ioctl_call = ioctl_call.replace("tmp_arg", "arg ptr64[in, int16]")
            elif j == "i32":
                ioctl_call = ioctl_call.replace("tmp_arg", "arg ptr64[in, int32]")
            elif j == "i64":
                ioctl_call = ioctl_call.replace("tmp_arg", "arg ptr64[in, int64]")

            # array ex: "type_info":["[32 x i8]"]
            elif j[0] == "[":
                t = j[1:-1]
                element_type = t.split(" x ")[1]
                element_type = ir_to_sys(element_type)
                element_num = t.split(" x ")[0]
                ioctl_call = ioctl_call.replace("tmp_arg", "arg ptr64[in, array[{element_type}, {element_num}]]".format(element_type=element_type,element_num=element_num))

            # union ex: "type_info":["union.anon.89:STARTELEMENTS:", "[16 x i8]", "union.anon.89:ENDELEMENTS:"]
            # union is not exist, and we ignore it
            # elif j[:5] == "union.":
            #     continue

            # struct ex: "type_info":["%struct.bug_entry = type { i32, i32, i16, i16 }"]
            # {"type_info":["%struct.context_hal_config = type <{ i32, %struct.context_config* }>"]}
            elif "%struct" in j or "%union" in j:
                s_name = j.split(" = ")[0].replace("%struct.", "").replace("%union.anon.", "union_anon_").replace("%union.", "").replace(".", "_")
                ioctl_call = ioctl_call.replace("tmp_arg", "arg ptr64[in, {struct_name}]".format(struct_name=s_name))
                # print struct_type recursively
                for s in possible_types[i]["type_info"]:
                    try:
                        if s in int_types:
                            continue
                        s_output = ""
                        s_name = s.split(" = ")[0].replace("%struct.", "")
                        s_name = s_name.replace("%union.anon.", "union_anon_")
                        s_name = s_name.replace("%union.", "")
                        s_name = s_name.replace(".", "_")
                        s_name = s_name.replace("-", "_")
                        s_elements_raw = s.split(" = ")[1]
                        s_type = ""
                        if s_name not in printed_struct:
                            if s_elements_raw.startswith("type <{"):
                                s_type = "packed"
                                s_elements = s_elements_raw.replace("type <{ ", "")[:-2].split(", ")
                            elif s_elements_raw.startswith("type {"):
                                s_elements = s_elements_raw.replace("type { ", "")[:-2].strip().split(", ")
                            s_output += "{s_name}".format(s_name=s_name) +  " {\n"
                            for e_no in xrange(len(s_elements)):
                                s_output += "	element_{e_no}	{e_name}\n".format(e_no=e_no, e_name=ir_to_sys(s_elements[e_no]))
                            s_output += "}"
                            if s_type == "packed":
                                s_output += " [packed]"
                            s_output += "\n"
                            printed_struct[s_name] = s_output
                    except Exception as e:
                        print "[!] parse error: ", s
                        print str(e)


            output_syz_file_fd.write(ioctl_call + "\n")
            if debug:
                print "enable_syscalls.append: {}".format(ioctl_call.split("(fd")[0].strip())
            enable_syscalls.append(ioctl_call.split("(fd")[0].strip())
            # print ioctl_call
            # output_syzconst_file_fd.write(ioctl_const + "\n")
            ioctl_cnt += 1

    for s in printed_struct:
        if s not in printed_line:
            output_syz_file_fd.write(printed_struct[s] + "\n")
            printed_line.append(s)

    # output_syz_file_fd.write("open_flags = O_RDWR")
    # output_syzconst_file_fd.write("O_RDWR = 2")

    # close fds
    json_file_fd.close()
    output_syz_file_fd.close()
    # output_syzconst_file_fd.close()


def usage():
    print "Invalid Usage."
    print "Run: python ", __file__, " <output_json_dir>", "<output_syzkaller_dir>", "<path/to/entry_point_out.txt>"
    sys.exit(-1)


def parse_all_files(curr_dir, curr_out_dir):
    for curr_f in os.listdir(curr_dir):
        if curr_f.endswith('.json'):
            ep_name = curr_f[:-5]
            if not os.path.isdir(curr_out_dir):
                os.makedirs(curr_out_dir)
            parse_file(curr_dir, curr_f, curr_out_dir)
    return


def main():
    if len(sys.argv) < 4:
        usage()

    entry_file = open(sys.argv[3], "rb")
    e_lines = entry_file.read().strip().split("\n")
    entry_file.close()
    for e_line in e_lines:
        items = e_line.split(":")
        entry_funcs[items[1]] = items[0]
    if debug:
        print entry_funcs

    output_json_dir = sys.argv[1]
    output_syzkaller_dir = sys.argv[2]

    if not os.path.exists(output_json_dir) and os.path.isdir(output_json_dir):
        print "Provided Ioctl finder json out folder:", output_json_dir, "does not exist."
        sys.exit(-2)

    if not os.path.exists(output_syzkaller_dir):
        os.makedirs(output_syzkaller_dir)

    parse_all_files(output_json_dir, output_syzkaller_dir)
    print "Finished processing all ioctl out files."

    enable_syscalls_out = "["
    for s in enable_syscalls:
        enable_syscalls_out += "\"{}\",".format(s)
    enable_syscalls_out += "]"
    print enable_syscalls_out


main()
