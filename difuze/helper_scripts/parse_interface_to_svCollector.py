#!/usr/bin/python
#-*- coding: UTF-8-*-
# handle difuze result, generate ioctl_TopFunc.txt for dep-analyzer
# parse all .txt file in difuze ioctl_finded dir with help of interface_manual.csv
# please make sure this file is the latest version (with "fix_difuze" function)

# can not use sys_ioctl$ which causes "syscall sys_ioctl is unsupported on all arches" error

import sys
import os
import re
import linecache
import json
import os.path

debug = 0

blacklist_functions = ["printk", "send_cmd_from_kernel", "llvm.dbg.value", "__arch_copy_to_user", "copy_from_user", "copy_overflow", "copy_to_user", "__arch_copy_from_user", "_raw_spin_lock_bh", "_raw_spin_unlock_bh", "__wake_up", "kfree", "__kmalloc", "__rcu_read_lock", "__rcu_read_unlock", "snprintf", "kcalloc", "kzalloc", "compat_ptr"]


def usage():
    print "Invalid Usage."
    print "Run: python ", __file__, " <ioctlfinded_output_dir>", " </path/to/entry_point_out.txt>"
    sys.exit(-1)


if len(sys.argv) != 3:
    usage()


entry_funcs = {}
entry_file = open(sys.argv[2], "rb")
e_lines = entry_file.read().strip().split("\n")
entry_file.close()
for e_line in e_lines:
    items = e_line.split(":")
    entry_funcs[items[1]] = items[0]
if debug:
    print entry_funcs


path = sys.argv[1] 
files= os.listdir(path)
top_function_dict = {}

for file in files:
    top_function = {}
    LIds = {}
    SIds = {}
    python2json = {}
    last_command = ""
    json_str = json.dumps(python2json)
    if not file.endswith(".txt"):
        continue
    if not os.path.isdir(path + "/" + file):
        f = open(path + "/" + file, "rb"); 
        iter_f = iter(f)
        # print file, ":"
        (filename,extension) = os.path.splitext(file)
        dict2json = {}
        dict2json["cmds"] = {}
        dict2json["Device Name"] = ""
        dict2json["Target"] = ""
        command_value = ""
        command_macro = ""
        cmd_val_stack = ["top_level_ioctl"]
        top_function["top_level_ioctl"] = []
        LIds["top_level_ioctl"] = []
        SIds["top_level_ioctl"] = []
        for line in iter_f:
            if debug:
                print "Current Line: " + line.strip()
            matchObj = re.search(r'\[\+\] Provided Function Name: ', line)
            if matchObj is not None:
                firstfunc = line.split(' ')
                if firstfunc:
                    # print firstfunc[-1].strip()
                    dict2json["Target"] = firstfunc[-1].strip()

            matchObj = re.search(r'Device Name: ', line)
            if matchObj is not None:
                # print "device name found: ", line
                devname = line.strip().split(' ')
                # print "Device Name:",devname[-1].strip()
                dict2json["Device Name"] = devname[-1].strip().replace("-", "_").replace("%d", "0")
                if dict2json["Device Name"].startswith("/dev/"):
                    dict2json["Device Name"] = dict2json["Device Name"][5:]
                dict2json["Device Name"] = dict2json["Device Name"].replace('/', '_')
                if debug:
                    print "Device Name:",devname[-1].strip()

            # matchObj = re.search(r'Starting Found Cmd :', line)
            # if matchObj is not None:
            if ("Found Cmd:" in line and line.strip().endswith(":START")) or ("Found Cmd(BR):" in line and line.strip().endswith(":START")):
                command_value = line.split(',')[0].split(':')[1]
                # print command_value,
                cmd_val_stack.append(command_value)
                if command_value not in top_function:
                    top_function[command_value] = []
                    LIds[command_value] = []
                    SIds[command_value] = []
              
            matchObj = re.search(r'Cmd In File:', line) 
            if matchObj is not None:
                secordfunc = line.split(':')
                file_path = secordfunc[1]
                linenumstr = secordfunc[3]
                line_number = int(linenumstr)
                try:
                    source_code_case = linecache.getline(file_path, line_number).strip()
                    case = re.split(' |:',source_code_case)
                    # print "ioctl$", case[1].strip(),"(" ,command_value,")",":",
                    with open(path+"/" + filename+'.const','a') as file_handle:
                        file_handle.write(case[1].strip()+" = "+command_value)
                        file_handle.write('\n') 
                    command_macro = case[1].strip()
                except:
                    # print "",
                    pass

            matchObj = re.search(r'function name:', line)
            if matchObj is not None:
                secordfunc = line.split(' ')
                if "send_cmd_from_kernel" not in secordfunc[-1] and \
                  secordfunc[-1] not in blacklist_functions:
                    fname = secordfunc[-1].strip().split(".")[0]
                    if debug:
                        print fname
                    if secordfunc[-1].strip() not in top_function[cmd_val_stack[-1]]:
                        if debug:
                            print "\n[+] {} top function: {}".format(cmd_val_stack[-1], fname)
                        top_function[cmd_val_stack[-1]].append(fname)
                        if fname not in top_function_dict:
                            top_function_dict[fname] = 1
                        else:
                            top_function_dict[fname] += 1
            
            matchObj = re.search(r'find LoadId: ', line)
            if matchObj is not None:
                LId = line.replace('find LoadId: ', "").strip()
                if not LId.startswith("{lvar"):
                    LId = re.sub("\\.[0-9]+", "", LId, 0)
                    if LId not in LIds[cmd_val_stack[-1]]:
                        if debug:
                            print "\n[+] {} LId: {}".format(cmd_val_stack[-1], LId)
                        LIds[cmd_val_stack[-1]].append(LId)
            
            matchObj = re.search(r'find StoreId: ', line)
            if matchObj is not None:
                SId = line.replace('find StoreId: ', "").strip()
                if not SId.startswith("{lvar"):
                    SId = re.sub("\\.[0-9]+", "", SId, 0)
                    if SId not in SIds[cmd_val_stack[-1]]:
                        if debug:
                            print "\n[+] {} SId: {}".format(cmd_val_stack[-1], SId)
                        SIds[cmd_val_stack[-1]].append(SId)

            # matchObj = re.search(r'Ended Found Cmd:', line)
            # if matchObj is not None:
            if ("Found Cmd:" in line and line.strip().endswith(":END")) or ("Found Cmd(BR):" in line and line.strip().endswith(":END")):
                command_value = line.split(',')[0].split(':')[1]
                if debug:
                    print "[+] Cmd {} End".format(command_value)
                    print top_function[command_value]
                if command_value is not "":
                    dict2json["cmds"][command_value] = {"Macro":command_macro.strip(),"Hex":command_value.strip(), "Top Function":top_function[command_value], "LIds":LIds[command_value], "SIds":SIds[command_value]} 
                    # print ""
                    poped_cmd = cmd_val_stack.pop()
                    if poped_cmd != command_value:
                        print "statck pop an error cmd_value:{}, expected: {}!".format(poped_cmd, command_value)
                if debug:
                    print dict2json["cmds"]
        if debug:        
            try:
                json_str = json.dumps(dict2json, indent=4)
            except:
                print "dumps error",
                json_str = ""
            print json_str
        if dict2json["Device Name"] == "":
                continue

        if dict2json["Target"] in entry_funcs:
            func_type = entry_funcs[dict2json["Target"]]
            if func_type == "FileWrite":
                output_line = "write$dev_{devname} Top Level Functions: {f} ----- LIds: ----- SIds: ".format(devname=dict2json["Device Name"], f=dict2json["Target"])
                print output_line
                continue
            elif func_type == "FileRead":
                output_line = "read$dev_{devname} Top Level Functions: {f} ----- LIds: ----- SIds: ".format(devname=dict2json["Device Name"], f=dict2json["Target"])
                print output_line
                continue
            elif func_type == "DEVOPEN":
                output_line = "syz_open_dev$dev_{devname} Top Level Functions: {f} ----- LIds: ----- SIds: ".format(devname=dict2json["Device Name"], f=dict2json["Target"])
                print output_line
                continue
            elif func_type == "DEVRELEASE":
                output_line = "close$dev_{devname} Top Level Functions: {f} ----- LIds: ----- SIds: ".format(devname=dict2json["Device Name"], f=dict2json["Target"])
                print output_line
                continue
            elif func_type == "DEVMMAP":
                output_line = "mmap$dev_{devname} Top Level Functions: {f} ----- LIds: ----- SIds: ".format(devname=dict2json["Device Name"], f=dict2json["Target"])
                print output_line
                continue
            elif func_type == "DEVPOLL":
                output_line = "poll$dev_{devname} Top Level Functions: {f} ----- LIds: ----- SIds: ".format(devname=dict2json["Device Name"], f=dict2json["Target"])
                print output_line
                continue


        for cmd in dict2json["cmds"]:
            item = dict2json["cmds"][cmd]
            if debug:
                print "for cmd in dict2json[\"{}\"]:".format(cmd)
                print item
            output_line = "ioctl$dev_{devname}_{cmd_val} Top Level Functions:".format(devname=dict2json["Device Name"], cmd_val=str(cmd))
            if len(item["Top Function"]) == 0 and len(item["LIds"]) == 0 and len(item["SIds"]) == 0:
                continue
            for f in item["Top Function"]:
                if top_function_dict[f] <= 20:
                    output_line = output_line + " " + f
            output_line = output_line + " " + "----- LIds:"
            for LId in item["LIds"]:
                output_line = output_line + " " + LId
            output_line = output_line + " " + "----- SIds:"
            if len(item["SIds"]) > 0:
                for SId in item["SIds"]:
                    output_line = output_line + " " + SId
            else:
                output_line = output_line + " "
            print output_line
        # print("\n------------------------------------------\n")


if debug:
    print "----------------possible noise: ------------------"
    for i in top_function_dict:
        if top_function_dict[i] > 20:
            print i, top_function_dict[i]
