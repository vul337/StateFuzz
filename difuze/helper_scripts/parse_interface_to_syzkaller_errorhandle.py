#-*-coding:utf-8-*-
import sys
import os

'''
生成syzkaller测试用例
复制ioctlfined_syzkaller/里所有txt文件到syzkaller/sys/linux/


反复执行如下两条命令，直到没有错误报出



  make generate HOSTOS=linux HOSTARCH=amd64 TARGETOS=linux TARGETARCH=arm64 SOURCEDIR=/path/to/kernel_src_dir > parse_err.log;cat parse_err.log;


python err_handle.py parse_err.log /home/nopitydays/go/src/github.com/google/syzkaller/sys/linux /path/to/ioctlfinded-linux-4.19-syzkaller
'''

debug = 0
difuze_files = os.listdir(sys.argv[3])
if debug:
    print difuze_files

log_file = open(sys.argv[1], "rb")
syslinux_dir = sys.argv[2]
err_pair = {}
lines = log_file.read().split("\n")
for line in lines:
    if line.startswith("test.txt"):
        continue
    if ".txt" not in line:
        continue
    if len(line.split(":")) < 2:
        continue
    err_file_candidate = []
    ef_1 = line.split(" ")[0]
    ef_2 = line.split(" ")[-1]
    # if ".txt" in ef_2 and ef_1.split(":")[0] in difuze_files and \
    #   ef_2.split(":")[0] not in difuze_files:
    #     ef = ef_2
    # else:
    #     ef = ef_1
    ef = ef_1
    if debug:
        print "ef = {}".format(ef)
    err_file = ef.split(":")[0]
    err_line_no = int(ef.split(":")[1])
    if err_file not in err_pair:
        err_pair[err_file] = []
    if err_line_no not in err_pair[err_file]:
        err_pair[err_file].append(err_line_no - 1)

for err_file in err_pair:
    # print err_file, err_pair[err_file]
    try:
        f = open(syslinux_dir + "/" + err_file, "rb")
        f_lines = f.readlines()
        f.close()
        f = open(syslinux_dir + "/" + err_file, "wb")
        f_lines_num = len(f_lines)
        for i in xrange(f_lines_num):
            # print f_lines[i]
            # print err_pair[err_file]
            if i not in err_pair[err_file]:
                f.write(f_lines[i])
                if "syz_open" in f_lines[i] or "ioctl$" in f_lines[i]:
                    print f_lines[i]
            else:
                # print "[+] " + f_lines[i], i
                if not f_lines[i].strip():
                    continue
                if f_lines[i].strip()[-1] == '{':
                    # print 'xxxxxxxxxxxxx'
                    j = i
                    while j<len(f_lines) and f_lines[j].strip() != "}":
                        err_pair[err_file].append(j + 1)
                        j += 1
        f.close()
    except Exception, e:
        print str(e)
