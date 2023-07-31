import sys
import os
import csv


def main():
    csv_file_name = sys.argv[2]
    csv_file = open(csv_file_name, "rb")
    reader = csv.reader(csv_file)
    ioctl_findout_dir_name = sys.argv[1]
    # os.system("cp -r " + ioctl_findout_dir_name + " " + ioctl_findout_dir_name + "_bk")
    line_no = 0
    entry_dev_dict = {}
    # parse csv
    for line in reader:
        line_no += 1
        if line_no == 1:
            continue
        dev_name = line[1]
        # dev_name = line[1].replace("/dev/", "/")
        # dev_name = dev_name[1:].replace("/", "_")
        entry_name = line[0]
        # print dev_name, entry_name
        if entry_name not in entry_dev_dict:
            entry_dev_dict[entry_name] = []
            entry_dev_dict[entry_name].append(dev_name)
        else:
            if dev_name not in entry_dev_dict[entry_name]:
                entry_dev_dict[entry_name].append(dev_name)
    to_process_dirs = []
    to_process_dirs.append(ioctl_findout_dir_name)

    while True:
        if not len(to_process_dirs):
            break
        output_dir_name = to_process_dirs.pop()
        txt_files = os.listdir(output_dir_name)
        for txt_file_name in txt_files:
            fixed = False
            if not os.path.isdir(output_dir_name + "/" + txt_file_name):
                txt_file = open(output_dir_name + "/" + txt_file_name, "rb")
                content = txt_file.read()
                txt_file.close()
                # if "[+] Device Name: " in content:
                #     continue
                print txt_file_name
                content_lines = content.strip().split("\n")
                for l in content_lines:
                    if l.startswith("[+] Provided Function Name: "):
                        provided_fname = l.split("[+] Provided Function Name: ")[-1]
                        print "provided_fname: ", provided_fname
                        if provided_fname not in entry_dev_dict:
                            if provided_fname.endswith("_read"):
                                provided_fname = "_open".join(provided_fname.rsplit('_read', 1))
                            elif provided_fname.endswith("_write"):
                                provided_fname = "_open".join(provided_fname.rsplit('_write', 1))
                            elif provided_fname.endswith("_ioctl"):
                                provided_fname = "_open".join(provided_fname.rsplit('_ioctl', 1))
                            elif provided_fname.endswith("_release"):
                                provided_fname = "_open".join(provided_fname.rsplit('_release', 1))
                            elif provided_fname.endswith("_close"):
                                provided_fname = "_open".join(provided_fname.rsplit('_close', 1))
                            elif provided_fname.endswith("_mmap"):
                                provided_fname = "_open".join(provided_fname.rsplit('_mmap', 1))
                            elif provided_fname.endswith("_poll"):
                                provided_fname = "_open".join(provided_fname.rsplit('_poll', 1))
                        if provided_fname in entry_dev_dict:
                            newf_num = 0
                            for dev_name in entry_dev_dict[provided_fname]:
                                if dev_name in content:
                                    continue
                                content = content.replace("[+] Device Name: ", "[-] devname: ")
                                new_content = content.replace(l, l + "\n" + "[+] Device Name: " + dev_name)
                                newfile = open(output_dir_name + "/" + txt_file_name[:-4] + "_" + str(newf_num) + ".txt", "wb")
                                newfile.write(new_content + "\n")
                                newfile.close()
                                newf_num += 1
                        break
            else:
                to_process_dirs.append(output_dir_name + "/" + txt_file_name)

    csv_file.close()


main()
