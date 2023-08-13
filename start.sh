#!/bin/bash
export IMAGE="/home/fuzz/kernel/fs/"
sudo apt update && sudo apt install -y debootstrap qemu-system-x86-64
cd /home/fuzz/kernel/fs
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
chmod +x create-image.sh && ./create-image.sh
wget https://go.dev/dl/go1.20.6.linux-amd64.tar.gz -O /tmp/go1.20.6.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf /tmp/go1.20.6.linux-amd64.tar.gz
export PATH="$PATH:/usr/local/go/bin"

cd /home/fuzz/code/statefuzz
make HOSTOS=linux HOSTARCH=amd64 TARGETOS=linux TARGETARCH=amd64 SOURCEDIR=/home/fuzz/kernel/linux > parse_err.log;cat parse_err.log
sudo ./bin/syz-manager -config my.cfg 2>&1 | tee "$(date +"%Y_%m_%d").log"