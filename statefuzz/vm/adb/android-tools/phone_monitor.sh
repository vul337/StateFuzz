#!/bin/sh

# "adb" "-s" "99281FFAZ0051Y" "shell"

while true :
do
    if [ `tail -n 5 $1 | grep "failed to create instance" | wc -l` -gt 0 ] ; then
        if [ `tail -n 5 $1 | grep "failed to create instance" | grep "/data/syzkaller"| grep "99281FFAZ0051Y" | wc -l` -gt 0 ] ; then
            ps -ef | grep syz-manager | grep -v grep | awk '{print "kill -stop "$2}' | sh
            sleep 90
            adb -s "99281FFAZ0051Y" shell rm -rf /data/syzkaller*/*/*/cgroup*
            ps -ef | grep syz-manager | grep -v grep | awk '{print "kill -cont "$2}' | sh
        elif [ `tail -n 5 $1 | grep "failed to create instance" | grep "/data/syzkaller"| grep "99241FFAZ0009E" | wc -l` -gt 0 ] ; then
            ps -ef | grep syz-manager | grep -v grep | awk '{print "kill -stop "$2}' | sh
            sleep 90
            adb -s "99241FFAZ0009E" shell rm -rf /data/syzkaller*/*/*/cgroup*
            ps -ef | grep syz-manager | grep -v grep | awk '{print "kill -cont "$2}' | sh
        elif [ `tail -n 5 $1 | grep "failed to create instance" | grep "/data/syzkaller"| grep "9C181FF995B7E9" | wc -l` -gt 0 ] ; then
            ps -ef | grep syz-manager | grep -v grep | awk '{print "kill -stop "$2}' | sh
            sleep 90
            adb -s "9C181FF995B7E9" shell rm -rf /data/syzkaller*/*/*/cgroup*
            ps -ef | grep syz-manager | grep -v grep | awk '{print "kill -cont "$2}' | sh
        elif [ `tail -n 5 $1 | grep "failed to create instance" | grep "/data/syzkaller"| grep "9A271FFAZ004NK" | wc -l` -gt 0 ] ; then
            ps -ef | grep syz-manager | grep -v grep | awk '{print "kill -stop "$2}' | sh
            sleep 90
            adb -s "9A271FFAZ004NK" shell rm -rf /data/syzkaller*/*/*/cgroup*
            ps -ef | grep syz-manager | grep -v grep | awk '{print "kill -cont "$2}' | sh
        elif [ `tail -n 5 $1 | grep "failed to create instance" | grep -v "/data/syzkaller"| grep "99281FFAZ0051Y" | wc -l` -gt 0 ] ; then
            python hard_reboot.py 1
            sleep 60
        elif [ `tail -n 5 $1 | grep "failed to create instance" | grep -v "/data/syzkaller"| grep "99241FFAZ0009E" | wc -l` -gt 0 ] ; then
            python hard_reboot.py 2
            sleep 60
        elif [ `tail -n 5 $1 | grep "failed to create instance" | grep -v "/data/syzkaller"| grep "9C181FF995B7E9" | wc -l` -gt 0 ] ; then
            python hard_reboot.py 3
            sleep 60
        elif [ `tail -n 5 $1 | grep "failed to create instance" | grep -v "/data/syzkaller"| grep "9A271FFAZ004NK" | wc -l` -gt 0 ] ; then
            python hard_reboot.py 0
            sleep 60
        fi
        # notify-send "phone freeze, reboot it manually!"
    fi
    sleep 30
done

