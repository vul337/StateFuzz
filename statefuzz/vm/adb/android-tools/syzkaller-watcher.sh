#!/bin/sh
# echo '9999' > /sys/module/lowmemorykiller/parameters/adj
# echo '1' > /sys/module/lowmemorykiller/parameters/minfree

count=0
dmesg -w > /data/dmesg.log&
while true : 
do
    echo "[info] watcher heartbeat" >> /dev/kmsg
    echo `ps -ef | grep -v grep | grep adb` >> /dev/kmsg
    ps -ef | grep 'syz-' | grep -v grep | awk '{print "echo -17 > /proc/"$2"/oom_adj"}' | sh
    ps -ef | grep 'syzkaller' | grep -v grep | awk '{print "echo -17 > /proc/"$2"/oom_adj"}' | sh
    # if [ `dmesg | grep -v grep | grep "lowmemorykiller: Killing 'ndroid.settings'" | wc -l` -gt 0 ] ; then
    if [ `cat /data/dmesg.log | grep -v grep | grep "lowmemorykiller: Killing 'syz-executor'" | wc -l` -gt 0 ] ; then
    # if [ `ps -ef | grep -v grep | grep adb | wc -l` -eq 0 ] ; then
        # echo "lowmemorykiller killing processes. rebooting " >> /dev/kmsg;
        echo "syzkaller-watcher: rebooting " >> /dev/kmsg;
        reboot;
    fi

# no adbd but syz-fuzzer exists, wait for 120s, reboot
	if [ `ps -ef | grep -v grep | grep -w -E "syz-fuzzer|syz-execprog" | wc -l` -gt 0 ] ; then
		if [ `ps -ef | grep -v grep | grep -w adbd | wc -l` -eq 0 ] ; then
			count=$(($count+1))
		else
			count=0
		fi
		if [ $count -gt 12000 ] ; then
			echo "no adbd found, rebooting" >> /dev/kmsg;
            sleep 5;
            reboot;
		fi
# no syz-fuzzer but adbd exists, wait for 300s, reboot
	elif [ `ps -ef | grep -v grep | grep -w adbd | wc -l` -gt 0 ] ; then
		if [ `ps -ef | grep -v grep | grep -w -E "syz-fuzzer|syz-execprog" | wc -l` -eq 0 ] ; then
			count=$(($count+1))
		else
			count=0
		fi
		if [ $count -gt 12000 ] ; then
			echo "no syz-fuzzer found, rebooting" >> /dev/kmsg;
            sleep 5;
            reboot;
		fi
# neither syz-fuzzer nor adbd exist, wait for 300s, reboot
	else
		count=$(($count+1))
        if [ $count -gt 15000 ] ; then
			echo "no syz-fuzzer or adbd found, rebooting" >> /dev/kmsg;
            sleep 5;
            reboot;
		fi
	fi
	# echo $count
	sleep 0.01
done
