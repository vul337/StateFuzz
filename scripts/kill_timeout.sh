#!/bin/sh

while true;do ps -ef | grep -v grep | grep -v python | grep -E "bin/opt |bin/clang |bin/wpa " | grep '[1-9]:[0-9][0-9]:'  | awk '{print "kill -9 "$2}' |sh; sleep 10;done
