#!/bin/sh

echo > /tmp/sv_range.txt
for f in $(find $1 -name *.sv_range)
do
        echo "$f" >> /tmp/sv_range.txt;
        cat $f >> /tmp/sv_range.txt
done
