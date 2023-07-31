#!/bin/sh
  
echo > /tmp/sv_range.txt
for f in $(find $1 -name *.sv_range)
do
       echo "$f" >> /tmp/sv_range.txt;
       cat $f | grep -E "sym_name|FieldName|sv_in_one_check:" >> /tmp/sv_range.txt
done
