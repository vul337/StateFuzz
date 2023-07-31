#!/bin/sh

# find $1 -name "*.llvm.bc" | grep -v llvm_link > bitcode.list;
find $1"/drivers" -name "*.llvm.bc" > bitcode.list;
find $1"/fs" -name "*.llvm.bc" >> bitcode.list;
find $1"/net" -name "*.llvm.bc" >> bitcode.list;
find $1"/sound" -name "*.llvm.bc" >> bitcode.list;
find $1"/block" -name "*.llvm.bc" >> bitcode.list;
sleep 5
./build/lib/KAMain -StateVariable-Analysis @bitcode.list > $2 2>&1

