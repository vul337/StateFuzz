.md# StateFuzz

This version has been compatible with LLVM 11 to support fuzzing the latest Linux kernel.

### Introduction
StateFuzz is state-aware fuzzing solution for fuzzing Linux kernel drivers. 

It utilizes static analysis to recognize shared variables that are accessed by multiple program actions, 
and use them as state-variables to characterize program states. 

By tracing values of state-variables and using a combination of two state-variables as feedback, 
StateFuzzcan explore states during fuzzing while increasing code coverage.

### Find more details in our paper.

[paper](statefuzz.pdf)

```
@inproceedings {281444,
author = {Bodong Zhao and Zheming Li and Shisong Qin and Zheyu Ma and Ming Yuan and Wenyu Zhu and Zhihong Tian and Chao Zhang},
title = {{StateFuzz}: System {Call-Based} {State-Aware} Linux Driver Fuzzing},
booktitle = {31st USENIX Security Symposium (USENIX Security 22)},
year = {2022},
isbn = {978-1-939133-31-1},
address = {Boston, MA},
pages = {3273--3289},
url = {https://www.usenix.org/conference/usenixsecurity22/presentation/zhao-bodong},
publisher = {USENIX Association},
month = aug,
}
```

### Usage
#### Docker

You can easily use StateFuzz by running the following commands.

The built Docker image is huge (hundreds of GB). 

If you don't like it, we highly recommend you to manually build a container based on the Ubuntu 22.04 container, 
by executing the commands listed in the Dockerfile.


```
# Kill timeout processes of "bin/opt, bin/clang and bin/wpa"
chmod +x scripts/kill_timeout.sh
# Be careful! May kill innocent processes!
sudo ./scripts/kill_timeout.sh &

# build the image
docker image build --force-rm -t statefuzz_release:latest .
docker run --name statefuzz--container --privileged --rm  -itd statefuzz_release:latest
```
