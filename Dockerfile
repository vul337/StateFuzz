FROM ubuntu:20.04 as basic_env

LABEL maintainer="nop" email="nopitydays@gmail.com"
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Aisa/Shanghai

RUN apt update && apt install -y sudo gcc g++ binutils cmake make \
    python automake autoconf libelf-dev bc git \
    flex bison python3 libssl-dev dwarves pkg-config \
    libxml2-dev sqlite3 libsqlite3-dev vim


RUN useradd -ms /bin/bash fuzz
RUN echo "fuzz:fuzz" | chpasswd && \
    gpasswd -a fuzz sudo && echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER fuzz
RUN mkdir -p /home/fuzz/code /home/fuzz/kernel /home/fuzz/kernel/fs

FROM basic_env as llvm_env
# compile llvm-11.0.1
RUN git clone https://github.com/Z3Prover/z3 /home/fuzz/code/z3
WORKDIR /home/fuzz/code/z3
RUN ./configure && cd build && make -j4 && sudo make install

COPY --chown=fuzz llvm-11.0.1 /home/fuzz/code/llvm-11.0.1
RUN mkdir /home/fuzz/code/llvm-11.0.1/build
WORKDIR /home/fuzz/code/llvm-11.0.1/build
RUN cmake .. && make -j12

FROM llvm_env as linux_kernel_env
# build the Linux kernel
# COPY --chown=fuzz linux /home/fuzz/kernel/linux
RUN git clone https://github.com/torvalds/linux /home/fuzz/kernel/linux
WORKDIR /home/fuzz/kernel/linux
# RUN git checkout v6.4-rc3
COPY --chown=fuzz linux-patches/config_syzbot* /home/fuzz/kernel/linux/
WORKDIR /home/fuzz/kernel/linux
RUN mkdir /home/fuzz/kernel/linux-out /home/fuzz/kernel/linux-out-kasan
RUN cp /home/fuzz/kernel/linux/config_syzbot /home/fuzz/kernel/linux-out/.config
RUN yes "" | make oldconfig CC=/home/fuzz/code/llvm-11.0.1/build/bin/clang O=/home/fuzz/kernel/linux-out
RUN make -j12 V=1 CC=/home/fuzz/code/llvm-11.0.1/build/bin/clang O=/home/fuzz/kernel/linux-out 2>&1 | tee /home/fuzz/kernel/linux/makeout.txt


FROM linux_kernel_env as difuze_env
# build DIFUZE
ENV PATH="$PATH:/home/fuzz/code/llvm-11.0.1/build/bin:/home/fuzz/code/difuze/difuze_deps/sparse"
ENV LLVM_ROOT="LLVM_ROOT=/home/fuzz/code/llvm-11.0.1/build"
RUN mkdir -p /tmp/difuze/ home/fuzz/kernel/ioctlfinded-linux /home/fuzz/kernel/lvout-linux
COPY --chown=fuzz difuze /home/fuzz/code/difuze
RUN git clone git://git.kernel.org/pub/scm/devel/sparse/sparse.git /home/fuzz/code/difuze/difuze_deps/sparse
WORKDIR /home/fuzz/code/difuze/difuze_deps/sparse
RUN git checkout v0.6.4
RUN mv /home/fuzz/code/difuze/deps/sparse/pre-process.c /home/fuzz/code/difuze/difuze_deps/sparse/ && rm -rf /home/fuzz/code/difuze/deps/
RUN make -j12
WORKDIR /home/fuzz/code/difuze/InterfaceHandlers
RUN chmod +x build.sh && ./build.sh
WORKDIR /home/fuzz/code/difuze/helper_scripts
RUN python run_all.py -l /home/fuzz/kernel/lvout-linux -a 5 -m /home/fuzz/kernel/linux/makeout.txt -g /home/fuzz/code/llvm-11.0.1/build/bin/clang -n 3 -o /home/fuzz/kernel/linux-out -k /home/fuzz/kernel/linux -f /home/fuzz/kernel/ioctlfinded-linux -clangp /home/fuzz/code/llvm-11.0.1/build/bin/clang 2>&1 | tee output.log && sudo rm /tmp/tmp*
RUN cp -r /home/fuzz/kernel/ioctlfinded-linux /home/fuzz/kernel/ioctlfinded-linux-backup
RUN python parse_interface_with_manual_interface.py /home/fuzz/kernel/ioctlfinded-linux/ interface_manual_linux.csv
RUN python parse_interface_to_svCollector.py /home/fuzz/kernel/ioctlfinded-linux/ /home/fuzz/kernel/lvout-linux/entry_point_out.txt > /home/fuzz/ioctl_TopFunc.txt

FROM difuze_env as sv_collector_env
# build sv-collector
COPY --chown=fuzz sv-collector /home/fuzz/code/sv-collector
WORKDIR /home/fuzz/code/sv-collector
RUN make
RUN mkdir -p /home/fuzz/code/sv-collector/result /home/fuzz/work/statemodel  /home/fuzz/kernel/lvout-linux-sym /home/fuzz/kernel/ioctlfinded-linux-tmp
RUN cp /home/fuzz/ioctl_TopFunc.txt /home/fuzz/code/sv-collector/result/ioctl_TopFunc.txt
RUN chmod +x run.sh && ./run.sh /home/fuzz/kernel/lvout-linux /home/fuzz/code/sv-collector/result/logfile.txt

# get sv list
COPY --chown=fuzz scripts /home/fuzz/code/scripts
WORKDIR /home/fuzz/code/scripts
RUN python parse_svCollector_output.py -i /home/fuzz/code/sv-collector/result/logfile.txt -o /home/fuzz/work/statemodel/sv_list.txt

FROM sv_collector_env as state_model_env
# extract sv-ranges with CSA
WORKDIR /home/fuzz/code/difuze/helper_scripts
###
RUN cp /home/fuzz/work/statemodel/sv_list.* /tmp/
RUN python run_all.py -l /home/fuzz/kernel/lvout-linux-sym -a 5 -m /home/fuzz/kernel/linux/makeout.txt -g /home/fuzz/code/llvm-11.0.1/build/bin/clang -n 3 -o /home/fuzz/kernel/linux-out -k /home/fuzz/kernel/linux -f /home/fuzz/kernel/ioctlfinded-linux-tmp -clangp /home/fuzz/code/llvm-11.0.1/build/bin/clang -clang-static-checker debug.SymStateVariableValueAnalysis 2>&1 | tee output-sym.log
WORKDIR /home/fuzz/code/scripts
RUN chmod +x *.sh && ./parse_sv_range.sh /home/fuzz/kernel/lvout-linux-sym
RUN python parse_sv_range_to_statefuzz.py /tmp/sv_range.txt /tmp/sv_list.txt  /home/fuzz/work/statemodel/sv_range.json /home/fuzz/work/statemodel/sv_pairs.json

FROM state_model_env as final_fuzz_env
COPY --chown=fuzz svf /home/fuzz/code/svf
WORKDIR /home/fuzz/code/svf
RUN chmod +x build.sh && ./build.sh
WORKDIR /home/fuzz/code/scripts
RUN python svf_find_sv_alias.py /home/fuzz/code/svf/Release-build/bin/wpa /home/fuzz/kernel/lvout-linux
RUN python parse_svf_output.py /home/fuzz/kernel/lvout-linux > /home/fuzz/work/statemodel/instrument_points.json && cp /home/fuzz/work/statemodel/instrument_points.json /tmp
RUN sed -i 's/"linux\//"/g' /tmp/instrument_points.json
WORKDIR /home/fuzz/kernel/linux
COPY --chown=fuzz linux-patches/kcov.c.patched /home/fuzz/kernel/linux/kernel/kcov.c
COPY --chown=fuzz linux-patches/Makefile.kcov.patched /home/fuzz/kernel/linux/scripts/Makefile.kcov
RUN cp /home/fuzz/kernel/linux/config_syzbot_kasan /home/fuzz/kernel/linux-out-kasan/.config
RUN yes "" | make oldconfig CC=/home/fuzz/code/llvm-11.0.1/build/bin/clang O=/home/fuzz/kernel/linux-out-kasan
RUN make -j12 CC=/home/fuzz/code/llvm-11.0.1/build/bin/clang O=/home/fuzz/kernel/linux-out-kasan 2>&1 | tee build_kasan.log

COPY --chown=fuzz statefuzz /home/fuzz/code/statefuzz
COPY --chown=fuzz start.sh /home/fuzz/start.sh
RUN chmod +x /home/fuzz/start.sh
CMD ["/bin/bash", "/home/fuzz/start.sh"]
