# BSD 2-Clause License

# Copyright (c) 2020, Supreeth Herle
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

FROM ubuntu:jammy

ENV DEBIAN_FRONTEND=noninteractive

# Install updates and dependencies
RUN apt-get update && \
    apt-get -y install cmake make gcc g++ pkg-config libfftw3-dev libmbedtls-dev libsctp-dev libyaml-cpp-dev libgtest-dev \
    libzmq3-dev software-properties-common pkg-config net-tools iputils-ping git libboost-all-dev

# Install SoapySDR
RUN git clone https://github.com/pothosware/SoapySDR.git && \
    cd SoapySDR && mkdir build && cd build && cmake ../ && make -j`nproc` && make install && ldconfig

# Install bladerf and firmware
RUN add-apt-repository ppa:nuandllc/bladerf && apt-get update && \
    apt-get -y install bladerf libbladerf-dev bladerf-fpga-hostedxa4

# Install SoapyBladeRF
RUN git clone https://github.com/pothosware/SoapyBladeRF.git && cd SoapyBladeRF && \
    mkdir build && cd build && cmake ../ && make -j`nproc` && make install && ldconfig

# Install UHD drivers
RUN add-apt-repository ppa:ettusresearch/uhd && \
    apt update && apt -y install libuhd-dev uhd-host

# Install SoapyUHD
RUN git clone https://github.com/pothosware/SoapyUHD.git && cd SoapyUHD && mkdir build && cd build && \
    cmake ../ && make -j`nproc` && make install && ldconfig

ENV UHD_MODULE_PATH=/lib/uhd/modules

# Get srsRAN_Project, compile and install
RUN git clone https://github.com/maxbraunschmied/srsRAN_Project_bladeRF && \
    cd srsRAN_Project_bladeRF && \
    mkdir build && cd build && \
    cmake ../ -DENABLE_EXPORT=ON -DENABLE_ZEROMQ=ON && make -j`nproc` && make install && \
    ldconfig

CMD cd /mnt/srsran && /mnt/srsran/srsran_init.sh
