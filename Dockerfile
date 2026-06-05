# To avoid compatibility issues, align debian version with version produced by syzkaller/tools/create_image.sh
FROM debian:bullseye-slim
ARG KERNEL_DIR="v6.13-rc4"
RUN apt update -y
RUN apt install build-essential -y
RUN apt install libelf-dev python3 -y
RUN apt install wget -y
RUN apt install lsb-release software-properties-common gnupg -y
RUN apt install git -y
RUN apt install cmake -y
RUN wget https://apt.llvm.org/llvm.sh
RUN chmod +x ./llvm.sh
RUN ./llvm.sh 16
RUN for f in /usr/bin/*-16; do \
      base="$(basename "$f" -16)"; \
      [ -e "/usr/bin/$base" ] || ln -s "$f" "/usr/bin/$base"; \
    done

# Define the Go version
ENV GO_VERSION=1.20

# Install dependencies and download Go
RUN apt install -y tar \
    && wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz

# Set environment variables
ENV PATH=$PATH:/usr/local/go/bin

# Verify installation
RUN go version

RUN apt install -y clang-format


RUN wget https://apt.llvm.org/llvm.sh

RUN apt install cmake zlib1g-dev libdw-dev -y
RUN git clone --branch v1.28 https://github.com/acmel/dwarves
WORKDIR /dwarves

RUN mkdir build; cd build; cmake ..; make install
RUN ldconfig



COPY ./instrumentation /sect/instrumentation

WORKDIR /sect/instrumentation

RUN cmake -DLLVM_ENABLE_ASSERTIONS=ON -DCMAKE_BUILD_TYPE=Debug -B build; cd build; make

RUN mkdir /sect/$KERNEL_DIR
WORKDIR /sect/$KERNEL_DIR

WORKDIR /
# RUN git clone https://github.com/udhos/update-golang.git
# WORKDIR /update-golang
# RUN RELEASE=1.19 ./update-golang.sh
# RUN /etc/profile.d/golang_path.sh
# RUN go version


