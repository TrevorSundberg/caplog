FROM ubuntu:19.10@sha256:bd5f4f235eb31768b2c5caf1988bbdc182d4fc3cb6ee4aca6c6d74613f256140

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      clang \
      cmake \
      curl \
      git \
      ninja-build \
      tar \
      unzip

RUN git clone https://github.com/Microsoft/vcpkg.git
ENV CC=/usr/bin/clang
ENV CXX=/usr/bin/clang++
RUN cd vcpkg && \
    ./bootstrap-vcpkg.sh && \
    ./vcpkg integrate install
RUN cd vcpkg && \
    ./vcpkg install \
      cxxopts \
      date