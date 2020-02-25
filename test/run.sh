#!/usr/bin/env bash
set -e
cd `dirname "$0"`
../build.sh
docker build -t muxd/test -f Dockerfile ..
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --rm -v /usr/share/zoneinfo/UTC:/usr/share/zoneinfo/UTC muxd/test