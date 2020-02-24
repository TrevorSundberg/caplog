#!/usr/bin/env bash
set -e
cd `dirname "$0"`
[ ! -d build ] && ./generate.sh
cd build
../docker/run.sh cmake --build .