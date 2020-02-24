#!/usr/bin/env bash
set -e
cd `dirname "$0"`/build
../docker/run.sh cmake --build .