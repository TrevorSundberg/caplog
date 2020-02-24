#!/usr/bin/env bash
set -e
cd `dirname "$0"`
rm -rf build
mkdir -p build
cd build
../docker/run.sh bash -c 'cmake -Wno-dev -GNinja -DCMAKE_TOOLCHAIN_FILE=/vcpkg/scripts/buildsystems/vcpkg.cmake ..'