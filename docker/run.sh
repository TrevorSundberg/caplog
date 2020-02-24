#!/usr/bin/env bash
set -e
REPO=`git rev-parse --show-toplevel`
docker build -t muxd/build $REPO/docker
docker run \
    --rm \
    -u $(id -u):$(id -g) \
    -e CCACHE_DIR="$REPO/build/cache" \
    -v "$REPO:$REPO" \
    -w "`pwd`" \
    muxd/build \
    "$@"