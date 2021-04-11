#!/bin/bash

set -e

cd $(dirname $0)

docker build -t asciinema-recorder .
docker run -it --rm --network host \
  -v $(pwd):/data \
  -v /etc/hosts:/etc/hosts \
  asciinema-recorder
