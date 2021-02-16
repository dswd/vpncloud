#!/bin/bash

set -e 

docker build -t asciinema-recorder .
docker run -it --rm --network host -v $(pwd)/../../target/release/:/usr/local/bin/ -v $(pwd):/data asciinema-recorder asciinema "$@"