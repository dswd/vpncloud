#!/bin/bash

DST=$1

echo
echo "----------"
echo "Throughput"
echo "----------"
for i in 0 1 2; do
  iperf -c $DST -t 30
done

for size in 100 500 1000; do
  echo
  echo "--------------------"
  echo "Latency ($size Bytes)"
  echo "--------------------"
  for i in 0 1 2 3 4; do
    ping $DST -c 30000 -i 0.001 -s $size -U -q
  done
done
