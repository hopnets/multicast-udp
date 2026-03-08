#!/usr/bin/env bash
set -euo pipefail

mkdir -p receiver_outputs

# Usage: ./build/reno_receiver --port P [--out file]
# [--rcvbuf BYTES] [--rwnd N] [--rto-ms MS] [--retries K]

out_file="receiver_outputs/r1.bin"
echo "Output file: ${out_file}"

./build/peel_receiver \
  --port 5000 \
  --out "${out_file}"