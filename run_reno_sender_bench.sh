#!/usr/bin/env bash
set -euo pipefail

# -------------------------------
# Parse command-line arguments
# -------------------------------

# Usage: ./build/reno_sender_bench --host IP --port P
# --sender-port S [--file path] [--rto-ms MS] [--retries K]
# [--chunk BYTES] [--rwnd N]

expected="${1:-1}"     # default expected = 1
payload_mb="${2:-10}"  # default payload size = 10M

echo "Expected receivers : ${expected}"
echo "Payload size (MB)  : ${payload_mb}M"

# Construct payload file path
payload_file="payloads/payload.bin_${payload_mb}M"
echo "Using payload file : ${payload_file}"

# -------------------------------
# Run sender
# -------------------------------
./build/reno_sender_bench \
  --host "10.169.144.15" \
  --port 5000 \
  --sender-port 45000 \
  --rto-ms 250 \
  --retries 20
  # --host should be changed outside of testing