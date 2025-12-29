#!/usr/bin/env bash
set -euo pipefail

#IP_PREFIX="10.169.144."
IP_PREFIX="192.168.1."

# -------------------------------
# Parse command-line arguments
# -------------------------------
expected="${1:-1}"     # default expected = 1
payload_mb="${2:-10}"  # default payload size = 10M

echo "Expected receivers : ${expected}"
echo "Payload size (MB)  : ${payload_mb}M"

# Construct payload file path
payload_file="payloads/payload.bin_${payload_mb}M"
echo "Using payload file : ${payload_file}"

# -------------------------------
# Detect interface IP
# -------------------------------
iface_ip=$(
  ip -4 -o addr show \
  | awk -v prefix="$IP_PREFIX" '
      index($4, prefix) == 1 {
        sub(/\/.*/, "", $4);
        print $4;
        exit;
      }
    '
)

if [[ -z "${iface_ip:-}" ]]; then
  echo "ERROR: No IPv4 address starting with ${IP_PREFIX} found." >&2
  exit 1
fi

echo "Using iface IP     : ${iface_ip}"

# -------------------------------
# Run sender
# -------------------------------
./build/peel_sender \
  --group 239.255.0.1 \
  --port 5000 \
  --sender-port 45000 \
  --expected "${expected}" \
  --ttl 1 \
  --rto-ms 250 \
  --retries 20 \
  --chunk 1452 \
  --iface "${iface_ip}"
#--file "${payload_file}" \