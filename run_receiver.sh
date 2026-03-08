#!/usr/bin/env bash
set -euo pipefail

IP_PREFIX="10.169.144."

# Find the first IPv4 address on this host that starts with 10.169.144.
iface_ip=$(
  ip -4 -o addr show \
  | awk -v prefix="$IP_PREFIX" '
      index($4, prefix) == 1 {       # address field starts with the prefix
        sub(/\/.*/, "", $4);         # strip /mask (e.g. /24)
        print $4;
        exit;                        # use the first match
      }
    '
)

if [[ -z "${iface_ip:-}" ]]; then
  echo "ERROR: No IPv4 address starting with ${IP_PREFIX} found on this host." >&2
  exit 1
fi

echo "Using iface IP: ${iface_ip}"

# Extract last octet for filename, e.g. 10.169.144.16 → 16
last_octet="${iface_ip##*.}"

mkdir -p receiver_outputs

out_file="receiver_outputs/r1.bin_${last_octet}"
echo "Output file: ${out_file}"

./build/peel_receiver \
  --group 239.255.0.1 \
  --port 5000 \
  --out "${out_file}" \
  --iface "${iface_ip}"
