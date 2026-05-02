#!/usr/bin/env bash
# Regenerates the wire-format vector files in
# internal/wire/testdata/interop/<name>.bin from a real libzmq instance.
#
# Usage: ./capture.sh [vector-name]
#
# Requires: docker (with the libzmq Docker image), tcpdump (for capture
# script alternative — currently we use `socat` to splice and Wireshark
# to extract bytes manually for new vectors). For each vector, see the
# corresponding section below.
set -euo pipefail
# ... vector capture procedures ...
echo "TODO: implement per-vector capture for the listed scenarios."
exit 1
