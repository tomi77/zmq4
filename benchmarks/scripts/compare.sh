#!/usr/bin/env bash
# Compare tomi77 against go-zeromq (and optionally pebbe) using benchstat.
# Each benchmark runs in its own process via bench.sh to avoid GC cross-contamination.
#
# Usage:
#   ./compare.sh                     # tomi77 vs go-zeromq
#   BENCHTIME=5s COUNT=6 ./compare.sh
#
# Requires: go install golang.org/x/perf/cmd/benchstat@latest
set -euo pipefail
cd "$(dirname "$0")/.."

BENCHTIME="${BENCHTIME:-3s}"
COUNT="${COUNT:-6}"

echo "=== tomi77 vs go-zeromq ===" >&2
BENCHTIME="$BENCHTIME" COUNT="$COUNT" OUTFILE=/tmp/bench_isolated.txt \
  ./scripts/bench.sh

if command -v benchstat &>/dev/null; then
  grep '/tomi77/'   /tmp/bench_isolated.txt > /tmp/bench_tomi77.txt
  grep '/gozeromq/' /tmp/bench_isolated.txt > /tmp/bench_gozeromq.txt
  benchstat /tmp/bench_tomi77.txt /tmp/bench_gozeromq.txt
else
  echo "Install benchstat: go install golang.org/x/perf/cmd/benchstat@latest"
fi

if pkg-config --exists libzmq 2>/dev/null; then
  echo "" >&2
  echo "=== tomi77 vs pebbe ===" >&2
  BENCHTIME="$BENCHTIME" COUNT="$COUNT" OUTFILE=/tmp/bench_isolated_libzmq.txt \
    ./scripts/bench.sh -tags libzmq

  if command -v benchstat &>/dev/null; then
    grep '/tomi77/' /tmp/bench_isolated_libzmq.txt > /tmp/bench_tomi77_libzmq.txt
    grep '/pebbe/'  /tmp/bench_isolated_libzmq.txt > /tmp/bench_pebbe.txt
    benchstat /tmp/bench_tomi77_libzmq.txt /tmp/bench_pebbe.txt
  fi
else
  echo "" >&2
  echo "(pebbe pominięte — libzmq niedostępne; zainstaluj: brew install zeromq)" >&2
fi
