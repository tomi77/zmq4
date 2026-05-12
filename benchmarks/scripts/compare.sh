#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== tomi77 vs go-zeromq ==="
go test -bench=. -benchmem -count=6 ./... 2>/dev/null \
  | tee /tmp/bench_all.txt

if command -v benchstat &>/dev/null; then
  grep '/tomi77/' /tmp/bench_all.txt > /tmp/bench_tomi77.txt
  grep '/gozeromq/' /tmp/bench_all.txt > /tmp/bench_gozeromq.txt
  benchstat /tmp/bench_tomi77.txt /tmp/bench_gozeromq.txt
else
  echo "Install benchstat: go install golang.org/x/perf/cmd/benchstat@latest"
fi

# Porównanie z pebbe wymaga libzmq (CGO). Pomijamy jeśli niedostępne.
if pkg-config --exists libzmq 2>/dev/null; then
  echo ""
  echo "=== tomi77 vs pebbe ==="
  go test -tags libzmq -bench=. -benchmem -count=6 ./... 2>/dev/null \
    | tee /tmp/bench_all_libzmq.txt

  if command -v benchstat &>/dev/null; then
    grep '/tomi77/' /tmp/bench_all_libzmq.txt > /tmp/bench_tomi77_libzmq.txt
    grep '/pebbe/' /tmp/bench_all_libzmq.txt > /tmp/bench_pebbe.txt
    benchstat /tmp/bench_tomi77_libzmq.txt /tmp/bench_pebbe.txt
  fi
else
  echo ""
  echo "(pebbe pominięte — libzmq niedostępne; zainstaluj: brew install zeromq)"
fi
