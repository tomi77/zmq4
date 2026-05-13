#!/usr/bin/env bash
# Run each benchmark pattern in its own process so accumulated GC pressure
# from earlier benchmarks cannot skew later results (especially large messages).
#
# Usage:
#   ./bench.sh                      # tomi77 only, count=3, benchtime=3s
#   ./bench.sh -tags libzmq         # include pebbe (requires libzmq)
#   BENCHTIME=5s COUNT=6 ./bench.sh # override defaults
#
# Output is tee'd to OUTFILE (default /tmp/bench_isolated.txt) and also
# printed to stdout — pipe-friendly for benchstat:
#   ./bench.sh | benchstat /dev/stdin
set -euo pipefail
cd "$(dirname "$0")/.."

BENCHTIME="${BENCHTIME:-3s}"
COUNT="${COUNT:-3}"
OUTFILE="${OUTFILE:-/tmp/bench_isolated.txt}"

# Extra go test flags forwarded verbatim (e.g. -tags libzmq).
EXTRA_FLAGS=("$@")

BENCHES=(BenchmarkPair BenchmarkPubSub BenchmarkPushPull BenchmarkReqRep)
SIZES=(64B 1KiB 64KiB 1MiB)

total=$(( ${#BENCHES[@]} * ${#SIZES[@]} ))
current=0

rm -f "$OUTFILE"

for bench in "${BENCHES[@]}"; do
  for size in "${SIZES[@]}"; do
    current=$(( current + 1 ))
    printf "[%d/%d] %-35s\r" "$current" "$total" "$bench/$size" >&2
    go test \
      -run='^$' \
      -bench="${bench}/.*/.*/${size}" \
      -benchtime="$BENCHTIME" \
      -benchmem \
      -count="$COUNT" \
      "${EXTRA_FLAGS[@]}" \
      . 2>/dev/null \
      | grep -v '^ok\|^PASS\|^FAIL' \
      | tee -a "$OUTFILE"
  done
done

printf '\n' >&2
printf 'Results written to %s\n' "$OUTFILE" >&2
