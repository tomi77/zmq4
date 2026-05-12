package bench_test

import "testing"

func BenchmarkPair(b *testing.B) {
	for _, a := range adapters {
		b.Run(a.Name(), func(b *testing.B) {
			for _, tr := range benchTransports {
				b.Run(tr.name, func(b *testing.B) {
					for _, sz := range benchSizes {
						b.Run(humanSize(sz), func(b *testing.B) {
							a1, a2, cleanup, err := a.Pair(tr.addrFn())
							if skipIfNotSupported(b, err) {
								return
							}
							if err != nil {
								b.Fatalf("Pair setup: %v", err)
							}
							defer cleanup()
							waitReady(5 * 1e6)
							// PAIR: mierzymy throughput w jednym kierunku.
							benchThroughput(b, a1, a2, sz)
						})
					}
				})
			}
		})
	}
}
