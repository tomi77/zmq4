package bench_test

import "testing"

func BenchmarkPushPull(b *testing.B) {
	for _, a := range adapters {
		b.Run(a.Name(), func(b *testing.B) {
			for _, tr := range benchTransports {
				b.Run(tr.name, func(b *testing.B) {
					for _, sz := range benchSizes {
						b.Run(humanSize(sz), func(b *testing.B) {
							push, pull, cleanup, err := a.PushPull(tr.addrFn())
							if skipIfNotSupported(b, err) {
								return
							}
							if err != nil {
								b.Fatalf("PushPull setup: %v", err)
							}
							defer cleanup()
							waitReady(5 * 1e6) // 5ms
							benchThroughput(b, push, pull, sz)
						})
					}
				})
			}
		})
	}
}
