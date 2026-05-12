package bench_test

import "testing"

func BenchmarkPubSub(b *testing.B) {
	topic := []byte("bench")
	for _, a := range adapters {
		b.Run(a.Name(), func(b *testing.B) {
			for _, tr := range benchTransports {
				b.Run(tr.name, func(b *testing.B) {
					for _, sz := range benchSizes {
						b.Run(humanSize(sz), func(b *testing.B) {
							pub, sub, cleanup, err := a.PubSub(tr.addrFn(), topic)
							if skipIfNotSupported(b, err) {
								return
							}
							if err != nil {
								b.Fatalf("PubSub setup: %v", err)
							}
							defer cleanup()
							// Dłuższy czas na propagację subskrypcji.
							waitReady(50 * 1e6) // 50ms
							// Use benchPubSubThroughput instead of benchThroughput
							// because PUB drops messages when the outbound queue is
							// full; benchThroughput would deadlock waiting for exact
							// b.N deliveries.
							benchPubSubThroughput(b, pub, sub, sz)
						})
					}
				})
			}
		})
	}
}
