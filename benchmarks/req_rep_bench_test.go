package bench_test

import "testing"

func BenchmarkReqRep(b *testing.B) {
	for _, a := range adapters {
		b.Run(a.Name(), func(b *testing.B) {
			for _, tr := range benchTransports {
				b.Run(tr.name, func(b *testing.B) {
					for _, sz := range benchSizes {
						b.Run(humanSize(sz), func(b *testing.B) {
							req, rep, cleanup, err := a.ReqRep(tr.addrFn())
							if skipIfNotSupported(b, err) {
								return
							}
							if err != nil {
								b.Fatalf("ReqRep setup: %v", err)
							}
							defer cleanup()
							waitReady(5 * 1e6)
							benchRoundTrip(b, req, rep, sz)
						})
					}
				})
			}
		})
	}
}
