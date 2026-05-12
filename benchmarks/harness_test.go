package bench_test

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// ErrNotSupported zwraca adapter gdy dany transport jest nieobsługiwany.
var ErrNotSupported = errors.New("transport not supported")

// Socket — minimalny interfejs wspólny dla wszystkich wzorców.
type Socket interface {
	Send(msg []byte) error
	Recv() ([]byte, error)
	Close() error
}

// Adapter — każda implementacja dostarcza jeden egzemplarz.
type Adapter interface {
	Name() string
	// Każda metoda zwraca (bind_socket, connect_socket, cleanup, err).
	// Zwróć ErrNotSupported jeśli transport jest nieobsługiwany.
	PushPull(addr string) (Socket, Socket, func(), error)
	ReqRep(addr string) (Socket, Socket, func(), error)
	PubSub(addr string, topic []byte) (Socket, Socket, func(), error)
	Pair(addr string) (Socket, Socket, func(), error)
}

var adapters []Adapter

func registerAdapter(a Adapter) { adapters = append(adapters, a) }

var inprocCounter atomic.Int64

func inprocAddr() string {
	return fmt.Sprintf("inproc://bench-%d", inprocCounter.Add(1))
}

func tcpAddr() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := l.Addr().String()
	l.Close()
	return "tcp://" + addr
}

var benchTransports = []struct {
	name    string
	addrFn  func() string
}{
	{"inproc", inprocAddr},
	{"tcp", tcpAddr},
}

var benchSizes = []int{64, 1024, 65536, 1 << 20}

func humanSize(n int) string {
	switch {
	case n >= 1<<20:
		return "1MiB"
	case n >= 1<<16:
		return "64KiB"
	case n >= 1<<10:
		return "1KiB"
	default:
		return "64B"
	}
}

// benchThroughput mierzy przepustowość: sender wysyła b.N wiadomości,
// receiver czyta w goroutine.
func benchThroughput(b *testing.B, sender, receiver Socket, msgSize int) {
	b.Helper()
	msg := make([]byte, msgSize)
	for i := range msg {
		msg[i] = 0x42
	}
	b.SetBytes(int64(msgSize))
	b.ReportAllocs()

	errCh := make(chan error, 1)
	go func() {
		for i := 0; i < b.N; i++ {
			if _, err := receiver.Recv(); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sender.Send(msg); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if err := <-errCh; err != nil {
		b.Fatal(err)
	}
}

// benchRoundTrip mierzy latencję round-trip: req wysyła + czeka na odpowiedź,
// rep echo-pętla w goroutine.
func benchRoundTrip(b *testing.B, req, rep Socket, msgSize int) {
	b.Helper()
	msg := make([]byte, msgSize)
	for i := range msg {
		msg[i] = 0x42
	}
	b.SetBytes(int64(msgSize * 2))
	b.ReportAllocs()

	// Rep echo-goroutine
	go func() {
		for {
			data, err := rep.Recv()
			if err != nil {
				return
			}
			if err := rep.Send(data); err != nil {
				return
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := req.Send(msg); err != nil {
			b.Fatal(err)
		}
		if _, err := req.Recv(); err != nil {
			b.Fatal(err)
		}
	}
}

// waitReady daje czas na propagację połączenia/subskrypcji.
func waitReady(d time.Duration) { time.Sleep(d) }

// skipIfNotSupported pomija benchmark gdy adapter nie obsługuje transportu.
func skipIfNotSupported(b *testing.B, err error) bool {
	b.Helper()
	if errors.Is(err, ErrNotSupported) {
		b.Skipf("adapter does not support this transport")
		return true
	}
	return false
}
