package transport_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/tomi77/zmq4/internal/transport"
)

// shortTempDir returns a short-pathed temp dir registered for cleanup.
// We avoid t.TempDir() for ipc because t.TempDir() embeds the test name
// in the path, and on macOS UNIX socket paths must fit in sun_path
// (~104 bytes), which is overrun by long subtest names.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "zmq")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

type schemeFactory struct {
	name         string
	bindEndpoint func(t *testing.T) string
	dialEndpoint func(lis net.Listener) string
	skipReason   string // non-empty => Skip with this reason
}

func schemes(t *testing.T) []schemeFactory {
	t.Helper()
	ipcSkip := ""
	if runtime.GOOS == "windows" {
		ipcSkip = "ipc not implemented on windows (transport.ErrSchemeUnknown)"
	}
	return []schemeFactory{
		{
			name:         "tcp",
			bindEndpoint: func(t *testing.T) string { return "tcp://127.0.0.1:*" },
			dialEndpoint: func(lis net.Listener) string { return "tcp://" + lis.Addr().String() },
		},
		{
			name: "ipc",
			bindEndpoint: func(t *testing.T) string {
				return "ipc://" + filepath.Join(shortTempDir(t), "zmq.sock")
			},
			dialEndpoint: func(lis net.Listener) string { return "ipc://" + lis.Addr().String() },
			skipReason:   ipcSkip,
		},
		{
			name:         "inproc",
			bindEndpoint: func(t *testing.T) string { return "inproc://crossscheme/" + t.Name() },
			dialEndpoint: func(lis net.Listener) string { return "inproc://" + lis.Addr().String() },
		},
	}
}

func TestCrossSchemeRoundTrip(t *testing.T) {
	for _, sc := range schemes(t) {
		t.Run(sc.name, func(t *testing.T) {
			if sc.skipReason != "" {
				t.Skip(sc.skipReason)
			}
			ctx := context.Background()
			lis, err := transport.Listen(ctx, sc.bindEndpoint(t))
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer lis.Close()

			type p struct {
				c net.Conn
				e error
			}
			ch := make(chan p, 1)
			go func() {
				c, e := lis.Accept()
				ch <- p{c, e}
			}()

			dc, err := transport.Dial(ctx, sc.dialEndpoint(lis))
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer dc.Close()
			got := <-ch
			if got.e != nil {
				t.Fatalf("Accept: %v", got.e)
			}
			defer got.c.Close()

			payloads := [][]byte{
				bytes.Repeat([]byte("a"), 1024),
				bytes.Repeat([]byte("b"), 1<<20), // 1 MiB
			}
			var wg sync.WaitGroup
			for _, want := range payloads {
				want := want
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, _ = dc.Write(want)
				}()
				buf := make([]byte, len(want))
				if _, err := io.ReadFull(got.c, buf); err != nil {
					t.Fatalf("ReadFull(%d): %v", len(want), err)
				}
				if !bytes.Equal(buf, want) {
					t.Fatalf("recv mismatch (len=%d)", len(want))
				}
			}
			wg.Wait()
		})
	}
}

func TestCrossSchemeCloseUnblocksAccept(t *testing.T) {
	for _, sc := range schemes(t) {
		t.Run(sc.name, func(t *testing.T) {
			if sc.skipReason != "" {
				t.Skip(sc.skipReason)
			}
			ctx := context.Background()
			lis, err := transport.Listen(ctx, sc.bindEndpoint(t))
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			errCh := make(chan error, 1)
			go func() {
				_, e := lis.Accept()
				errCh <- e
			}()
			time.Sleep(20 * time.Millisecond)
			_ = lis.Close()

			select {
			case e := <-errCh:
				if !errors.Is(e, net.ErrClosed) {
					t.Fatalf("Accept err = %v, want net.ErrClosed", e)
				}
			case <-time.After(time.Second):
				t.Fatalf("Accept did not unblock within 1s")
			}
		})
	}
}

func TestCrossSchemePeerCloseEOF(t *testing.T) {
	for _, sc := range schemes(t) {
		t.Run(sc.name, func(t *testing.T) {
			if sc.skipReason != "" {
				t.Skip(sc.skipReason)
			}
			ctx := context.Background()
			lis, err := transport.Listen(ctx, sc.bindEndpoint(t))
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer lis.Close()

			type p struct {
				c net.Conn
				e error
			}
			ch := make(chan p, 1)
			go func() {
				c, e := lis.Accept()
				ch <- p{c, e}
			}()
			dc, _ := transport.Dial(ctx, sc.dialEndpoint(lis))
			got := <-ch

			_ = dc.Close()
			buf := make([]byte, 4)
			_, err = got.c.Read(buf)
			if err == nil {
				t.Fatalf("Read after peer close = nil, want EOF")
			}
			if !errors.Is(err, io.EOF) {
				t.Fatalf("Read err = %v, want io.EOF", err)
			}
			got.c.Close()
		})
	}
}

func TestCrossSchemeDialAfterClose(t *testing.T) {
	for _, sc := range schemes(t) {
		t.Run(sc.name, func(t *testing.T) {
			if sc.skipReason != "" {
				t.Skip(sc.skipReason)
			}
			ctx := context.Background()
			lis, err := transport.Listen(ctx, sc.bindEndpoint(t))
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			ep := sc.dialEndpoint(lis)
			_ = lis.Close()

			switch sc.name {
			case "tcp", "ipc":
				// Both report a connect-refused or no-such-file error.
				dialCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
				defer cancel()
				dc, derr := transport.Dial(dialCtx, ep)
				if derr == nil {
					dc.Close()
					t.Fatalf("Dial after Close = nil error, want %s-class failure", sc.name)
				}
			case "inproc":
				// Name was released; Dial blocks until ctx fires.
				dialCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
				dc, derr := transport.Dial(dialCtx, ep)
				if derr == nil {
					dc.Close()
					t.Fatalf("inproc Dial after Close = nil error, want context error")
				}
				if !errors.Is(derr, context.DeadlineExceeded) {
					t.Fatalf("inproc Dial err = %v, want context.DeadlineExceeded", derr)
				}
			default:
				t.Fatalf("unknown scheme %q in cross-scheme test", sc.name)
			}
		})
	}
}
