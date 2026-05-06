package inproc

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
)

func TestRaceDetectorClean(t *testing.T) {
	const cycles = 100
	const dialers = 4
	ctx := context.Background()

	for c := range cycles {
		name := "test/race/" + t.Name() + "/" + strconv.Itoa(c)
		var wg sync.WaitGroup

		dialChan := make(chan net.Conn, dialers)
		for range dialers {
			wg.Go(func() {
				dc, err := Dial(ctx, name)
				if err != nil {
					return
				}
				dialChan <- dc
			})
		}

		lis, err := Listen(ctx, name)
		if err != nil {
			t.Fatalf("[%d] Listen: %v", c, err)
		}

		// Accept drainers.
		var accepted []net.Conn
		var amu sync.Mutex
		var awg sync.WaitGroup
		for range dialers {
			awg.Go(func() {
				ac, err := lis.Accept()
				if err != nil {
					return
				}
				amu.Lock()
				accepted = append(accepted, ac)
				amu.Unlock()
			})
		}

		wg.Wait()
		close(dialChan)
		_ = lis.Close()
		// Closing should unblock any still-parked Accepts.
		awg.Wait()

		for ac := range accepted {
			_ = accepted[ac].Close()
		}
		for dc := range dialChan {
			_ = dc.Close()
		}
	}
}
