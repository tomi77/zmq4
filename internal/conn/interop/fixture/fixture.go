//go:build interop

// Package fixture spins up a libzmq ZMQ_PAIR peer in a Docker
// container for F4 interop tests. Build tag interop ensures it is
// excluded from default test runs.
package fixture

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Role identifies the libzmq side's role in the pair.
type Role string

const (
	RoleDialer   Role = "dialer"
	RoleListener Role = "listener"
)

// Mechanism is the wire mechanism name.
type Mechanism string

const (
	MechNULL  Mechanism = "NULL"
	MechPLAIN Mechanism = "PLAIN"
	MechCURVE Mechanism = "CURVE"
)

// Scenario describes what the libzmq peer does after the socket opens.
type Scenario string

const (
	ScenarioHandshake Scenario = "handshake"
	ScenarioSingle    Scenario = "single"    // echo: recv 1, send 1.
	ScenarioMultipart Scenario = "multipart" // echo: recv N parts, send N parts.
)

// Spec describes one libzmq peer to spawn.
type Spec struct {
	Role      Role
	Endpoint  string // "tcp://127.0.0.1:0" or "ipc:///shared/zmq.sock" (resolved-port endpoint returned via Peer.ResolvedEndpoint).
	Mechanism Mechanism
	Scenario  Scenario

	// IPCBindMountHost: when scheme is ipc, the path on the host that
	// must be bind-mounted into the container at the same location so
	// the UDS is visible to both sides. Ignored for tcp.
	IPCBindMountHost string

	PLAIN PlainParams
	CURVE CurveParams
}

type PlainParams struct {
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
}

type CurveParams struct {
	ServerKey string `json:"server_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	IsServer  bool   `json:"is_server"`
}

// Peer is a running libzmq peer process. ResolvedEndpoint holds the
// wildcard-replaced address (for tcp://*:0). Wait blocks until the
// scenario completes; Stop kills the process if the test wants to
// abort early.
type Peer struct {
	ResolvedEndpoint string

	cmd *exec.Cmd

	stdoutBuf *strings.Builder
	stdoutMu  sync.Mutex

	waitOnce sync.Once
	waitErr  error
}

// Start launches the libzmq bridge container with spec piped to stdin.
// Blocks until the bridge prints "READY <endpoint>" on stdout. Returns
// a Peer whose ResolvedEndpoint is the address callers should use.
//
// Linux-only: --network=host (host networking) and host bind-mounts
// for ipc do not behave as expected on Docker Desktop (macOS/Windows).
// On non-Linux hosts this function calls t.Skipf with a clear message.
//
// t.Cleanup automatically stops the peer at test end.
func Start(t *testing.T, spec Spec) *Peer {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Skipf("interop fixture requires Linux (--network=host + host bind-mount for ipc); GOOS=%s", runtime.GOOS)
	}

	cfg := map[string]any{
		"role":      string(spec.Role),
		"endpoint":  spec.Endpoint,
		"mechanism": string(spec.Mechanism),
		"scenario":  string(spec.Scenario),
		"plain":     spec.PLAIN,
		"curve":     spec.CURVE,
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}

	dockerArgs := []string{"run", "--rm", "-i", "--network=host"}
	if spec.IPCBindMountHost != "" {
		// Bind-mount the UDS directory so both bridge (in container)
		// and our F4 side (on host) see the same socket file.
		dockerArgs = append(dockerArgs,
			"-v", fmt.Sprintf("%s:%s", spec.IPCBindMountHost, spec.IPCBindMountHost))
	}
	dockerArgs = append(dockerArgs, "zmq4-interop-bridge:latest")

	cmd := exec.Command("docker", dockerArgs...)
	cmd.Stdin = strings.NewReader(string(cfgJSON) + "\n")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Skipf("docker not available: %v", err) // skip rather than fail when Docker is missing.
	}

	p := &Peer{cmd: cmd, stdoutBuf: &strings.Builder{}}

	// Read stdout in a goroutine; capture all lines for diagnostics
	// and signal once we see READY.
	readyCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			p.stdoutMu.Lock()
			p.stdoutBuf.WriteString(line)
			p.stdoutBuf.WriteString("\n")
			p.stdoutMu.Unlock()
			if strings.HasPrefix(line, "READY ") {
				select {
				case readyCh <- strings.TrimPrefix(line, "READY "):
				default:
				}
			}
		}
	}()
	go func() { _, _ = io.Copy(io.Discard, stderr) }() // drain stderr; Wait() will surface via ExitError.

	select {
	case ep := <-readyCh:
		p.ResolvedEndpoint = ep
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		p.stdoutMu.Lock()
		out := p.stdoutBuf.String()
		p.stdoutMu.Unlock()
		t.Fatalf("libzmq bridge did not signal READY within 15 s; stdout: %s", out)
	}

	t.Cleanup(func() { p.Stop() })
	return p
}

// doWait calls cmd.Wait exactly once (sync.Once) and caches the result.
// Prevents double-Wait when both Wait() and Stop() are called.
func (p *Peer) doWait() error {
	p.waitOnce.Do(func() { p.waitErr = p.cmd.Wait() })
	return p.waitErr
}

// Wait blocks until the bridge exits and returns its exit error (nil
// on success). Tests that exercise scenarios call this after they
// finish driving the F4 side, to verify the peer also saw clean
// completion.
func (p *Peer) Wait(t *testing.T, timeout time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- p.doWait() }()
	select {
	case err := <-done:
		if err != nil {
			p.stdoutMu.Lock()
			out := p.stdoutBuf.String()
			p.stdoutMu.Unlock()
			t.Fatalf("libzmq bridge exited with error: %v; stdout: %s", err, out)
		}
	case <-time.After(timeout):
		p.stdoutMu.Lock()
		out := p.stdoutBuf.String()
		p.stdoutMu.Unlock()
		t.Fatalf("libzmq bridge did not exit within %v; stdout: %s", timeout, out)
	}
}

// Stop kills the bridge process if it is still running. Idempotent.
func (p *Peer) Stop() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	_ = p.doWait()
}

// Stdout returns the accumulated stdout for diagnostics.
func (p *Peer) Stdout() string {
	p.stdoutMu.Lock()
	defer p.stdoutMu.Unlock()
	return p.stdoutBuf.String()
}

// PairMetadata returns the wire.Metadata that both peers must inject
// to keep libzmq happy (it requires Socket-Type to be set).
func PairMetadata() (name, value []byte) {
	return []byte("Socket-Type"), []byte("PAIR")
}

// EnsureDockerImage checks that the bridge image exists locally and
// builds it if missing. Called by TestInteropHappyPath before the
// matrix runs.
func EnsureDockerImage(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("interop fixture requires Linux; GOOS=%s", runtime.GOOS)
	}
	out, err := exec.Command("docker", "image", "inspect", "zmq4-interop-bridge:latest").CombinedOutput()
	if err == nil {
		return
	}
	t.Logf("zmq4-interop-bridge:latest not present (%s); building", strings.TrimSpace(string(out)))
	build := exec.Command("docker", "build",
		"-t", "zmq4-interop-bridge:latest",
		"-f", "Dockerfile",
		"bridge")
	out, err = build.CombinedOutput()
	if err != nil {
		t.Skipf("cannot build interop image: %v\n%s", err, out)
	}
}
