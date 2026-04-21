package subprocrunner

import (
	"fmt"
	"net"
)

// PickFreePort binds 127.0.0.1:0 briefly, records the OS-assigned port,
// closes the listener, and returns the port for caller use. Good enough
// for test isolation on a single host. Returns (0, err) on listen failure.
//
// Note: technically racy — between the listener close and the caller
// using the port, another process could bind it. For validator-driven
// subprocess spawns (single-process caller, sequential spawns) this is
// reliable in practice. For parallel-across-hosts harnesses, use
// OS-level port reservation or bind-and-pass-fd.
func PickFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("pick free port: %w", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port, nil
}
