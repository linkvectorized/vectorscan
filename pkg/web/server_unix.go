//go:build !windows

package web

import (
	"os"
	"os/signal"
	"syscall"
)

// detachTerminal makes the process survive terminal closure by ignoring SIGHUP.
// Note: syscall.Setsid() fails with EPERM when the process is a group leader (typical).
func detachTerminal() {
	signal.Ignore(syscall.SIGHUP)
}

// platformSignals returns the OS signals to catch for graceful shutdown.
func platformSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}
