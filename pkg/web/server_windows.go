//go:build windows

package web

import "os"

// detachTerminal is a no-op on Windows.
func detachTerminal() {}

// platformSignals returns the OS signals to catch for graceful shutdown.
func platformSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
