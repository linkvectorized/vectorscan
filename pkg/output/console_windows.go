//go:build windows

package output

import (
	"os"
	"syscall"
	"unsafe"
)

func init() {
	enableVirtualTerminalProcessing()
}

// enableVirtualTerminalProcessing enables ANSI escape sequence support
// on Windows 10 1511+ consoles. Without this, colored output is garbled.
func enableVirtualTerminalProcessing() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")

	const enableVTP = 0x0004

	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		handle := syscall.Handle(f.Fd())
		var mode uint32
		r, _, _ := getConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
		if r == 0 {
			continue // not a console handle (e.g., piped to file)
		}
		setConsoleMode.Call(uintptr(handle), uintptr(mode|enableVTP))
	}
}
