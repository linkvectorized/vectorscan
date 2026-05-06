package platform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type windows struct{}

func NewWindows() Platform {
	return &windows{}
}

func (w *windows) GetOSVersion() (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-WmiObject Win32_OperatingSystem).Caption + ' ' + (Get-WmiObject Win32_OperatingSystem).Version")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to cmd /c ver
		cmd2 := exec.Command("cmd", "/c", "ver")
		out2, err2 := cmd2.Output()
		if err2 != nil {
			return "", fmt.Errorf("cannot determine OS version")
		}
		return strings.TrimSpace(string(out2)), nil
	}
	return strings.TrimSpace(string(output)), nil
}

func (w *windows) RunCommand(ctx context.Context, cmd string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, cmd, args...)
	output, err := c.CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (w *windows) ReadFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (w *windows) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (w *windows) GetFilePermissions(path string) (string, error) {
	cmd := exec.Command("icacls", path)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("icacls failed: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func (w *windows) IsRoot() bool {
	// net session requires Administrator or Server Operator privilege
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}
