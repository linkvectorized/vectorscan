package platform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

type macOS struct{}

// NewMacOS creates a new macOS platform handler
func NewMacOS() Platform {
	return &macOS{}
}

// GetOSVersion returns the macOS version
func (m *macOS) GetOSVersion() (string, error) {
	cmd := exec.Command("sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// RunCommand executes a shell command and returns output
func (m *macOS) RunCommand(ctx context.Context, cmd string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, cmd, args...)
	output, err := c.CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// ReadFile reads a file and returns its contents
func (m *macOS) ReadFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FileExists checks if a file exists
func (m *macOS) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GetFilePermissions returns file permissions in octal format
func (m *macOS) GetFilePermissions(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%o", info.Mode().Perm()), nil
}

// IsRoot checks if running as root
func (m *macOS) IsRoot() bool {
	u, err := user.Current()
	if err != nil {
		return false
	}
	return u.Uid == "0"
}
