package platform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

type linux struct{}

func NewLinux() Platform {
	return &linux{}
}

func (l *linux) GetOSVersion() (string, error) {
	// Try lsb_release first
	cmd := exec.Command("lsb_release", "-rs")
	if output, err := cmd.Output(); err == nil {
		return strings.TrimSpace(string(output)), nil
	}
	// Fallback: parse /etc/os-release
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VERSION_ID=") {
			return strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\""), nil
		}
	}
	return "", fmt.Errorf("could not determine OS version")
}

func (l *linux) RunCommand(ctx context.Context, cmd string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, cmd, args...)
	output, err := c.CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (l *linux) ReadFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (l *linux) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (l *linux) GetFilePermissions(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%o", info.Mode().Perm()), nil
}

func (l *linux) IsRoot() bool {
	u, err := user.Current()
	if err != nil {
		return false
	}
	return u.Uid == "0"
}
