package platform

import "context"

// Platform is the interface for OS-specific operations
type Platform interface {
	GetOSVersion() (string, error)
	RunCommand(ctx context.Context, cmd string, args ...string) (string, error)
	ReadFile(path string) (string, error)
	FileExists(path string) bool
	GetFilePermissions(path string) (string, error)
	IsRoot() bool
}
