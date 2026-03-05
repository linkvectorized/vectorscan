package platform

import "context"

type linux struct{}

func NewLinux() Platform {
	return &linux{}
}

func (l *linux) GetOSVersion() (string, error) {
	// TODO: Implement
	return "", nil
}

func (l *linux) RunCommand(ctx context.Context, cmd string, args ...string) (string, error) {
	// TODO: Implement
	return "", nil
}

func (l *linux) ReadFile(path string) (string, error) {
	// TODO: Implement
	return "", nil
}

func (l *linux) FileExists(path string) bool {
	// TODO: Implement
	return false
}

func (l *linux) GetFilePermissions(path string) (string, error) {
	// TODO: Implement
	return "", nil
}

func (l *linux) IsRoot() bool {
	// TODO: Implement
	return false
}
