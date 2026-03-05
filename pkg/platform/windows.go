package platform

import "context"

type windows struct{}

func NewWindows() Platform {
	return &windows{}
}

func (w *windows) GetOSVersion() (string, error) {
	// TODO: Implement
	return "", nil
}

func (w *windows) RunCommand(ctx context.Context, cmd string, args ...string) (string, error) {
	// TODO: Implement
	return "", nil
}

func (w *windows) ReadFile(path string) (string, error) {
	// TODO: Implement
	return "", nil
}

func (w *windows) FileExists(path string) bool {
	// TODO: Implement
	return false
}

func (w *windows) GetFilePermissions(path string) (string, error) {
	// TODO: Implement
	return "", nil
}

func (w *windows) IsRoot() bool {
	// TODO: Implement
	return false
}
