//go:build !linux

package modules

import (
	"errors"
	"os"
)

// btnWatch: button events exist only on OpenWrt (Linux).
func btnWatch() {}

func btnLockEvents() func() { return func() {} }

const btnNoFollow = 0

func btnStateDirSafe() bool { return os.MkdirAll(btnStateDir, 0o755) == nil }

func btnReadOwned(path string, max int64) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil && int64(len(data)) > max {
		return nil, errors.New("request too large")
	}
	return data, err
}
