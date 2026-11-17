//go:build !linux

package modules

// btnWatch: button events exist only on OpenWrt (Linux).
func btnWatch() {}

func btnLockEvents() func() { return func() {} }
