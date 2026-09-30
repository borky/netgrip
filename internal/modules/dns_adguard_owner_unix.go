//go:build unix

package modules

import (
	"io/fs"
	"syscall"
)

// fileOwner is fi's owning user and group. FORK.
func fileOwner(fi fs.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
