//go:build !unix

package modules

import "io/fs"

// fileOwner cannot be read here; ownership is left as it is. FORK.
func fileOwner(fs.FileInfo) (int, int, bool) { return 0, 0, false }
