//go:build linux

package modules

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// btnWatch notifies what the runner ran. It blocks in the kernel (inotify
// on the runner's state directory) until the runner writes its log, so it
// costs nothing between presses.
func btnWatch() {
	for {
		if err := btnWatchRun(); err != nil {
			log.Printf("netgrip: buttons watch: %v", err)
			time.Sleep(time.Minute)
			continue
		}
		// The directory went away (/tmp cleaned): watch the new one now.
		time.Sleep(time.Second)
	}
}

func btnWatchRun() error {
	if !btnStateDirSafe() {
		return fmt.Errorf("%s is not a safe directory", btnStateDir)
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	// The log is appended to (close after write) or replaced when trimmed
	// (moved in); the directory going away (it lives in /tmp) ends the
	// watch, and the loop starts a new one.
	if _, err := unix.InotifyAddWatch(fd, btnStateDir, unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF); err != nil {
		return err
	}
	btnHandleRequests() // stale ones, from before NetGrip started
	btnNotifyNew()      // what ran while NetGrip was not running
	buf := make([]byte, 4096)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		relevant, gone, requests := false, false, false
		for off := 0; off+unix.SizeofInotifyEvent <= n; {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
			nameLen := int(ev.Len)
			name := ""
			if nameLen > 0 {
				raw := buf[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+nameLen]
				for i, c := range raw {
					if c == 0 {
						raw = raw[:i]
						break
					}
				}
				name = string(raw)
			}
			if ev.Mask&(unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_IGNORED) != 0 {
				gone = true
			}
			// An overflow lost events: read the log anyway.
			if name == "events" || ev.Mask&unix.IN_Q_OVERFLOW != 0 {
				relevant = true
			}
			if strings.HasPrefix(name, "request.") || ev.Mask&unix.IN_Q_OVERFLOW != 0 {
				requests = true
			}
			off += unix.SizeofInotifyEvent + nameLen
		}
		if requests {
			btnHandleRequests() // logs an event: the next read notifies it
		}
		if relevant {
			btnNotifyNew()
		}
		if gone {
			return nil
		}
	}
}

// btnLockEvents takes the runner's lock on its event log (flock, as the
// runner uses where it has flock).
func btnLockEvents() func() {
	f, err := os.OpenFile(btnStateDir+"/events.lock", os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return func() {}
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_EX)
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}
}

// btnNoFollow: opens never follow a link planted in the state directory.
const btnNoFollow = syscall.O_NOFOLLOW

// btnStateDirSafe makes sure the runner's state directory (in /tmp) is a
// real directory owned by this process's user and writable by nobody else,
// creating it if missing and recreating it otherwise: someone else's
// directory could feed NetGrip requests (pause the quarantine) or point
// its writes elsewhere with links.
func btnStateDirSafe() bool {
	ok := func() bool {
		st, err := os.Lstat(btnStateDir)
		if err != nil {
			return false
		}
		sys, isSys := st.Sys().(*syscall.Stat_t)
		return st.IsDir() && st.Mode()&os.ModeSymlink == 0 && st.Mode().Perm()&0o022 == 0 &&
			isSys && int(sys.Uid) == os.Geteuid()
	}
	if ok() {
		return true
	}
	if _, err := os.Lstat(btnStateDir); err == nil {
		log.Printf("netgrip: buttons: %s is not NetGrip's own directory; recreating it", btnStateDir)
		// RemoveAll removes a link itself, not what it points to.
		if err := os.RemoveAll(btnStateDir); err != nil {
			return false
		}
	}
	_ = os.MkdirAll(filepath.Dir(btnStateDir), 0o755) // /tmp on a router
	if err := os.Mkdir(btnStateDir, 0o755); err != nil && !os.IsExist(err) {
		return false
	}
	_ = os.Chmod(btnStateDir, 0o755)
	return ok()
}

// btnReadOwned reads a small regular file this process's user owns,
// without following a link or blocking on a pipe.
func btnReadOwned(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	sys, isSys := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || !isSys || int(sys.Uid) != os.Geteuid() || st.Size() > max {
		return nil, fmt.Errorf("%s is not a request file", filepath.Base(path))
	}
	buf := make([]byte, st.Size())
	n, err := f.Read(buf)
	if err != nil && n == 0 && st.Size() > 0 {
		return nil, err
	}
	return buf[:n], nil
}
