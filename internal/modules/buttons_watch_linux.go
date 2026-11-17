//go:build linux

package modules

import (
	"log"
	"os"
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
		}
		time.Sleep(time.Minute)
	}
}

func btnWatchRun() error {
	if err := os.MkdirAll(btnStateDir, 0o755); err != nil {
		return err
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
	btnNotifyNew() // what ran while NetGrip was not running
	buf := make([]byte, 4096)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		relevant, gone := false, false
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
			if name == "events" {
				relevant = true
			}
			off += unix.SizeofInotifyEvent + nameLen
		}
		if relevant {
			btnNotifyNew()
		}
		if gone {
			return nil
		}
	}
}
