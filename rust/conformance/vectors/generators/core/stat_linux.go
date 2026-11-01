//go:build core_vectors && linux

package main

import (
	"os"
	"syscall"
)

func statFields(info os.FileInfo) directPlayOut {
	s := info.Sys().(*syscall.Stat_t)
	return directPlayOut{uint64(s.Dev), s.Ino, int64(s.Ctim.Sec), int64(s.Ctim.Nsec), info.ModTime().UnixNano(), info.Size(), "linux", "", ""}
}
