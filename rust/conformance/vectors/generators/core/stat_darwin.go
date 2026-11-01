//go:build core_vectors && darwin

package main

import (
	"os"
	"syscall"
)

func statFields(info os.FileInfo) directPlayOut {
	s := info.Sys().(*syscall.Stat_t)
	return directPlayOut{uint64(s.Dev), s.Ino, s.Ctimespec.Sec, s.Ctimespec.Nsec, info.ModTime().UnixNano(), info.Size(), "darwin", "", ""}
}
