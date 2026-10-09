//go:build !windows

package runtimesecurity

import (
	"os"
	"syscall"
)

func unexpectedOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || (stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0)
}

func repairableOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && (info.IsDir() || (info.Mode().IsRegular() && stat.Nlink == 1))
}
func directoryFlags() int {
	return os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_DIRECTORY
}

func unexpectedLinks(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return info.Mode().IsRegular() && (!ok || stat.Nlink != 1)
}
