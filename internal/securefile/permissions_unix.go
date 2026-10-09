//go:build !windows

package securefile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// Restrict changes only the pinned inode, never a linked destination or an
// inode owned by another account. Callers supply a fixed managed resource.
func Restrict(path string, directory bool) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	parent, err := root.Stat(".")
	if err != nil {
		return err
	}
	owner, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) || parent.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe managed parent")
	}
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSymlink != 0 || (directory && !before.IsDir()) || (!directory && !before.Mode().IsRegular()) {
		return errors.New("unsafe managed resource")
	}
	file, err := root.OpenFile(name, readFlags(), 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || (!directory && stat.Nlink != 1) || !os.SameFile(before, info) {
		return errors.New("managed resource ownership or identity mismatch")
	}
	mode := os.FileMode(0600)
	if directory {
		mode = 0700
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	after, err := file.Stat()
	if err != nil {
		return err
	}
	if after.Mode().Perm() != mode {
		return errors.New("managed permissions not confirmed")
	}
	return file.Sync()
}
