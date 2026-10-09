// Package securefile provides confined, atomic writes for managed local state.
package securefile

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Write pins the parent directory for the entire operation. Rename replaces
// directory entries, never follows a destination symlink, and publishes only a
// complete file. Callers choose whether the crash boundary requires fsync.
func Write(path string, data []byte, mode os.FileMode, sync bool) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(path)
	if info, err := root.Lstat(name); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("managed state destination is not a regular file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := ".state-" + hex.EncodeToString(nonce[:]) + ".tmp"
	file, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if sync {
		if err := file.Sync(); err != nil {
			return err
		}
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmp, name); err != nil {
		return err
	}
	if sync {
		return syncDirectory(root)
	}
	return nil
}

// Read refuses links and changed inodes before reading any bytes. The limit is
// enforced on both metadata and actual reads, including virtual files.
func Read(path string, limit int64) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > limit {
		return nil, errors.New("unsafe or oversized managed file")
	}
	file, err := root.OpenFile(name, readFlags(), 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
		return nil, errors.New("managed file changed during open")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("managed file exceeds size limit")
	}
	return raw, nil
}

// OpenAppend opens only a regular managed log and repairs its access mode.
func OpenAppend(path string) (*os.File, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.OpenFile(filepath.Base(path), readFlags()|os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("unsafe managed log")
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

// Remove persists removal of a completed recovery journal.
func Remove(path string) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Remove(filepath.Base(path)); err != nil {
		return err
	}
	return syncDirectory(root)
}

// Digest streams one regular file with a fixed memory and byte budget. It
// detects replacement or modification during inspection and never follows links.
func Digest(ctx context.Context, path string, limit int64) (string, int64, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return "", 0, err
	}
	defer root.Close()
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil {
		return "", 0, err
	}
	if !before.Mode().IsRegular() || before.Size() > limit {
		return "", 0, errors.New("unsafe or oversized binary")
	}
	file, err := root.OpenFile(name, readFlags(), 0)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return "", 0, errors.New("binary changed")
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		n, err := file.Read(buffer)
		total += int64(n)
		if total > limit {
			return "", 0, errors.New("binary exceeds budget")
		}
		hash.Write(buffer[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", 0, err
		}
	}
	after, err := root.Lstat(name)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", 0, errors.New("binary changed")
	}
	return hex.EncodeToString(hash.Sum(nil)), total, nil
}
