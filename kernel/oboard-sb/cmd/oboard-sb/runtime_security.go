package main

import (
	"encoding/json"
	"errors"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/runtimeguard"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/stealth"
	"io"
	"os"
	"path/filepath"
)

func applyRuntimeSecurityPolicy(config string, key []byte) error {
	path := kernelStatePath(config, key, "runtime-security.json")
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Lstat(filepath.Base(path))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("unsafe runtime security policy")
	}
	file, err := root.OpenFile(filepath.Base(path), managedPolicyReadFlags(), 0)
	if err != nil {
		return err
	}
	defer file.Close()
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) {
		return errors.New("runtime security policy changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) > 4096 {
		return errors.New("invalid runtime security policy")
	}
	if len(key) > 0 {
		raw, err = stealth.Decrypt(key, raw)
		if err != nil {
			return err
		}
	}
	var policy struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		return err
	}
	if policy.Mode != "standard" && policy.Mode != "enhanced" {
		return errors.New("invalid runtime security policy mode")
	}
	return runtimeguard.Apply(policy.Mode)
}
