package runtimesecurity

import "os"

func unexpectedOwner(os.FileInfo) bool { return false }

func repairableOwner(os.FileInfo) bool { return false }
func directoryFlags() int              { return os.O_RDONLY }

func unexpectedLinks(os.FileInfo) bool { return false }
