package runtimesecurity

import "os"

func unexpectedOwner(os.FileInfo) bool { return false }
