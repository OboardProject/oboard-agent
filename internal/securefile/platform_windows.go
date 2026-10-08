package securefile

import "os"

func readFlags() int { return os.O_RDONLY }

// Windows does not expose directory fsync through os.File. The file itself is
// flushed before publishing; inspection does not claim POSIX durability there.
func syncDirectory(*os.Root) error { return nil }
