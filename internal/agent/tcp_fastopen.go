package agent

import (
	"os"
	"strconv"
	"strings"

	"github.com/OboardProject/oboard-agent/internal/model"
)

// tcpFastOpenSysctlPath holds the kernel bitmask that decides whether a
// tcp_fast_open socket option has any effect on this host.
const tcpFastOpenSysctlPath = "/proc/sys/net/ipv4/tcp_fastopen"

// detectTCPFastOpen reports the host TCP Fast Open state. The Agent never
// changes the sysctl: TFO interacts with middleboxes and stays opt-in per
// inbound, so the value is only reported so Controller can tell an operator
// that a configured listen option is inert.
func detectTCPFastOpen() (string, int) {
	return tcpFastOpenFromFile(tcpFastOpenSysctlPath)
}

// tcpFastOpenFromFile parses one net.ipv4.tcp_fastopen file. A missing or
// unparsable file is reported as unavailable, which is different from a kernel
// that answers 0 (TFO compiled in but fully disabled).
func tcpFastOpenFromFile(path string) (string, int) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return model.TCPFastOpenStateUnavailable, 0
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || value < 0 {
		return model.TCPFastOpenStateUnavailable, 0
	}
	return model.TCPFastOpenStateFromMask(value), value
}
