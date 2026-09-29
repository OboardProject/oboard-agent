//go:build !linux && !darwin

package netdiag

// OpenRawTransport is unavailable where the Agent does not implement raw
// ICMP probing; ping and trace report unsupported instead of falling back
// to any external program.
func OpenRawTransport(bool) (probeTransport, error) { return nil, ErrUnsupported }
