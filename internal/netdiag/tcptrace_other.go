//go:build !linux

package netdiag

// TCPTracer is nil where TTL-limited TCP probes are not implemented.
var TCPTracer tcpTracer
