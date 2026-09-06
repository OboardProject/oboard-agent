package restrictedtarget

import (
	"net/netip"
)

// Public is the restricted SSH relay's existing destination boundary.
func Public(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback()
}
