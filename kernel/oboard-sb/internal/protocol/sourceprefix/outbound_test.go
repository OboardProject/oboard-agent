// SPDX-License-Identifier: GPL-3.0-or-later

package sourceprefix

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParsePrefixCanonicalizesNetwork(t *testing.T) {
	prefix, err := parsePrefix(" 2401:b60:3c:6b::a/64 ")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := prefix.String(), "2401:b60:3c:6b::/64"; got != want {
		t.Fatalf("prefix = %q, want %q", got, want)
	}
}

func TestSelectSourceFromAddresses(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8:2::/64")
	addresses := []netip.Addr{
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("2001:db8:3::1"),
		netip.MustParseAddr("2001:db8:2::20"),
		netip.MustParseAddr("2001:db8:2::10"),
	}
	got, err := selectSourceFromAddresses(prefix, addresses)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddr("2001:db8:2::10"); got != want {
		t.Fatalf("source = %s, want %s", got, want)
	}
}

func TestSelectSourceFailsClosedWithoutMatch(t *testing.T) {
	_, err := selectSourceFromAddresses(
		netip.MustParsePrefix("198.51.100.0/24"),
		[]netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("127.0.0.1")},
	)
	if err == nil || !strings.Contains(err.Error(), "no active global-unicast address") {
		t.Fatalf("expected no-match error, got %v", err)
	}
}
