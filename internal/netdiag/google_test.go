package netdiag

import (
	"context"
	"net/netip"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestGoogleRegionFromPage(t *testing.T) {
	for _, tc := range []struct {
		host, body, want string
	}{
		{"www.youtube.com", `ytcfg.set({"INNERTUBE_CONTEXT_GL":"SG","INNERTUBE_CONTEXT_HL":"en"})`, "SG"},
		{"www.youtube.com", `{"INNERTUBE_CONTEXT_GL" : "CN"}`, "CN"},
		{"www.youtube.com", `<a href="https://www.google.cn/">`, "CN"},
		{"www.google.cn", ``, "CN"},
		{"consent.youtube.com", `<form>`, ""},
		{"www.youtube.com", `"INNERTUBE_CONTEXT_GL":"usa"`, ""},
	} {
		if got := googleRegionFromPage(tc.host, []byte(tc.body)); got != tc.want {
			t.Fatalf("%s %q: got %q, want %q", tc.host, tc.body, got, tc.want)
		}
	}
}

func TestGoogleRegionRefusesPrivateResolutionAndBadFamily(t *testing.T) {
	payload := model.GoogleRegionTaskPayload{NetworkDiagnosticEnvelope: envelope(), IPFamily: model.NetworkFamilyIPv4}
	resolver := fakeResolver{"www.youtube.com": {netip.MustParseAddr("10.0.0.8")}}
	if _, err := GoogleRegion(context.Background(), resolver, &fakeDialer{target: "127.0.0.1:1"}, payload); CodeOf(err) != model.NetworkDiagnosticCodeTargetNotAllowed {
		t.Fatalf("a private answer for the fixed host must be refused, got %v", err)
	}
	payload.IPFamily = model.NetworkFamilyAuto
	if _, err := GoogleRegion(context.Background(), resolver, &fakeDialer{target: "127.0.0.1:1"}, payload); CodeOf(err) != model.NetworkDiagnosticCodeInvalidInput {
		t.Fatalf("auto family must be refused, got %v", err)
	}
}
