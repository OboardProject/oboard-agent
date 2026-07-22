package agent

import "testing"

func TestParseEgressRegionCodeCloudflareTrace(t *testing.T) {
	got := parseEgressRegionCode([]byte("fl=1\nip=203.0.113.1\nloc=hk\ntls=TLSv1.3\n"))
	if got != "HK" {
		t.Fatalf("parseEgressRegionCode() = %q, want HK", got)
	}
}

func TestParseEgressRegionCodeGeoIPJSON(t *testing.T) {
	got := parseEgressRegionCode([]byte(`{"ip":"203.0.113.1","country_code":"tw"}`))
	if got != "TW" {
		t.Fatalf("parseEgressRegionCode() = %q, want TW", got)
	}
}

func TestParseEgressRegionCodeRejectsInvalidValues(t *testing.T) {
	for _, body := range [][]byte{
		[]byte("loc=UNKNOWN\n"),
		[]byte(`{"country_code":"CHN"}`),
		[]byte(`{"country_code":"1A"}`),
	} {
		if got := parseEgressRegionCode(body); got != "" {
			t.Fatalf("parseEgressRegionCode(%q) = %q, want empty", body, got)
		}
	}
}
