package netdiag

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

// GoogleRegionURL is the only page the Google region probe fetches. YouTube
// Premium embeds the country Google's geolocation assigns to the requesting
// address, which is the same decision that redirects China-located addresses
// to google.cn.
const GoogleRegionURL = "https://www.youtube.com/premium"

const (
	googleRegionBodyLimit = 1 << 20
	googleRegionTimeout   = 15 * time.Second
	googleRegionUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	googleRegionCookie    = "CONSENT=YES+cb.20220301-11-p0.en+FX+700; SOCS=CAI"
)

var (
	googleRegionPattern = regexp.MustCompile(`"INNERTUBE_CONTEXT_GL"\s*:\s*"([A-Z]{2})"`)
	googleRegionHosts   = map[string]bool{"www.youtube.com": true, "youtube.com": true, "m.youtube.com": true, "consent.youtube.com": true, "www.google.cn": true}
)

// GoogleRegion fetches the fixed YouTube Premium page from this server and
// returns the country it was served as. The body is read up to 1 MiB, scanned
// for the region marker and discarded; nothing else from it is returned.
func GoogleRegion(ctx context.Context, resolver Resolver, dialer Dialer, p model.GoogleRegionTaskPayload) (model.GoogleRegionResult, error) {
	result := model.GoogleRegionResult{OperationID: p.OperationID}
	if p.IPFamily != model.NetworkFamilyIPv4 && p.IPFamily != model.NetworkFamilyIPv6 {
		return result, invalid("ip_family must be ipv4 or ipv6")
	}
	probeCtx, cancel := context.WithTimeout(ctx, googleRegionTimeout)
	defer cancel()
	transport := &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: googleRegionTimeout,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ip, err := ResolveTarget(ctx, resolver, host, p.IPFamily)
			if err != nil {
				return nil, err
			}
			if result.ResolvedIP == "" {
				result.ResolvedIP = ip.String()
			}
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if len(via) > model.HTTPProbeMaxRedirects {
			return errors.New("too many redirects")
		}
		if next.URL.Scheme != "https" || !googleRegionHosts[strings.ToLower(next.URL.Hostname())] {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, GoogleRegionURL, nil)
	if err != nil {
		return result, err
	}
	request.Header.Set("User-Agent", googleRegionUserAgent)
	request.Header.Set("Accept-Language", "en")
	request.Header.Set("Cookie", googleRegionCookie)
	response, err := client.Do(request)
	if err != nil {
		var diag *Error
		if errors.As(err, &diag) && diag.Code == model.NetworkDiagnosticCodeTargetNotAllowed {
			return result, diag
		}
		result.ErrorClass = errorClass(err)
		return result, nil
	}
	defer response.Body.Close()
	result.StatusCode = response.StatusCode
	body, err := io.ReadAll(io.LimitReader(response.Body, googleRegionBodyLimit))
	if err != nil && len(body) == 0 {
		result.ErrorClass = errorClass(err)
		return result, nil
	}
	result.CountryCode = googleRegionFromPage(response.Request.URL.Hostname(), body)
	result.SentToChina = result.CountryCode == "CN"
	if result.CountryCode == "" {
		result.ErrorClass = "region_unknown"
	}
	return result, nil
}

func googleRegionFromPage(host string, body []byte) string {
	if strings.EqualFold(host, "www.google.cn") {
		return "CN"
	}
	if match := googleRegionPattern.FindSubmatch(body); match != nil {
		return string(match[1])
	}
	if strings.Contains(string(body), "www.google.cn") {
		return "CN"
	}
	return ""
}
