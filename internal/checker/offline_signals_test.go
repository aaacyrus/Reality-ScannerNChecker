package checker

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/aaacyrus/Reality-ScannerNChecker/internal/domain"
)

func TestEmbeddedSignalDataIntegrity(t *testing.T) {
	t.Parallel()
	if len(cruxBloom) != int((cruxBloomBits+7)/8) || cruxBloomCount != 99_946 {
		t.Fatalf("bloom bytes=%d count=%d", len(cruxBloom), cruxBloomCount)
	}
	for _, host := range []string{"openai.com", "github.com", "www.google.com"} {
		if !cruxBloomContains(host) {
			t.Fatalf("embedded CrUX filter lost %q", host)
		}
	}
	wantProviders := map[string]int{"Cloudflare": 15, "CloudFront": 209, "Fastly": 19, "Azure Front Door": 123}
	gotProviders := make(map[string]int)
	for _, rule := range cdnPrefixRules {
		if !rule.prefix.IsValid() || !rule.prefix.Addr().Is4() || rule.prefix != rule.prefix.Masked() {
			t.Fatalf("invalid embedded prefix: %+v", rule)
		}
		gotProviders[rule.provider]++
	}
	for provider, want := range wantProviders {
		if gotProviders[provider] != want {
			t.Errorf("%s prefixes=%d, want %d", provider, gotProviders[provider], want)
		}
	}
}

func TestPopularityClassificationIsExactAndFreshnessAware(t *testing.T) {
	t.Parallel()
	fresh := time.Date(2026, time.July, 23, 0, 0, 0, 0, time.UTC)
	stale := time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)

	known, hot, match := classifyPopularity([]string{"cold-reality-scanner-example.invalid", "OPENAI.COM."}, fresh)
	if !known || !hot || match != "openai.com" {
		t.Fatalf("redirect hit: known=%v hot=%v match=%q", known, hot, match)
	}
	known, hot, _ = classifyPopularity([]string{"www.openai.com"}, fresh)
	if !known || hot {
		t.Fatalf("exact-host miss inherited parent popularity: known=%v hot=%v", known, hot)
	}
	known, hot, _ = classifyPopularity([]string{"cold-reality-scanner-example.invalid"}, stale)
	if known || hot {
		t.Fatalf("stale miss: known=%v hot=%v", known, hot)
	}
	known, hot, match = classifyPopularity([]string{"openai.com"}, stale)
	if !known || !hot || match != "openai.com" {
		t.Fatalf("stale positive signal was lost: known=%v hot=%v match=%q", known, hot, match)
	}
}

func TestCDNEvidenceMatrix(t *testing.T) {
	t.Parallel()
	fresh := time.Date(2026, time.July, 23, 0, 0, 0, 0, time.UTC)
	stale := time.Date(2026, time.August, 4, 0, 0, 0, 0, time.UTC)

	headers := http.Header{"Cf-Ray": {"abc"}, "X-Amz-Cf-Id": {"def"}}
	multiple := classifyCDN(cdnFromHeaders(headers), 3, true, fresh)
	if !multiple.known || !multiple.detected || multiple.provider != "Multiple" || multiple.confidence != "high" {
		t.Fatalf("multiple providers: %+v", multiple)
	}
	single := classifyCDN(cdnFromHeaders(http.Header{"Cf-Ray": {"abc"}}), 0, false, stale)
	if !single.known || !single.detected || single.provider != "Cloudflare" || single.confidence != "medium" {
		t.Fatalf("single strong signal: %+v", single)
	}
	if ignored := cdnFromHeaders(http.Header{"Server": {"cloudflare"}}); len(ignored) != 0 {
		t.Fatalf("weak Server header was treated as proof: %+v", ignored)
	}
	direct := classifyCDN(nil, 2, true, fresh)
	if !direct.known || direct.detected {
		t.Fatalf("fresh direct finding: %+v", direct)
	}
	for name, finding := range map[string]cdnFinding{
		"stale":          classifyCDN(nil, 3, true, stale),
		"one round":      classifyCDN(nil, 1, true, fresh),
		"cname unchecked": classifyCDN(nil, 3, false, fresh),
	} {
		if finding.known {
			t.Errorf("%s no-signal result should be unknown: %+v", name, finding)
		}
	}
}

func TestCDNRulesMatchOnlyExactBoundaries(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"d111.cloudfront.net", "CLOUDFront.NET."} {
		if evidence := cdnFromCNAME(host); len(evidence) != 1 || evidence[0].provider != "CloudFront" {
			t.Fatalf("CNAME %q evidence=%+v", host, evidence)
		}
	}
	if evidence := cdnFromCNAME("cloudfront.net.evil.example"); len(evidence) != 0 {
		t.Fatalf("suffix boundary false positive: %+v", evidence)
	}
	for _, address := range []string{"173.245.48.0", "173.245.63.255"} {
		evidence := cdnFromIP(netip.MustParseAddr(address))
		if len(evidence) != 1 || evidence[0].provider != "Cloudflare" {
			t.Fatalf("IP %s evidence=%+v", address, evidence)
		}
	}
	for _, address := range []string{"173.245.47.255", "173.245.64.0"} {
		if evidence := cdnFromIP(netip.MustParseAddr(address)); len(evidence) != 0 {
			t.Fatalf("adjacent IP %s evidence=%+v", address, evidence)
		}
	}
}

func TestVerifyQualifiedKeepsCDNDecisionPerCandidateIP(t *testing.T) {
	t.Parallel()
	metrics := domain.DirectMetrics{
		TLS: 20 * time.Millisecond, HTTP: 30 * time.Millisecond,
		CertificateDays: 90, Success: true,
	}
	cdnIP := netip.MustParseAddr("1.1.1.1")
	directIP := netip.MustParseAddr("1.1.1.2")
	service := &Service{
		now: func() time.Time { return time.Date(2026, time.July, 23, 0, 0, 0, 0, time.UTC) },
		lookupCNAME: func(_ context.Context, host string) (string, error) { return host, nil },
		validate: func(_ context.Context, candidate domain.Candidate) (validation, error) {
			checked := validation{metrics: metrics}
			if candidate.IP == cdnIP {
				checked.cdn = []cdnEvidence{{layer: cdnLayerHTTP, provider: "Cloudflare", detail: "HTTP強訊號:Cf-Ray"}}
			}
			return checked, nil
		},
	}
	run := domain.RunResult{Qualified: []domain.Result{
		{Candidate: domain.Candidate{IP: cdnIP, SNI: "example.com"}, Analysis: domain.SiteAnalysis{HotKnown: true}, Initial: metrics},
		{Candidate: domain.Candidate{IP: directIP, SNI: "example.com"}, Analysis: domain.SiteAnalysis{HotKnown: true}, Initial: metrics},
	}}

	service.VerifyQualified(context.Background(), &run, nil)

	if len(run.Ranked) != 2 {
		t.Fatalf("ranked=%d", len(run.Ranked))
	}
	for _, result := range run.Ranked {
		switch result.Candidate.IP {
		case cdnIP:
			if !result.Analysis.CDNKnown || !result.Analysis.CDN || result.Score.NoCDN != 0 {
				t.Fatalf("CDN candidate=%+v", result)
			}
		case directIP:
			if !result.Analysis.CDNKnown || result.Analysis.CDN || result.Score.NoCDN != 15 {
				t.Fatalf("direct candidate=%+v", result)
			}
		}
	}
}
