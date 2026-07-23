package ui

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/aaacyrus/Reality-ScannerNChecker/internal/domain"
	"github.com/aaacyrus/Reality-ScannerNChecker/internal/i18n"
)

func TestRankingTableContainsEveryMetric(t *testing.T) {
	t.Parallel()
	result := domain.Result{
		Candidate: domain.Candidate{IP: netip.MustParseAddr("1.1.1.1"), SNI: "example.com"},
		Analysis: domain.SiteAnalysis{
			CDNKnown: true, HotKnown: true, CountryCode: "US", CountryNameEN: "United States", CountryNameZH: "美國",
		},
		Median: domain.DirectMetrics{
			TCP: 10 * time.Millisecond, TLS: 20 * time.Millisecond, HTTP: 30 * time.Millisecond,
			TLS13: true, X25519: true, HTTP2: true, SNIValid: true, CertificateDays: 90,
		},
		Rounds: []domain.DirectMetrics{{Success: true}, {Success: true}, {Success: true}},
		Score:  domain.ScoreBreakdown{Stability: 30, TLS: 25, HTTP: 15, NoCDN: 15, NotHot: 10, Domain: 5, Certificate: 5},
	}
	output := RankingTable([]domain.Result{result}, i18n.Translator{Language: domain.LanguageEnglish})
	for _, expected := range []string{"1.1.1.1", "example.com", "105", "3/3", "10ms", "20ms", "30ms", "TLS1.3", "X25519", "H2", "CERT DAYS", "US"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("table does not contain %q:\n%s", expected, output)
		}
	}
}

func TestStyledRankingTableAddsSemanticColor(t *testing.T) {
	result := domain.Result{
		Candidate: domain.Candidate{IP: netip.MustParseAddr("1.1.1.1"), SNI: "example.com"},
		Median: domain.DirectMetrics{
			TCP: 10 * time.Millisecond, TLS: 20 * time.Millisecond, HTTP: 30 * time.Millisecond,
			TLS13: true, X25519: true, HTTP2: true, SNIValid: true,
		},
		Rounds: []domain.DirectMetrics{{Success: true}, {Success: true}, {Success: true}},
		Score:  domain.ScoreBreakdown{Stability: 30, TLS: 25, HTTP: 15, NoCDN: 15, NotHot: 10, Domain: 5, Certificate: 5},
	}
	output := RankingTableStyled([]domain.Result{result}, i18n.Translator{Language: domain.LanguageEnglish}, true)
	for _, expected := range []string{"\x1b[", "★ 1", "105", "✓"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("styled table does not contain %q:\n%s", expected, output)
		}
	}
}

func TestDetailLocalizesOfflineCDNAndPopularityEvidence(t *testing.T) {
	t.Parallel()
	result := domain.Result{
		Candidate: domain.Candidate{IP: netip.MustParseAddr("1.1.1.1"), SNI: "openai.com"},
		Analysis: domain.SiteAnalysis{
			CDNKnown: true, CDN: true, CDNProvider: "Cloudflare", CDNConfidence: "high", CDNEvidence: "HTTP強訊號:Cf-Ray；CNAME特徵:cdn.cloudflare.net",
			HotKnown: true, HotWebsite: true, HotSnapshot: "202606", HotMatch: "openai.com",
		},
	}
	english := Detail(result, i18n.Translator{Language: domain.LanguageEnglish})
	for _, expected := range []string{"Strong HTTP signal: Cf-Ray; CNAME signal: cdn.cloudflare.net", "matched embedded CrUX Top 100k (202606): openai.com"} {
		if !strings.Contains(english, expected) {
			t.Fatalf("English detail does not contain %q:\n%s", expected, english)
		}
	}
	traditionalChinese := Detail(result, i18n.Translator{Language: domain.LanguageTraditionalChinese})
	for _, expected := range []string{"HTTP強訊號:Cf-Ray", "命中內建 CrUX Top 100k（202606）：openai.com"} {
		if !strings.Contains(traditionalChinese, expected) {
			t.Fatalf("Traditional Chinese detail does not contain %q:\n%s", expected, traditionalChinese)
		}
	}
}

func TestDetailExplainsOfflineUnknownAndNegativeResults(t *testing.T) {
	t.Parallel()
	translator := i18n.Translator{Language: domain.LanguageEnglish}
	direct := domain.Result{Analysis: domain.SiteAnalysis{
		CDNKnown: true, CDNConfidence: "medium", CDNEvidence: "至少兩輪成功重測未發現已知CDN訊號（快照20260723）",
		HotKnown: true, HotSnapshot: "202606",
	}}
	directOutput := Detail(direct, translator)
	for _, expected := range []string{"no supported CDN signal", "No known CDN signal in at least two successful verification rounds (snapshot 20260723)", "not in embedded CrUX Top 100k (202606)"} {
		if !strings.Contains(directOutput, expected) {
			t.Fatalf("direct detail does not contain %q:\n%s", expected, directOutput)
		}
	}
	stale := domain.Result{Analysis: domain.SiteAnalysis{
		CDNEvidence: "內建CDN快照已過期（快照20260723）", HotSnapshot: "202606",
	}}
	staleOutput := Detail(stale, translator)
	for _, expected := range []string{"Embedded CDN snapshot is stale (snapshot 20260723)", "embedded CrUX Top 100k (202606) snapshot is stale"} {
		if !strings.Contains(staleOutput, expected) {
			t.Fatalf("stale detail does not contain %q:\n%s", expected, staleOutput)
		}
	}
}
