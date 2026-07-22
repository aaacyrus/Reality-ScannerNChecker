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
