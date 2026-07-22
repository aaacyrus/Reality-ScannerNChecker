package scoring

import (
	"testing"
	"time"

	"github.com/aaacyrus/Reality-ScannerNChecker/internal/domain"
)

func TestProportionalLatencyScores(t *testing.T) {
	t.Parallel()
	metrics := func(tls, http time.Duration, successes int) []domain.DirectMetrics {
		rounds := make([]domain.DirectMetrics, 0, 3)
		for index := range 3 {
			rounds = append(rounds, domain.DirectMetrics{
				TLS:     tls,
				HTTP:    http,
				Success: index < successes,
			})
		}
		return rounds
	}
	results := []domain.Result{
		{Rounds: metrics(50*time.Millisecond, 100*time.Millisecond, 3)},
		{Rounds: metrics(100*time.Millisecond, 200*time.Millisecond, 3)},
		{Rounds: metrics(200*time.Millisecond, 400*time.Millisecond, 3)},
		// An unverified candidate must not become the latency baseline.
		{Rounds: metrics(time.Millisecond, time.Millisecond, 1)},
	}
	CalculateQualified(results)
	want := [][2]int{{25, 15}, {13, 8}, {6, 4}, {0, 0}}
	for index, result := range results {
		if got := [2]int{result.Score.TLS, result.Score.HTTP}; got != want[index] {
			t.Errorf("result %d latency score=%v, want %v", index, got, want[index])
		}
	}
	if results[3].Verified {
		t.Fatal("candidate with one successful round was verified")
	}
}

func TestCalculateQualifiedScore(t *testing.T) {
	t.Parallel()
	base := domain.DirectMetrics{
		TCP:              10 * time.Millisecond,
		TLS:              45 * time.Millisecond,
		HTTP:             90 * time.Millisecond,
		TLS13:            true,
		X25519:           true,
		HTTP2:            true,
		SNIValid:         true,
		CertificateValid: true,
		CertificateDays:  61,
		Success:          true,
	}
	results := []domain.Result{{
		Candidate: domain.Candidate{SNI: "example.com"},
		Analysis:  domain.SiteAnalysis{CDNKnown: true, HotKnown: true},
		Rounds:    []domain.DirectMetrics{base, base, base},
		Suitable:  true,
	}}
	CalculateQualified(results)
	result := &results[0]
	if !result.Verified || result.Score.Domain != 5 || result.Score.Total() != 105 {
		t.Fatalf("verified=%v score=%+v", result.Verified, result.Score)
	}

	result.Rounds[2].Success = false
	CalculateQualified(results)
	if result.Score.Stability != 15 || result.Score.Total() != 90 {
		t.Fatalf("score with 2/3 = %+v", result.Score)
	}

	result.Rounds[1].Success = false
	CalculateQualified(results)
	if result.Verified || result.Reason != "unstable" {
		t.Fatalf("verified=%v reason=%s", result.Verified, result.Reason)
	}
}

func TestDomainPoints(t *testing.T) {
	t.Parallel()
	tests := map[string]int{
		"example.com":           5,
		"EXAMPLE.COM.":          5,
		"example.co.uk":         5,
		"project.github.io":     5,
		"www.example.com":       5,
		"www.example.co.uk":     5,
		"api.example.com":       0,
		"a.www.example.com":     0,
		"www.project.github.io": 5,
		"api.project.github.io": 0,
		"com":                   0,
		"co.uk":                 0,
		"":                      0,
	}
	for value, want := range tests {
		if got := domainPoints(value); got != want {
			t.Errorf("domainPoints(%q)=%d, want %d", value, got, want)
		}
	}
}

func TestApplyPreliminaryIncludesDomainPoints(t *testing.T) {
	t.Parallel()
	results := make([]domain.Result, 0, 2)
	for multiplier := time.Duration(1); multiplier <= 2; multiplier++ {
		results = append(results, domain.Result{
			Candidate: domain.Candidate{SNI: "example.com"},
			Initial: domain.DirectMetrics{
				TLS:             50 * time.Millisecond * multiplier,
				HTTP:            100 * time.Millisecond * multiplier,
				CertificateDays: 60,
			},
			Analysis: domain.SiteAnalysis{CDNKnown: true, HotKnown: true},
		})
	}
	ApplyPreliminary(results)
	if result := results[0]; result.Score.Domain != 5 || result.Score.Total() != 75 {
		t.Fatalf("fastest score=%+v", result.Score)
	}
	if result := results[1]; result.Score.TLS != 13 || result.Score.HTTP != 8 || result.Score.Total() != 56 {
		t.Fatalf("slower score=%+v", result.Score)
	}
}

func TestCertificatePoints(t *testing.T) {
	t.Parallel()
	tests := map[int]int{60: 5, 59: 3, 30: 3, 29: 1, 8: 1, 7: 0, 1: 0}
	for days, want := range tests {
		if got := certificatePoints(days); got != want {
			t.Fatalf("days=%d got=%d want=%d", days, got, want)
		}
	}
}
