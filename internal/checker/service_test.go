package checker

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aaacyrus/Reality-ScannerNChecker/internal/domain"
	"github.com/aaacyrus/Reality-ScannerNChecker/internal/scanner"
)

func TestExtractSourcesRejectsEveryWildcardAndDeduplicates(t *testing.T) {
	t.Parallel()
	scans := []scanner.Result{
		{
			IP:         netip.MustParseAddr("1.1.1.1"),
			CommonName: "*.example.com",
			DNSNames:   []string{"WWW.Example.com.", "www.example.com", "*.other.example"},
		},
	}
	sources, rejected := ExtractSources(scans)
	if len(sources) != 1 || sources[0].SNI != "www.example.com" {
		t.Fatalf("sources = %+v", sources)
	}
	if len(rejected) != 2 {
		t.Fatalf("rejected = %+v", rejected)
	}
	for _, result := range rejected {
		if result.Reason != "wildcard" {
			t.Fatalf("reason = %s", result.Reason)
		}
	}
}

func TestValidDomain(t *testing.T) {
	t.Parallel()
	valid := []string{"example.com", "www.example.com", "xn--fsq.com"}
	for _, value := range valid {
		if !validDomain(value) {
			t.Fatalf("expected valid: %s", value)
		}
	}
	invalid := []string{"localhost", "1.1.1.1", "*.example.com", "-bad.example", "bad_.example"}
	for _, value := range invalid {
		if validDomain(value) {
			t.Fatalf("expected invalid: %s", value)
		}
	}
}

func TestInitialValidationRetriesOneTransientFailure(t *testing.T) {
	t.Parallel()
	attempts := 0
	service := &Service{
		retryDelay: func() time.Duration { return 0 },
		validate: func(context.Context, domain.Candidate) (validation, error) {
			attempts++
			if attempts == 1 {
				return validation{}, errors.New("connection reset by peer")
			}
			return validation{metrics: domain.DirectMetrics{Success: true}}, nil
		},
	}
	checked, err := service.validateInitialWithRetry(context.Background(), domain.Candidate{})
	if err != nil || !checked.metrics.Success || attempts != 2 {
		t.Fatalf("validation=%+v err=%v attempts=%d", checked, err, attempts)
	}
}

func TestInitialValidationDoesNotRetryDeterministicFailure(t *testing.T) {
	t.Parallel()
	attempts := 0
	service := &Service{
		retryDelay: func() time.Duration { return 0 },
		validate: func(context.Context, domain.Candidate) (validation, error) {
			attempts++
			return validation{}, &validationError{reason: "certificate", err: errors.New("certificate is invalid")}
		},
	}
	_, err := service.validateInitialWithRetry(context.Background(), domain.Candidate{})
	if err == nil || attempts != 1 {
		t.Fatalf("err=%v attempts=%d", err, attempts)
	}
}

func TestVerifyQualifiedScoresEveryCandidate(t *testing.T) {
	t.Parallel()
	metrics := domain.DirectMetrics{
		TCP:              10 * time.Millisecond,
		TLS:              40 * time.Millisecond,
		HTTP:             80 * time.Millisecond,
		TLS13:            true,
		X25519:           true,
		HTTP2:            true,
		SNIValid:         true,
		CertificateValid: true,
		CertificateDays:  90,
		Success:          true,
	}
	var calls atomic.Int64
	service := &Service{
		validate: func(context.Context, domain.Candidate) (validation, error) {
			calls.Add(1)
			return validation{metrics: metrics}, nil
		},
	}
	run := domain.RunResult{}
	for index := range 12 {
		run.Qualified = append(run.Qualified, domain.Result{
			Candidate: domain.Candidate{
				IP:  netip.AddrFrom4([4]byte{1, 1, 1, byte(index + 1)}),
				SNI: "example.com",
			},
			Analysis: domain.SiteAnalysis{CDNKnown: true, HotKnown: true},
			Initial:  metrics,
		})
	}

	service.VerifyQualified(context.Background(), &run, nil)

	if len(run.Qualified) != 0 || len(run.Ranked) != 12 {
		t.Fatalf("pending=%d ranked=%d", len(run.Qualified), len(run.Ranked))
	}
	if got := calls.Load(); got != 36 {
		t.Fatalf("validation calls=%d, want 36", got)
	}
	for _, result := range run.Ranked {
		if !result.Verified || result.Score.Total() != 105 {
			t.Fatalf("result=%+v", result)
		}
	}
}

func TestVerifyQualifiedScoresLatencyProportionally(t *testing.T) {
	t.Parallel()
	service := &Service{
		validate: func(_ context.Context, candidate domain.Candidate) (validation, error) {
			multiplier := time.Duration(candidate.IP.As4()[3])
			return validation{metrics: domain.DirectMetrics{
				TCP:              10 * time.Millisecond * multiplier,
				TLS:              40 * time.Millisecond * multiplier,
				HTTP:             80 * time.Millisecond * multiplier,
				TLS13:            true,
				X25519:           true,
				HTTP2:            true,
				SNIValid:         true,
				CertificateValid: true,
				CertificateDays:  90,
				Success:          true,
			}}, nil
		},
	}
	run := domain.RunResult{}
	for lastByte := byte(1); lastByte <= 2; lastByte++ {
		run.Qualified = append(run.Qualified, domain.Result{
			Candidate: domain.Candidate{
				IP:  netip.AddrFrom4([4]byte{1, 1, 1, lastByte}),
				SNI: "example.com",
			},
			Analysis: domain.SiteAnalysis{CDNKnown: true, HotKnown: true},
			Initial: domain.DirectMetrics{
				TLS:             40 * time.Millisecond * time.Duration(lastByte),
				HTTP:            80 * time.Millisecond * time.Duration(lastByte),
				CertificateDays: 90,
			},
		})
	}

	service.VerifyQualified(context.Background(), &run, nil)

	if len(run.Ranked) != 2 {
		t.Fatalf("ranked=%d, want 2", len(run.Ranked))
	}
	if got := run.Ranked[0].Score.Total(); got != 105 {
		t.Fatalf("fastest total=%d, want 105", got)
	}
	if got := run.Ranked[1].Score; got.TLS != 13 || got.HTTP != 8 || got.Total() != 86 {
		t.Fatalf("slower score=%+v, want TLS=13 HTTP=8 total=86", got)
	}
}
