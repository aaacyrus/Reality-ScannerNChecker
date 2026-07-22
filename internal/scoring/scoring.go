package scoring

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/aaacyrus/Reality-ScannerNChecker/internal/domain"
	"golang.org/x/net/publicsuffix"
)

const (
	maxTLSPoints  = 25
	maxHTTPPoints = 15
)

// CalculateQualified scores TLS and HTTP latency relative to the fastest
// successful candidate in the same qualified list.
func CalculateQualified(results []domain.Result) {
	for index := range results {
		calculateBase(&results[index])
	}
	applyProportionalLatency(results, func(result domain.Result) time.Duration {
		if !result.Verified {
			return 0
		}
		return result.Median.TLS
	}, func(result domain.Result) time.Duration {
		if !result.Verified {
			return 0
		}
		return result.Median.HTTP
	})
}

func calculateBase(result *domain.Result) {
	result.Score = domain.ScoreBreakdown{}
	result.Median = domain.DirectMetrics{}
	successes := successfulRounds(result.Rounds)
	result.Verified = len(successes) >= 2
	if !result.Verified {
		result.Suitable = false
		result.Reason = "unstable"
		return
	}
	result.Median = medianMetrics(successes)
	stability := 15
	if len(successes) == 3 {
		stability = 30
	}
	result.Score = domain.ScoreBreakdown{
		Stability:   stability,
		NoCDN:       boolPoints(result.Analysis.CDNKnown && !result.Analysis.CDN, 15),
		NotHot:      boolPoints(result.Analysis.HotKnown && !result.Analysis.HotWebsite, 10),
		Domain:      domainPoints(result.Candidate.SNI),
		Certificate: certificatePoints(result.Median.CertificateDays),
	}
}

// ApplyPreliminary scores initial latency relative to the same hard-check-
// qualified list before the three verification rounds.
func ApplyPreliminary(results []domain.Result) {
	for index := range results {
		result := &results[index]
		result.Median = result.Initial
		result.Score = domain.ScoreBreakdown{
			NoCDN:       boolPoints(result.Analysis.CDNKnown && !result.Analysis.CDN, 15),
			NotHot:      boolPoints(result.Analysis.HotKnown && !result.Analysis.HotWebsite, 10),
			Domain:      domainPoints(result.Candidate.SNI),
			Certificate: certificatePoints(result.Initial.CertificateDays),
		}
	}
	applyProportionalLatency(results,
		func(result domain.Result) time.Duration { return result.Initial.TLS },
		func(result domain.Result) time.Duration { return result.Initial.HTTP },
	)
}

func Sort(results []domain.Result) {
	sort.SliceStable(results, func(i, j int) bool {
		left, right := results[i], results[j]
		if left.Score.Total() != right.Score.Total() {
			return left.Score.Total() > right.Score.Total()
		}
		leftSuccess, rightSuccess := successCount(left.Rounds), successCount(right.Rounds)
		if leftSuccess != rightSuccess {
			return leftSuccess > rightSuccess
		}
		if left.Median.TLS != right.Median.TLS {
			return left.Median.TLS < right.Median.TLS
		}
		if left.Median.HTTP != right.Median.HTTP {
			return left.Median.HTTP < right.Median.HTTP
		}
		if left.Candidate.IP != right.Candidate.IP {
			return left.Candidate.IP.Less(right.Candidate.IP)
		}
		return left.Candidate.SNI < right.Candidate.SNI
	})
}

func applyProportionalLatency(
	results []domain.Result,
	tlsValue func(domain.Result) time.Duration,
	httpValue func(domain.Result) time.Duration,
) {
	fastestTLS := fastestDuration(results, tlsValue)
	fastestHTTP := fastestDuration(results, httpValue)
	for index := range results {
		results[index].Score.TLS = proportionalPoints(tlsValue(results[index]), fastestTLS, maxTLSPoints)
		results[index].Score.HTTP = proportionalPoints(httpValue(results[index]), fastestHTTP, maxHTTPPoints)
	}
}

func fastestDuration(results []domain.Result, value func(domain.Result) time.Duration) time.Duration {
	var fastest time.Duration
	for _, result := range results {
		current := value(result)
		if current > 0 && (fastest == 0 || current < fastest) {
			fastest = current
		}
	}
	return fastest
}

func proportionalPoints(value, fastest time.Duration, maximum int) int {
	if value <= 0 || fastest <= 0 || maximum <= 0 {
		return 0
	}
	points := int(math.Round(float64(fastest) / float64(value) * float64(maximum)))
	return min(max(points, 0), maximum)
}

func certificatePoints(days int) int {
	switch {
	case days >= 60:
		return 5
	case days >= 30:
		return 3
	case days >= 8:
		return 1
	default:
		return 0
	}
}

func domainPoints(value string) int {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	apex, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || (host != apex && host != "www."+apex) {
		return 0
	}
	return 5
}

func boolPoints(value bool, points int) int {
	if value {
		return points
	}
	return 0
}

func successfulRounds(rounds []domain.DirectMetrics) []domain.DirectMetrics {
	result := make([]domain.DirectMetrics, 0, len(rounds))
	for _, round := range rounds {
		if round.Success {
			result = append(result, round)
		}
	}
	return result
}

func successCount(rounds []domain.DirectMetrics) int {
	return len(successfulRounds(rounds))
}

func medianMetrics(items []domain.DirectMetrics) domain.DirectMetrics {
	if len(items) == 0 {
		return domain.DirectMetrics{}
	}
	result := items[0]
	result.TCP = medianDuration(items, func(item domain.DirectMetrics) time.Duration { return item.TCP })
	result.TLS = medianDuration(items, func(item domain.DirectMetrics) time.Duration { return item.TLS })
	result.HTTP = medianDuration(items, func(item domain.DirectMetrics) time.Duration { return item.HTTP })
	result.CertificateDays = medianInt(items, func(item domain.DirectMetrics) int { return item.CertificateDays })
	result.Success = true
	return result
}

func medianDuration(items []domain.DirectMetrics, value func(domain.DirectMetrics) time.Duration) time.Duration {
	values := make([]time.Duration, len(items))
	for index, item := range items {
		values[index] = value(item)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values[len(values)/2]
}

func medianInt(items []domain.DirectMetrics, value func(domain.DirectMetrics) int) int {
	values := make([]int, len(items))
	for index, item := range items {
		values[index] = value(item)
	}
	sort.Ints(values)
	return values[len(values)/2]
}
