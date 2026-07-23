package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/aaacyrus/Reality-ScannerNChecker/internal/domain"
	"github.com/aaacyrus/Reality-ScannerNChecker/internal/i18n"
	"github.com/jedib0t/go-pretty/v6/table"
)

func RankingTable(results []domain.Result, translator i18n.Translator) string {
	return RankingTableStyled(results, translator, false)
}

func RankingTableStyled(results []domain.Result, translator i18n.Translator, colors bool) string {
	writer := table.NewWriter()
	writer.SetStyle(table.StyleLight)
	writer.AppendHeader(table.Row{
		tableHeader(translator.T("col.rank"), colors), tableHeader(translator.T("col.ip"), colors), tableHeader(translator.T("col.sni"), colors),
		tableHeader(translator.T("col.score"), colors), tableHeader(translator.T("col.success"), colors), tableHeader(translator.T("col.tcp"), colors),
		tableHeader(translator.T("col.tls"), colors), tableHeader(translator.T("col.http"), colors), tableHeader(translator.T("col.tls13"), colors),
		tableHeader(translator.T("col.x25519"), colors), tableHeader(translator.T("col.h2"), colors), tableHeader(translator.T("col.sni_ok"), colors),
		tableHeader(translator.T("col.cert"), colors), tableHeader(translator.T("col.cdn"), colors), tableHeader(translator.T("col.hot"), colors),
		tableHeader(translator.T("col.region"), colors),
	})
	for index, result := range results {
		metrics := result.Median
		totalScore := result.Score.Total()
		score := scoreText(totalScore, colors)
		successes := successCount(result.Rounds)
		success := paint(colors, fmt.Sprintf("%d/3", successes), successColor(successes))
		rank := fmt.Sprintf("%d", index+1)
		if index == 0 {
			rank = paint(colors, "★ 1", ansiBold, ansiYellow)
		}
		writer.AppendRow(table.Row{
			rank,
			result.Candidate.IP.String(),
			result.Candidate.SNI,
			score,
			success,
			durationText(metrics.TCP, colors),
			durationText(metrics.TLS, colors),
			durationText(metrics.HTTP, colors),
			markStyled(metrics.TLS13, colors),
			markStyled(metrics.X25519, colors),
			markStyled(metrics.HTTP2, colors),
			markStyled(metrics.SNIValid, colors),
			metrics.CertificateDays,
			cdnLabel(result, translator),
			yesNo(result.Analysis.HotKnown, result.Analysis.HotWebsite, translator),
			region(result, translator),
		})
	}
	return writer.Render()
}

func RejectedTable(results []domain.Result, translator i18n.Translator) string {
	return RejectedTableStyled(results, translator, false)
}

func RejectedTableStyled(results []domain.Result, translator i18n.Translator, colors bool) string {
	writer := table.NewWriter()
	writer.SetStyle(table.StyleLight)
	writer.AppendHeader(table.Row{
		tableHeader("#", colors), tableHeader(translator.T("col.ip"), colors), tableHeader(translator.T("col.sni"), colors),
		tableHeader(translator.T("col.reason"), colors), tableHeader(translator.T("col.detail"), colors),
	})
	for index, result := range results {
		writer.AppendRow(table.Row{
			index + 1,
			result.Candidate.IP.String(),
			result.Candidate.SNI,
			paint(colors, translator.Reason(result.Reason), ansiRed),
			paint(colors, trimDetail(localizeDetail(result.Detail, translator)), ansiDim),
		})
	}
	return writer.Render()
}

func Detail(result domain.Result, translator i18n.Translator) string {
	return DetailStyled(result, translator, false)
}

func DetailStyled(result domain.Result, translator i18n.Translator, colors bool) string {
	metrics := result.Median
	if !result.Verified {
		metrics = result.Initial
	}
	chain := translator.T("none")
	if len(result.Candidate.RedirectChain) > 0 {
		chain = strings.Join(result.Candidate.RedirectChain, " → ")
	}
	provider := localizeProvider(valueOr(result.Analysis.CDNProvider, translator.T("unknown")), translator)
	confidence := valueOr(result.Analysis.CDNConfidence, translator.T("unknown"))
	evidence := valueOr(result.Analysis.CDNEvidence, translator.T("none"))
	issuer := valueOr(metrics.CertificateIssuer, translator.T("unknown"))
	return strings.Join([]string{
		paint(colors, "◆ "+translator.T("detail_title"), ansiBold, ansiMagenta),
		paint(colors, translator.T("detail.source", result.Candidate.SourceIP, result.Candidate.SourceSNI), ansiDim),
		paint(colors, translator.T("detail.final", result.Candidate.IP, result.Candidate.SNI), ansiBold, ansiGreen),
		translator.T("detail.redirect", chain),
		paint(colors, translator.T("detail.score", result.Score.Stability, result.Score.TLS, result.Score.HTTP, result.Score.NoCDN, result.Score.NotHot, result.Score.Domain, result.Score.Certificate, result.Score.Total()), ansiBold, ansiYellow),
		translator.T("detail.metrics", formatDuration(metrics.TCP), formatDuration(metrics.TLS), formatDuration(metrics.HTTP), successCount(result.Rounds)),
		paint(colors, translator.T("detail.protocol", boolText(metrics.TLS13, translator), boolText(metrics.X25519, translator), boolText(metrics.HTTP2, translator), boolText(metrics.SNIValid, translator)), ansiCyan),
		translator.T("detail.certificate", metrics.CertificateDays, issuer),
		translator.T("detail.cdn", cdnStatus(result.Analysis, translator), provider, localizeConfidence(confidence, translator), localizeEvidence(evidence, translator)),
		translator.T("detail.hot", yesNo(result.Analysis.HotKnown, result.Analysis.HotWebsite, translator), hotEvidence(result.Analysis, translator)),
		translator.T("detail.location", countryName(result, translator), valueOr(result.Analysis.CountryCode, translator.T("unknown"))),
	}, "\n")
}

func tableHeader(value string, colors bool) string {
	return paint(colors, value, ansiBold, ansiCyan)
}

func scoreText(score int, colors bool) string {
	color := ansiRed
	if score >= 85 {
		color = ansiGreen
	} else if score >= 70 {
		color = ansiYellow
	}
	return paint(colors, fmt.Sprintf("%d", score), ansiBold, color)
}

func successColor(successes int) string {
	if successes >= 3 {
		return ansiGreen
	}
	if successes >= 2 {
		return ansiYellow
	}
	return ansiRed
}

func durationText(value time.Duration, colors bool) string {
	color := ansiGreen
	if value <= 0 || value >= 750*time.Millisecond {
		color = ansiRed
	} else if value >= 300*time.Millisecond {
		color = ansiYellow
	}
	return paint(colors, formatDuration(value), color)
}

func markStyled(value, colors bool) string {
	if value {
		return paint(colors, "✓", ansiBold, ansiGreen)
	}
	return paint(colors, "✗", ansiBold, ansiRed)
}

func formatDuration(value time.Duration) string {
	if value <= 0 {
		return "-"
	}
	if value < time.Millisecond {
		return fmt.Sprintf("%.1fms", float64(value)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%dms", value.Milliseconds())
}

func successCount(rounds []domain.DirectMetrics) int {
	count := 0
	for _, round := range rounds {
		if round.Success {
			count++
		}
	}
	return count
}

func boolText(value bool, translator i18n.Translator) string {
	if value {
		return translator.T("yes")
	}
	return translator.T("no")
}

func yesNo(known, value bool, translator i18n.Translator) string {
	if !known {
		return translator.T("unknown")
	}
	return boolText(value, translator)
}

func cdnLabel(result domain.Result, translator i18n.Translator) string {
	if result.Analysis.CDNKnown && result.Analysis.CDN && result.Analysis.CDNProvider != "" {
		return localizeProvider(result.Analysis.CDNProvider, translator)
	}
	return cdnStatus(result.Analysis, translator)
}

func cdnStatus(analysis domain.SiteAnalysis, translator i18n.Translator) string {
	if !analysis.CDNKnown {
		return translator.T("unknown")
	}
	if !analysis.CDN {
		return translator.T("cdn.not_detected")
	}
	return translator.T("yes")
}

func region(result domain.Result, translator i18n.Translator) string {
	if result.Analysis.CountryCode == "" {
		return translator.T("unknown")
	}
	name := countryName(result, translator)
	if name == "" || name == translator.T("unknown") || name == result.Analysis.CountryCode {
		return result.Analysis.CountryCode
	}
	return fmt.Sprintf("%s (%s)", name, result.Analysis.CountryCode)
}

func countryName(result domain.Result, translator i18n.Translator) string {
	name := result.Analysis.CountryNameEN
	if translator.Language == domain.LanguageTraditionalChinese {
		name = result.Analysis.CountryNameZH
	}
	return valueOr(name, translator.T("unknown"))
}

func localizeConfidence(value string, translator i18n.Translator) string {
	if translator.Language == domain.LanguageTraditionalChinese {
		switch value {
		case "high":
			return "高"
		case "medium":
			return "中"
		case "low":
			return "低"
		}
		return value
	}
	switch value {
	case "高":
		return "high"
	case "中":
		return "medium"
	case "低":
		return "low"
	default:
		return value
	}
}

func localizeProvider(value string, translator i18n.Translator) string {
	if value == "Multiple" {
		return translator.T("multiple")
	}
	return value
}

func hotEvidence(analysis domain.SiteAnalysis, translator i18n.Translator) string {
	if analysis.HotSnapshot == "" {
		return translator.T("none")
	}
	if analysis.HotKnown && analysis.HotWebsite {
		return translator.T("evidence.hot_hit", analysis.HotSnapshot, valueOr(analysis.HotMatch, translator.T("unknown")))
	}
	if analysis.HotKnown {
		return translator.T("evidence.hot_miss", analysis.HotSnapshot)
	}
	return translator.T("evidence.hot_stale", analysis.HotSnapshot)
}

func localizeEvidence(value string, translator i18n.Translator) string {
	if translator.Language == domain.LanguageTraditionalChinese {
		return value
	}
	replacements := map[string]string{
		"HTTP強訊號:": "Strong HTTP signal: ",
		"CNAME特徵:": "CNAME signal: ",
		"IP網段快照(":  "IP range snapshot (",
		"至少兩輪成功重測未發現已知CDN訊號（快照": "No known CDN signal in at least two successful verification rounds (snapshot ",
		"內建CDN快照已過期（快照":         "Embedded CDN snapshot is stale (snapshot ",
		"CNAME查詢未完成，無法排除CDN":    "CNAME lookup was incomplete; CDN cannot be ruled out",
		"HTTP强响应头特征:":           "Strong HTTP header signal:",
		"HTTP头值CDN域名特征:":        "CDN domain signal in HTTP header:",
		"HTTP中等响应头特征:":          "Medium HTTP header signal:",
		"证书签发者提示:":              "Certificate issuer signal:",
		"CNAME记录特征:":            "CNAME signal:",
		"NS记录:":                 "NS record:",
	}
	for source, target := range replacements {
		value = strings.ReplaceAll(value, source, target)
	}
	value = strings.ReplaceAll(value, "）", ")")
	value = strings.ReplaceAll(value, "；", "; ")
	return value
}

func localizeDetail(value string, translator i18n.Translator) string {
	if translator.Language == domain.LanguageTraditionalChinese {
		return value
	}
	replacements := map[string]string{
		"域名被墙":          "domain is listed as blocked",
		"国内网站":          "mainland China site",
		"网络不可达":         "network unreachable",
		"状态码不自然":        "HTTP status is not allowed",
		"不支持TLS 1.3":    "TLS 1.3 is unsupported",
		"不支持X25519密钥交换": "X25519 is unsupported",
		"不支持HTTP/2":     "HTTP/2 is unsupported",
		"证书无效":          "certificate is invalid",
		"证书已过期":         "certificate has expired",
		"SNI不匹配":        "SNI does not match",
		"IP解析失败":        "IP resolution failed",
		"检测超时":          "check timed out",
	}
	for source, target := range replacements {
		value = strings.ReplaceAll(value, source, target)
	}
	return value
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func trimDetail(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\n", " "))
	if len(value) > 100 {
		return value[:97] + "..."
	}
	return value
}
