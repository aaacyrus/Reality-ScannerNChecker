package domain

import (
	"net/netip"
	"time"

	"github.com/aaacyrus/Reality-ScannerNChecker/internal/scanner"
)

type Language string

const (
	LanguageTraditionalChinese Language = "zh-TW"
	LanguageEnglish            Language = "en"
)

type ScanProfile struct {
	Name        string
	Concurrency int
	Timeout     time.Duration
}

type ScanSelection struct {
	PublicIP netip.Addr
	Prefix   netip.Prefix
	Infinite bool
	Profile  ScanProfile
}

type Source struct {
	IP     netip.Addr
	SNI    string
	Scan   scanner.Result
	Origin string
}

type Candidate struct {
	SourceIP      netip.Addr
	SourceSNI     string
	IP            netip.Addr
	SNI           string
	RedirectChain []string
	Scan          scanner.Result
}

type DirectMetrics struct {
	TCP               time.Duration
	TLS               time.Duration
	HTTP              time.Duration
	HTTPStatus        int
	TLS13             bool
	X25519            bool
	HTTP2             bool
	SNIValid          bool
	CertificateValid  bool
	CertificateDays   int
	CertificateIssuer string
	Success           bool
}

type SiteAnalysis struct {
	Blocked       bool
	CountryCode   string
	CountryNameZH string
	CountryNameEN string
	CDNKnown      bool
	CDN           bool
	CDNProvider   string
	CDNConfidence string
	CDNEvidence   string
	HotKnown      bool
	HotWebsite    bool
	FinalDomain   string
	RedirectChain []string
	HTTPStatus    int
}

type ScoreBreakdown struct {
	Stability   int
	TLS         int
	HTTP        int
	NoCDN       int
	NotHot      int
	Domain      int
	Certificate int
}

func (s ScoreBreakdown) Total() int {
	return s.Stability + s.TLS + s.HTTP + s.NoCDN + s.NotHot + s.Domain + s.Certificate
}

type Result struct {
	Candidate Candidate
	Analysis  SiteAnalysis
	Initial   DirectMetrics
	Rounds    []DirectMetrics
	Median    DirectMetrics
	Score     ScoreBreakdown
	Suitable  bool
	Verified  bool
	Reason    string
	Detail    string
}

type RunResult struct {
	Ranked    []Result
	Qualified []Result
	Rejected  []Result
}
