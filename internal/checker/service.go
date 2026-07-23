package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aaacyrus/Reality-ScannerNChecker/internal/domain"
	"github.com/aaacyrus/Reality-ScannerNChecker/internal/publicip"
	"github.com/aaacyrus/Reality-ScannerNChecker/internal/scanner"
	"github.com/aaacyrus/Reality-ScannerNChecker/internal/scoring"
	"github.com/oschwald/geoip2-golang"
)

const (
	checkerConcurrency      = 8
	verificationConcurrency = 5
	candidateTimeout        = 15 * time.Second
	networkTimeout          = 3 * time.Second
	verificationRounds      = 3
)

type Progress struct {
	Done, Total, Qualified, Rejected int
	Domain                           string
}

type ProgressFunc func(Progress)

type inspection struct {
	finalDomain   string
	redirectChain []string
	status        int
}

type validation struct {
	metrics domain.DirectMetrics
	cdn     []cdnEvidence
}

type Service struct {
	geo         *geoip2.Reader
	prefix      netip.Prefix
	infinite    bool
	resolver    *net.Resolver
	inspect     func(context.Context, string) (inspection, error)
	validate    func(context.Context, domain.Candidate) (validation, error)
	lookupCNAME func(context.Context, string) (string, error)
	retryDelay  func() time.Duration
	now         func() time.Time
}

func New(dataDir string, prefix netip.Prefix, infinite bool) (*Service, error) {
	service := &Service{
		prefix: prefix.Masked(), infinite: infinite, resolver: net.DefaultResolver,
		inspect: inspectWebsite, lookupCNAME: net.DefaultResolver.LookupCNAME,
		retryDelay: jitterDelay, now: time.Now,
	}
	service.validate = service.validateExact
	if dataDir == "" {
		return service, nil
	}
	reader, err := geoip2.Open(filepath.Join(dataDir, "Country.mmdb"))
	if err != nil {
		return nil, err
	}
	service.geo = reader
	return service, nil
}

func (s *Service) Close() error {
	if s.geo == nil {
		return nil
	}
	return s.geo.Close()
}

// ExtractSources keeps every concrete certificate name and rejects wildcards.
func ExtractSources(scans []scanner.Result) ([]domain.Source, []domain.Result) {
	seen := make(map[string]struct{})
	var sources []domain.Source
	var rejected []domain.Result
	for _, scan := range scans {
		for _, raw := range append([]string{scan.CommonName}, scan.DNSNames...) {
			name := normalizeDomain(raw)
			if name == "" {
				continue
			}
			candidate := domain.Candidate{SourceIP: scan.IP, SourceSNI: name, IP: scan.IP, SNI: name, Scan: scan}
			if strings.Contains(name, "*") {
				rejected = append(rejected, domain.Result{Candidate: candidate, Reason: "wildcard", Detail: raw})
				continue
			}
			if !validDomain(name) {
				rejected = append(rejected, domain.Result{Candidate: candidate, Reason: "invalid_domain", Detail: raw})
				continue
			}
			key := scan.IP.String() + "\x00" + name
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			sources = append(sources, domain.Source{IP: scan.IP, SNI: name, Scan: scan, Origin: scan.Origin})
		}
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].IP != sources[j].IP {
			return sources[i].IP.Less(sources[j].IP)
		}
		return sources[i].SNI < sources[j].SNI
	})
	return sources, rejected
}

func (s *Service) Analyze(ctx context.Context, sources []domain.Source, onProgress ProgressFunc) domain.RunResult {
	type output struct{ qualified, rejected []domain.Result }
	jobs := make(chan domain.Source)
	outputs := make(chan output)
	var workers sync.WaitGroup
	workers.Add(checkerConcurrency)
	for range checkerConcurrency {
		go func() {
			defer workers.Done()
			for source := range jobs {
				qualified, rejected := s.analyzeSource(ctx, source)
				select {
				case outputs <- output{qualified, rejected}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, source := range sources {
			if !sendSource(ctx, jobs, source) {
				return
			}
		}
	}()
	go func() { workers.Wait(); close(outputs) }()
	result := domain.RunResult{}
	for item := range outputs {
		result.Qualified = append(result.Qualified, item.qualified...)
		result.Rejected = append(result.Rejected, item.rejected...)
		if onProgress != nil {
			name := ""
			if len(item.qualified) > 0 {
				name = item.qualified[0].Candidate.SNI
			} else if len(item.rejected) > 0 {
				name = item.rejected[0].Candidate.SNI
			}
			onProgress(Progress{Done: len(result.Qualified) + len(result.Rejected), Total: len(sources), Qualified: len(result.Qualified), Rejected: len(result.Rejected), Domain: name})
		}
	}
	return result
}

func (s *Service) analyzeSource(ctx context.Context, source domain.Source) ([]domain.Result, []domain.Result) {
	candidateCtx, cancel := context.WithTimeout(ctx, candidateTimeout)
	defer cancel()
	check, err := s.inspectWithRetry(candidateCtx, source.SNI)
	if err != nil {
		reason, detail := classifyValidationFailure(err)
		return nil, []domain.Result{rejectionForSource(source, reason, detail)}
	}
	hosts := append(append([]string(nil), check.redirectChain...), check.finalDomain)
	hotKnown, hot, hotMatch := classifyPopularity(hosts, s.currentTime())
	analysis := domain.SiteAnalysis{
		HotKnown: hotKnown, HotWebsite: hot, HotSnapshot: cruxSnapshot, HotMatch: hotMatch,
		FinalDomain: check.finalDomain, RedirectChain: check.redirectChain, HTTPStatus: check.status,
	}
	if !validDomain(check.finalDomain) {
		return nil, []domain.Result{rejectionForSourceWithAnalysis(source, analysis, "invalid_domain", check.finalDomain)}
	}
	addresses, err := s.resolveInScope(candidateCtx, check.finalDomain, source.IP)
	if err != nil {
		reason := "resolve_failed"
		if errors.Is(err, errOutsideScope) {
			reason = "redirect_outside_scope"
		}
		return nil, []domain.Result{rejectionForSourceWithAnalysis(source, analysis, reason, err.Error())}
	}
	var qualified, rejected []domain.Result
	for _, ip := range addresses {
		candidate := domain.Candidate{SourceIP: source.IP, SourceSNI: source.SNI, IP: ip, SNI: check.finalDomain, RedirectChain: append([]string(nil), check.redirectChain...), Scan: source.Scan}
		code, zh, en, err := s.country(ip)
		if err != nil || code == "" {
			rejected = append(rejected, domain.Result{Candidate: candidate, Analysis: analysis, Reason: "location_unknown", Detail: errorDetail(err)})
			continue
		}
		candidateAnalysis := analysis
		candidateAnalysis.CountryCode, candidateAnalysis.CountryNameZH, candidateAnalysis.CountryNameEN = code, zh, en
		if code == "CN" {
			rejected = append(rejected, domain.Result{Candidate: candidate, Analysis: candidateAnalysis, Reason: "china", Detail: code})
			continue
		}
		checked, err := s.validateInitialWithRetry(candidateCtx, candidate)
		metrics := checked.metrics
		if err != nil {
			reason, detail := classifyValidationFailure(err)
			rejected = append(rejected, domain.Result{Candidate: candidate, Analysis: candidateAnalysis, Initial: metrics, Reason: reason, Detail: detail})
			continue
		}
		mergeCDNFinding(&candidateAnalysis, classifyCDN(checked.cdn, 0, false, s.currentTime()))
		qualified = append(qualified, domain.Result{Candidate: candidate, Analysis: candidateAnalysis, Initial: metrics, Suitable: true})
	}
	return qualified, rejected
}

func (s *Service) inspectWithRetry(ctx context.Context, name string) (inspection, error) {
	var last inspection
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		last, err = s.inspect(ctx, name)
		if err == nil || !isTransient(err) {
			return last, err
		}
		if attempt == 0 && !s.waitRetry(ctx) {
			return last, ctx.Err()
		}
	}
	return last, err
}

func inspectWebsite(ctx context.Context, name string) (inspection, error) {
	current := &url.URL{Scheme: "https", Host: name, Path: "/"}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true, DisableKeepAlives: true, ResponseHeaderTimeout: networkTimeout, TLSHandshakeTimeout: networkTimeout}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: networkTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	chain := make([]string, 0, 6)
	for redirects := 0; redirects <= 5; redirects++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return inspection{}, err
		}
		request.Header.Set("User-Agent", "Reality-ScannerNChecker/1.0")
		response, err := client.Do(request)
		if err != nil {
			return inspection{}, classifyTLSHandshakeError(err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		response.Body.Close()
		if response.TLS == nil {
			return inspection{}, &validationError{reason: "network", err: errors.New("HTTPS response has no TLS state")}
		}
		if err := validateTLSState(response.TLS, current.Hostname()); err != nil {
			return inspection{}, err
		}
		chain = append(chain, current.Hostname())
		if next, ok := redirectTarget(current, response); ok {
			current = next
			continue
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			return inspection{}, &validationError{reason: "http_status", err: errors.New("redirect has no valid HTTPS location")}
		}
		if !safeStatus(response.StatusCode) {
			return inspection{}, &validationError{reason: "http_status", err: fmt.Errorf("unsafe HTTP status %d", response.StatusCode)}
		}
		return inspection{finalDomain: normalizeDomain(current.Hostname()), redirectChain: chain, status: response.StatusCode}, nil
	}
	return inspection{}, &validationError{reason: "http_status", err: errors.New("too many redirects")}
}

func redirectTarget(current *url.URL, response *http.Response) (*url.URL, bool) {
	if response.StatusCode < 300 || response.StatusCode >= 400 {
		return nil, false
	}
	next, err := response.Location()
	if err != nil {
		return nil, false
	}
	next = current.ResolveReference(next)
	if next.Scheme != "https" || next.Hostname() == "" {
		return nil, false
	}
	return next, true
}

func validateTLSState(state *tls.ConnectionState, host string) error {
	if state.Version != tls.VersionTLS13 {
		return &validationError{reason: "tls13", err: errors.New("TLS 1.3 was not negotiated")}
	}
	if state.CurveID != tls.X25519 {
		return &validationError{reason: "x25519", err: errors.New("X25519 was not negotiated")}
	}
	if state.NegotiatedProtocol != "h2" {
		return &validationError{reason: "h2", err: errors.New("HTTP/2 was not negotiated")}
	}
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return &validationError{reason: "certificate", err: errors.New("certificate was not verified")}
	}
	if err := state.PeerCertificates[0].VerifyHostname(host); err != nil {
		return &validationError{reason: "sni", err: err}
	}
	if time.Until(state.PeerCertificates[0].NotAfter) <= 0 {
		return &validationError{reason: "certificate", err: errors.New("certificate is expired")}
	}
	return nil
}

func (s *Service) validateInitialWithRetry(ctx context.Context, candidate domain.Candidate) (validation, error) {
	metrics, err := s.validate(ctx, candidate)
	if err == nil || !isTransient(err) {
		return metrics, err
	}
	if !s.waitRetry(ctx) {
		return metrics, ctx.Err()
	}
	return s.validate(ctx, candidate)
}

func (s *Service) waitRetry(ctx context.Context) bool {
	delay := jitterDelay()
	if s.retryDelay != nil {
		delay = s.retryDelay()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func jitterDelay() time.Duration { return time.Duration(200+rand.IntN(301)) * time.Millisecond }

var errOutsideScope = errors.New("resolved addresses are outside the selected scan range")

func (s *Service) resolveInScope(ctx context.Context, name string, sourceIP netip.Addr) ([]netip.Addr, error) {
	addresses, err := s.resolver.LookupNetIP(ctx, "ip4", name)
	if err != nil {
		return nil, err
	}
	seen := make(map[netip.Addr]struct{})
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		inScope := s.prefix.Contains(address)
		if s.infinite {
			inScope = address == sourceIP
		}
		if !publicip.IsPublicIPv4(address) || !inScope {
			continue
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}
	if len(result) == 0 {
		return nil, errOutsideScope
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	return result, nil
}

func (s *Service) country(ip netip.Addr) (string, string, string, error) {
	if s.geo == nil {
		return "", "", "", errors.New("Country.mmdb is unavailable; update detector data before scanning")
	}
	record, err := s.geo.Country(net.IP(ip.AsSlice()))
	if err != nil {
		return "", "", "", err
	}
	code := strings.ToUpper(strings.TrimSpace(record.Country.IsoCode))
	zh, en := record.Country.Names["zh-CN"], record.Country.Names["en"]
	if zh == "" {
		zh = valueOr(en, code)
	}
	if en == "" {
		en = valueOr(zh, code)
	}
	return code, zh, en, nil
}

type validationError struct {
	reason string
	err    error
}

func (e *validationError) Error() string { return e.err.Error() }
func (e *validationError) Unwrap() error { return e.err }

func (s *Service) validateExact(ctx context.Context, candidate domain.Candidate) (validation, error) {
	metrics := domain.DirectMetrics{}
	dialer := &net.Dialer{Timeout: networkTimeout}
	tcpStarted := time.Now()
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(candidate.IP.String(), "443"))
	if err != nil {
		return validation{metrics: metrics}, &validationError{reason: "network", err: err}
	}
	metrics.TCP = time.Since(tcpStarted)
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(networkTimeout)); err != nil {
		return validation{metrics: metrics}, &validationError{reason: "network", err: err}
	}
	tlsConfig := &tls.Config{ServerName: candidate.SNI, NextProtos: []string{"h2", "http/1.1"}, CurvePreferences: []tls.CurveID{tls.X25519}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13}
	tlsConnection := tls.Client(connection, tlsConfig)
	tlsStarted := time.Now()
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return validation{metrics: metrics}, classifyTLSHandshakeError(err)
	}
	metrics.TLS = time.Since(tlsStarted)
	state := tlsConnection.ConnectionState()
	metrics.TLS13, metrics.X25519, metrics.HTTP2 = state.Version == tls.VersionTLS13, state.CurveID == tls.X25519, state.NegotiatedProtocol == "h2"
	if len(state.PeerCertificates) == 0 {
		return validation{metrics: metrics}, &validationError{reason: "certificate", err: errors.New("peer returned no certificate")}
	}
	leaf := state.PeerCertificates[0]
	metrics.SNIValid, metrics.CertificateValid = leaf.VerifyHostname(candidate.SNI) == nil, len(state.VerifiedChains) > 0
	metrics.CertificateDays, metrics.CertificateIssuer = int(time.Until(leaf.NotAfter).Hours()/24), leaf.Issuer.String()
	if err := validateTLSState(&state, candidate.SNI); err != nil {
		return validation{metrics: metrics}, err
	}
	var headerEvidence []cdnEvidence
	metrics.HTTP, metrics.HTTPStatus, headerEvidence, err = requestExact(ctx, candidate, tlsConfig)
	if err != nil {
		return validation{metrics: metrics}, &validationError{reason: "network", err: err}
	}
	if !safeStatus(metrics.HTTPStatus) {
		return validation{metrics: metrics}, &validationError{reason: "http_status", err: fmt.Errorf("unsafe HTTP status %d", metrics.HTTPStatus)}
	}
	metrics.Success = true
	evidence := append(cdnFromIP(candidate.IP), headerEvidence...)
	return validation{metrics: metrics, cdn: evidence}, nil
}

func requestExact(ctx context.Context, candidate domain.Candidate, tlsConfig *tls.Config) (time.Duration, int, []cdnEvidence, error) {
	dialer := &net.Dialer{Timeout: networkTimeout}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(candidate.IP.String(), "443"))
	}, TLSClientConfig: tlsConfig.Clone(), ForceAttemptHTTP2: true, DisableKeepAlives: true, ResponseHeaderTimeout: networkTimeout, TLSHandshakeTimeout: networkTimeout}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: networkTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+candidate.SNI+"/", nil)
	if err != nil {
		return 0, 0, nil, err
	}
	request.Header.Set("User-Agent", "Reality-ScannerNChecker/1.0")
	started := time.Now()
	response, err := client.Do(request)
	duration := time.Since(started)
	if err != nil {
		return duration, 0, nil, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	return duration, response.StatusCode, cdnFromHeaders(response.Header), nil
}

func (s *Service) VerifyQualified(ctx context.Context, run *domain.RunResult, onProgress ProgressFunc) {
	scoring.ApplyPreliminary(run.Qualified)
	sort.SliceStable(run.Qualified, func(i, j int) bool { return run.Qualified[i].Score.Total() > run.Qualified[j].Score.Total() })
	candidates := append([]domain.Result(nil), run.Qualified...)
	run.Qualified = nil
	if len(candidates) == 0 {
		return
	}
	jobs := make(chan int)
	var workers sync.WaitGroup
	var mu sync.Mutex
	done := 0
	count := min(verificationConcurrency, len(candidates))
	workers.Add(count)
	for range count {
		go func() {
			defer workers.Done()
			for index := range jobs {
				observations := make([]cdnEvidence, 0, verificationRounds+1)
				cnameChecked := false
				if s.lookupCNAME != nil {
					cname, err := s.lookupCNAME(ctx, candidates[index].Candidate.SNI)
					if err == nil {
						cnameChecked = true
						observations = append(observations, cdnFromCNAME(cname)...)
					}
				}
				rounds := make([]domain.DirectMetrics, 0, verificationRounds)
				for range verificationRounds {
					checked, err := s.validate(ctx, candidates[index].Candidate)
					metrics := checked.metrics
					if err != nil {
						metrics.Success = false
					}
					observations = append(observations, checked.cdn...)
					rounds = append(rounds, metrics)
				}
				candidates[index].Rounds = rounds
				mergeCDNFinding(&candidates[index].Analysis, classifyCDN(observations, successfulRoundCount(rounds), cnameChecked, s.currentTime()))
				mu.Lock()
				done++
				if onProgress != nil {
					onProgress(Progress{Done: done, Total: len(candidates), Qualified: done, Domain: candidates[index].Candidate.SNI})
				}
				mu.Unlock()
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range candidates {
			select {
			case jobs <- index:
			case <-ctx.Done():
				return
			}
		}
	}()
	workers.Wait()
	scoring.CalculateQualified(candidates)
	for _, candidate := range candidates {
		if candidate.Verified {
			candidate.Suitable = true
			run.Ranked = append(run.Ranked, candidate)
		} else {
			run.Rejected = append(run.Rejected, candidate)
		}
	}
	scoring.Sort(run.Ranked)
}

func rejectionForSource(source domain.Source, reason, detail string) domain.Result {
	return domain.Result{Candidate: domain.Candidate{SourceIP: source.IP, SourceSNI: source.SNI, IP: source.IP, SNI: source.SNI, Scan: source.Scan}, Reason: reason, Detail: detail}
}
func rejectionForSourceWithAnalysis(source domain.Source, analysis domain.SiteAnalysis, reason, detail string) domain.Result {
	result := rejectionForSource(source, reason, detail)
	result.Analysis = analysis
	return result
}

func (s *Service) currentTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func successfulRoundCount(rounds []domain.DirectMetrics) int {
	count := 0
	for _, round := range rounds {
		if round.Success {
			count++
		}
	}
	return count
}

func mergeCDNFinding(analysis *domain.SiteAnalysis, finding cdnFinding) {
	if !finding.known {
		return
	}
	if analysis.CDNKnown && analysis.CDN {
		if !finding.detected {
			return
		}
		if analysis.CDNProvider != "" && finding.provider != "" && analysis.CDNProvider != finding.provider {
			analysis.CDNProvider = "Multiple"
			analysis.CDNConfidence = "high"
		}
		if analysis.CDNEvidence != finding.evidence && finding.evidence != "" {
			analysis.CDNEvidence = strings.Trim(analysis.CDNEvidence+"；"+finding.evidence, "；")
		}
		return
	}
	analysis.CDNKnown = true
	analysis.CDN = finding.detected
	analysis.CDNProvider = finding.provider
	analysis.CDNConfidence = finding.confidence
	analysis.CDNEvidence = finding.evidence
}
func classifyValidationFailure(err error) (string, string) {
	var target *validationError
	if errors.As(err, &target) {
		return target.reason, target.Error()
	}
	return "unverifiable", errorDetail(err)
}
func classifyTLSHandshakeError(err error) error {
	var authority x509.UnknownAuthorityError
	if errors.As(err, &authority) {
		return &validationError{reason: "certificate", err: err}
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return &validationError{reason: "sni", err: err}
	}
	return &validationError{reason: "network", err: err}
}
func isTransient(err error) bool {
	if err == nil {
		return false
	}
	var networkError net.Error
	if errors.As(err, &networkError) && (networkError.Timeout() || networkError.Temporary()) {
		return true
	}
	text := strings.ToLower(err.Error())
	for _, part := range []string{"timeout", "connection reset", "connection refused", "temporary", "network", "dns", "no such host", "eof"} {
		if strings.Contains(text, part) {
			return true
		}
	}
	return false
}
func safeStatus(status int) bool {
	return status == http.StatusOK || status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusNotFound
}
func normalizeDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}
func validDomain(value string) bool {
	if len(value) < 3 || len(value) > 253 || strings.Contains(value, "..") {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
func errorDetail(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
func sendSource(ctx context.Context, jobs chan<- domain.Source, source domain.Source) bool {
	select {
	case jobs <- source:
		return true
	case <-ctx.Done():
		return false
	}
}
