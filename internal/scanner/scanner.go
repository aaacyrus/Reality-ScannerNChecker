// Package scanner discovers TLS endpoints inside an explicitly selected IPv4 range.
package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Prefix      netip.Prefix
	Seed        netip.Addr
	Infinite    bool
	Port        int
	Concurrency int
	Timeout     time.Duration
}

type Result struct {
	IP                   netip.Addr
	Origin               string
	TLSVersion           string
	ALPN                 string
	Curve                string
	CertificateLength    int
	CertificateCount     int
	CertificateSignature string
	CertificatePublicKey string
	CommonName           string
	DNSNames             []string
	CertificateIssuer    string
	TCPDuration          time.Duration
	TLSHandshakeDuration time.Duration
}

type Progress struct {
	Scanned int64
	Total   int64
	Found   int64
	Failed  int64
	Current netip.Addr
	Elapsed time.Duration
}

type ProgressFunc func(Progress)

func Scan(ctx context.Context, cfg Config, report ProgressFunc) ([]Result, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	started := time.Now()
	total := int64(0)
	if !cfg.Infinite {
		total = int64(1) << (32 - cfg.Prefix.Bits())
	}
	jobs := make(chan netip.Addr)
	results := make(chan Result)
	var scanned, found, failed atomic.Int64
	var workers sync.WaitGroup
	workers.Add(cfg.Concurrency)
	for range cfg.Concurrency {
		go func() {
			defer workers.Done()
			for ip := range jobs {
				result, err := probe(ctx, cfg, ip)
				current := scanned.Add(1)
				if err == nil {
					found.Add(1)
					select {
					case results <- result:
					case <-ctx.Done():
						return
					}
				} else {
					failed.Add(1)
				}
				if report != nil {
					report(Progress{Scanned: current, Total: total, Found: found.Load(), Failed: failed.Load(), Current: ip, Elapsed: time.Since(started)})
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		if cfg.Infinite {
			forEachNearbyIPv4(ctx, cfg.Seed, func(ip netip.Addr) bool { return send(ctx, jobs, ip) })
			return
		}
		for ip := cfg.Prefix.Masked().Addr(); cfg.Prefix.Contains(ip); ip = ip.Next() {
			if !send(ctx, jobs, ip) {
				return
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()

	collected := make([]Result, 0)
	for result := range results {
		collected = append(collected, result)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(collected, func(i, j int) bool { return collected[i].IP.Less(collected[j].IP) })
	return collected, nil
}

func validateConfig(cfg Config) error {
	if cfg.Port != 443 {
		return errors.New("only TCP port 443 is supported")
	}
	if cfg.Concurrency < 1 || cfg.Timeout <= 0 {
		return errors.New("concurrency and timeout must be positive")
	}
	if cfg.Infinite && cfg.Seed.Is4() {
		return nil
	}
	if !cfg.Infinite && cfg.Prefix.IsValid() && cfg.Prefix.Addr().Is4() {
		return nil
	}
	return errors.New("an IPv4 seed or prefix is required")
}

func probe(ctx context.Context, cfg Config, ip netip.Addr) (Result, error) {
	attempt, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	dialer := net.Dialer{Timeout: cfg.Timeout}
	address := net.JoinHostPort(ip.String(), strconv.Itoa(cfg.Port))
	tcpStarted := time.Now()
	connection, err := dialer.DialContext(attempt, "tcp", address)
	if err != nil {
		return Result{}, err
	}
	defer connection.Close()
	tcpTime := time.Since(tcpStarted)
	deadline, _ := attempt.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return Result{}, err
	}
	tlsConnection := tls.Client(connection, &tls.Config{
		InsecureSkipVerify: true, // discovery only; candidates are verified later with their SNI.
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519},
	})
	tlsStarted := time.Now()
	if err := tlsConnection.HandshakeContext(attempt); err != nil {
		return Result{}, err
	}
	state := tlsConnection.ConnectionState()
	if state.NegotiatedProtocol != "h2" || len(state.PeerCertificates) == 0 {
		return Result{}, errors.New("endpoint does not offer the required TLS profile")
	}
	leaf := certificateWithNames(state.PeerCertificates)
	if strings.TrimSpace(leaf.Subject.CommonName) == "" && len(leaf.DNSNames) == 0 {
		return Result{}, errors.New("certificate contains no domain names")
	}
	bytes := 0
	for _, certificate := range state.PeerCertificates {
		bytes += len(certificate.Raw)
	}
	return Result{
		IP: ip, Origin: ip.String(), TLSVersion: tls.VersionName(state.Version), ALPN: state.NegotiatedProtocol,
		Curve: state.CurveID.String(), CertificateLength: bytes, CertificateCount: len(state.PeerCertificates),
		CertificateSignature: leaf.SignatureAlgorithm.String(), CertificatePublicKey: leaf.PublicKeyAlgorithm.String(),
		CommonName: strings.TrimSpace(leaf.Subject.CommonName), DNSNames: append([]string(nil), leaf.DNSNames...),
		CertificateIssuer: strings.Join(leaf.Issuer.Organization, " | "), TCPDuration: tcpTime,
		TLSHandshakeDuration: time.Since(tlsStarted),
	}, nil
}

func certificateWithNames(certificates []*x509.Certificate) *x509.Certificate {
	for _, certificate := range certificates {
		if len(certificate.DNSNames) > 0 {
			return certificate
		}
	}
	return certificates[0]
}

func forEachNearbyIPv4(ctx context.Context, seed netip.Addr, visit func(netip.Addr) bool) {
	if !visit(seed) {
		return
	}
	low, high := seed, seed
	for {
		if previous := low.Prev(); previous.IsValid() && previous.Is4() {
			low = previous
			if !visit(low) {
				return
			}
		}
		if next := high.Next(); next.IsValid() && next.Is4() {
			high = next
			if !visit(high) {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !low.Prev().IsValid() && !high.Next().IsValid() {
			return
		}
	}
}

func send(ctx context.Context, out chan<- netip.Addr, ip netip.Addr) bool {
	select {
	case out <- ip:
		return true
	case <-ctx.Done():
		return false
	}
}
