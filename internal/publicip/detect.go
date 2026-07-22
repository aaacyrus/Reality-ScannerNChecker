package publicip

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrAmbiguous = errors.New("public IPv4 detection returned multiple candidates")

type Result struct {
	Detected   netip.Addr
	Candidates []netip.Addr
	Source     string
}

type Detector struct {
	Interfaces func() ([]net.Addr, error)
	Endpoints  []string
	Client     *http.Client
}

func NewDetector() *Detector {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Detector{
		Interfaces: net.InterfaceAddrs,
		Endpoints: []string{
			"https://api.ipify.org",
			"https://checkip.amazonaws.com",
		},
		Client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		},
	}
}

// Detect first examines local interfaces, then cross-checks two direct HTTPS
// services when the host is behind NAT.
func (d *Detector) Detect(ctx context.Context) (Result, error) {
	local, err := d.detectInterfaces()
	if err == nil && len(local) == 1 {
		return Result{Detected: local[0], Candidates: local, Source: "interface"}, nil
	}
	if len(local) > 1 {
		return Result{Candidates: local, Source: "interface"}, ErrAmbiguous
	}

	external := d.detectExternal(ctx)
	if len(external) == 0 {
		if err != nil {
			return Result{}, fmt.Errorf("interface detection failed: %w", err)
		}
		return Result{}, errors.New("unable to detect a public IPv4 address")
	}
	if len(external) == 1 && len(d.Endpoints) >= 2 {
		return Result{Candidates: external, Source: "https"}, ErrAmbiguous
	}
	if allEqual(external) {
		return Result{Detected: external[0], Candidates: []netip.Addr{external[0]}, Source: "https"}, nil
	}
	return Result{Candidates: dedupe(external), Source: "https"}, ErrAmbiguous
}

func (d *Detector) detectInterfaces() ([]netip.Addr, error) {
	addresses, err := d.Interfaces()
	if err != nil {
		return nil, err
	}
	var found []netip.Addr
	for _, address := range addresses {
		raw := address.String()
		if slash := strings.IndexByte(raw, '/'); slash >= 0 {
			raw = raw[:slash]
		}
		ip, err := netip.ParseAddr(raw)
		if err == nil && IsPublicIPv4(ip) {
			found = append(found, ip)
		}
	}
	return dedupe(found), nil
}

func (d *Detector) detectExternal(ctx context.Context) []netip.Addr {
	type response struct {
		index int
		ip    netip.Addr
	}
	responses := make(chan response, len(d.Endpoints))
	var wg sync.WaitGroup
	for index, endpoint := range d.Endpoints {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			if err != nil {
				return
			}
			resp, err := d.Client.Do(request)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
			if err != nil {
				return
			}
			ip, err := netip.ParseAddr(strings.TrimSpace(string(body)))
			if err == nil && IsPublicIPv4(ip) {
				responses <- response{index: index, ip: ip}
			}
		}()
	}
	wg.Wait()
	close(responses)
	ordered := make([]response, 0, len(d.Endpoints))
	for item := range responses {
		ordered = append(ordered, item)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].index < ordered[j].index })
	result := make([]netip.Addr, 0, len(ordered))
	for _, item := range ordered {
		result = append(result, item.ip)
	}
	return result
}

func IsPublicIPv4(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() ||
		ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, prefix := range reservedIPv4Prefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

var reservedIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func allEqual(items []netip.Addr) bool {
	if len(items) < 2 {
		return false
	}
	for _, item := range items[1:] {
		if item != items[0] {
			return false
		}
	}
	return true
}

func dedupe(items []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(items))
	result := make([]netip.Addr, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	return result
}
