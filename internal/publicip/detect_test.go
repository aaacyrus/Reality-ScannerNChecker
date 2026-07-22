package publicip

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestIsPublicIPv4(t *testing.T) {
	t.Parallel()
	tests := []struct {
		address string
		want    bool
	}{
		{address: "1.1.1.1", want: true},
		{address: "8.8.8.8", want: true},
		{address: "10.0.0.1", want: false},
		{address: "100.64.0.1", want: false},
		{address: "127.0.0.1", want: false},
		{address: "169.254.1.1", want: false},
		{address: "192.0.2.1", want: false},
		{address: "198.18.0.1", want: false},
		{address: "203.0.113.1", want: false},
		{address: "::1", want: false},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			if got := IsPublicIPv4(netip.MustParseAddr(test.address)); got != test.want {
				t.Fatalf("IsPublicIPv4(%s) = %v, want %v", test.address, got, test.want)
			}
		})
	}
}

func TestDetectorPrefersSinglePublicInterface(t *testing.T) {
	t.Parallel()
	detector := &Detector{
		Interfaces: func() ([]net.Addr, error) {
			return []net.Addr{
				&net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.CIDRMask(24, 32)},
				&net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.CIDRMask(24, 32)},
			}, nil
		},
	}
	result, err := detector.Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Detected.String(); got != "1.1.1.1" {
		t.Fatalf("detected %s", got)
	}
	if result.Source != "interface" {
		t.Fatalf("source = %s", result.Source)
	}
}

func TestDetectorRequiresTwoMatchingHTTPSResults(t *testing.T) {
	t.Parallel()
	server := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
	}
	first := server("8.8.8.8\n")
	defer first.Close()
	second := server("8.8.8.8")
	defer second.Close()
	detector := &Detector{
		Interfaces: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)}}, nil
		},
		Endpoints: []string{first.URL, second.URL},
		Client:    first.Client(),
	}
	result, err := detector.Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Detected.String(); got != "8.8.8.8" {
		t.Fatalf("detected %s", got)
	}

	third := server("1.1.1.1")
	defer third.Close()
	detector.Endpoints[1] = third.URL
	result, err = detector.Detect(context.Background())
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("error = %v, want ErrAmbiguous", err)
	}
	if len(result.Candidates) != 2 {
		t.Fatalf("candidates = %v", result.Candidates)
	}
}
