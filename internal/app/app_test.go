package app

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/aaacyrus/Reality-ScannerNChecker/internal/publicip"
	"github.com/aaacyrus/Reality-ScannerNChecker/internal/ui"
)

func TestPrefixDetails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		prefix string
		count  int64
		first  string
		last   string
	}{
		{prefix: "203.0.113.0/24", count: 256, first: "203.0.113.0", last: "203.0.113.255"},
		{prefix: "203.0.112.0/23", count: 512, first: "203.0.112.0", last: "203.0.113.255"},
		{prefix: "203.0.112.0/22", count: 1024, first: "203.0.112.0", last: "203.0.115.255"},
		{prefix: "203.0.112.0/21", count: 2048, first: "203.0.112.0", last: "203.0.119.255"},
		{prefix: "203.0.112.0/20", count: 4096, first: "203.0.112.0", last: "203.0.127.255"},
		{prefix: "203.0.96.0/19", count: 8192, first: "203.0.96.0", last: "203.0.127.255"},
		{prefix: "203.0.64.0/18", count: 16384, first: "203.0.64.0", last: "203.0.127.255"},
		{prefix: "203.0.0.0/17", count: 32768, first: "203.0.0.0", last: "203.0.127.255"},
	}
	for _, test := range tests {
		prefix := netip.MustParsePrefix(test.prefix)
		if got := prefixCount(prefix); got != test.count {
			t.Fatalf("%s count = %d, want %d", prefix, got, test.count)
		}
		first, last := prefixEndpoints(prefix)
		if first.String() != test.first || last.String() != test.last {
			t.Fatalf("%s range = %s - %s, want %s - %s", prefix, first, last, test.first, test.last)
		}
	}
}

func TestFormattingHelpers(t *testing.T) {
	t.Parallel()
	if got := formatInt(1024); got != "1,024" {
		t.Fatalf("formatInt = %s", got)
	}
	if got := compactDuration(65 * time.Second); got != "1m05s" {
		t.Fatalf("compactDuration = %s", got)
	}
}

func TestDetectPublicIPUsesDetectedAddressAsInputDefault(t *testing.T) {
	t.Parallel()
	var output strings.Builder
	app := &App{
		console: ui.NewConsole(strings.NewReader("\n"), &output, false),
		ip: &publicip.Detector{
			Interfaces: func() ([]net.Addr, error) {
				return []net.Addr{&net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.CIDRMask(24, 32)}}, nil
			},
		},
	}
	app.console.SetLanguage("en")

	ip, err := app.detectPublicIP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "1.1.1.1" {
		t.Fatalf("detected IP = %s, want 1.1.1.1", got)
	}
	if got := output.String(); !strings.Contains(got, "Enter scan seed IPv4 [default 1.1.1.1]:") {
		t.Fatalf("input prompt did not show detected IPv4 as default:\n%s", got)
	}
}

func TestDetectPublicIPAcceptsManualAddress(t *testing.T) {
	t.Parallel()
	app := &App{
		console: ui.NewConsole(strings.NewReader("8.8.8.8\n"), &strings.Builder{}, false),
		ip: &publicip.Detector{
			Interfaces: func() ([]net.Addr, error) {
				return []net.Addr{&net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.CIDRMask(24, 32)}}, nil
			},
		},
	}
	app.console.SetLanguage("en")

	ip, err := app.detectPublicIP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "8.8.8.8" {
		t.Fatalf("manual IP = %s, want 8.8.8.8", got)
	}
}
