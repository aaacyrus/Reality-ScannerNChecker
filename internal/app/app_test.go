package app

import (
	"net/netip"
	"testing"
	"time"
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
