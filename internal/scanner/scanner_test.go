package scanner

import (
	"context"
	"net/netip"
	"testing"
)

func TestNearbySequenceStartsAtSeedAndAlternates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var got []netip.Addr
	forEachNearbyIPv4(ctx, netip.MustParseAddr("192.0.2.10"), func(ip netip.Addr) bool {
		got = append(got, ip)
		return len(got) < 5
	})
	want := []string{"192.0.2.10", "192.0.2.9", "192.0.2.11", "192.0.2.8", "192.0.2.12"}
	for index, expected := range want {
		if got[index].String() != expected {
			t.Fatalf("address %d = %s, want %s", index, got[index], expected)
		}
	}
}
