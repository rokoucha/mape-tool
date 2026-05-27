package apply

import (
	"net"
	"strings"
	"testing"

	"github.com/rokoucha/mape-tool/internal/mape"
)

func TestNftablesRuleset(t *testing.T) {
	params := &mape.Params{
		CeIPv4:   net.IP{106, 0, 1, 0},
		PSID:     0,
		PSIDBits: 0,
		PortBlocks: []mape.PortBlock{
			{4096, 8191},
			{8192, 12287},
		},
	}

	got := Ruleset(params, "mape0")

	// add table must precede flush table so the ruleset works on a fresh system.
	addIdx := strings.Index(got, "add table ip mape")
	flushIdx := strings.Index(got, "flush table ip mape")
	if addIdx == -1 {
		t.Error("output missing: add table ip mape")
	}
	if flushIdx == -1 {
		t.Error("output missing: flush table ip mape")
	}
	if addIdx != -1 && flushIdx != -1 && addIdx >= flushIdx {
		t.Errorf("add table ip mape (pos %d) must appear before flush table ip mape (pos %d)", addIdx, flushIdx)
	}

	mustContain := []string{
		"flush table ip mape",
		"table ip mape {",
		"chain postrouting {",
		// Must not share the bare srcnat (100) priority with table ip nat to
		// avoid undefined chain ordering. Use srcnat + 10 instead.
		"type nat hook postrouting priority srcnat + 10; policy accept;",
		// TCP
		`oifname "mape0" meta l4proto tcp meta mark set jhash ip saddr . tcp sport mod 2`,
		`oifname "mape0" meta l4proto tcp meta mark 0 snat to 106.0.1.0:4096-8191 persistent`,
		`oifname "mape0" meta l4proto tcp meta mark 1 snat to 106.0.1.0:8192-12287 persistent`,
		// UDP
		`oifname "mape0" meta l4proto udp meta mark set jhash ip saddr . udp sport mod 2`,
		`oifname "mape0" meta l4proto udp meta mark 0 snat to 106.0.1.0:4096-8191 persistent`,
		`oifname "mape0" meta l4proto udp meta mark 1 snat to 106.0.1.0:8192-12287 persistent`,
		// ICMP
		`oifname "mape0" ip protocol icmp icmp type echo-request meta mark set jhash ip saddr . icmp id mod 2`,
		`oifname "mape0" ip protocol icmp icmp type echo-request meta mark 0 snat to 106.0.1.0:4096-8191 persistent`,
		`oifname "mape0" ip protocol icmp icmp type echo-request meta mark 1 snat to 106.0.1.0:8192-12287 persistent`,
	}

	for _, want := range mustContain {
		if !strings.Contains(got, want) {
			t.Errorf("output missing:\n  %s\n\nFull output:\n%s", want, got)
		}
	}
}
