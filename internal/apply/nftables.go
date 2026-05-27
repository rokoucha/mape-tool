package apply

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rokoucha/mape-tool/internal/mape"
)

// Ruleset generates a complete nftables ruleset for the MAP-E SNAT table.
// It uses a dedicated "ip mape" table so it can be atomically replaced without
// touching the existing "ip nat" table that handles other SNAT/DNAT rules.
func Ruleset(p *mape.Params, tunIf string) string {
	n := len(p.PortBlocks)
	ceV4 := p.CeIPv4.String()

	var sb strings.Builder

	sb.WriteString("add table ip mape\n")
	sb.WriteString("flush table ip mape\n")
	sb.WriteString("table ip mape {\n")
	sb.WriteString("    chain postrouting {\n")
	sb.WriteString("        type nat hook postrouting priority srcnat + 10; policy accept;\n")
	sb.WriteString("\n")

	// TCP
	fmt.Fprintf(&sb, "        oifname %q meta l4proto tcp meta mark set jhash ip saddr . tcp sport mod %d\n", tunIf, n)
	for i, b := range p.PortBlocks {
		fmt.Fprintf(&sb, "        oifname %q meta l4proto tcp meta mark %d snat to %s:%d-%d persistent\n",
			tunIf, i, ceV4, b.Start, b.End)
	}
	sb.WriteString("\n")

	// UDP
	fmt.Fprintf(&sb, "        oifname %q meta l4proto udp meta mark set jhash ip saddr . udp sport mod %d\n", tunIf, n)
	for i, b := range p.PortBlocks {
		fmt.Fprintf(&sb, "        oifname %q meta l4proto udp meta mark %d snat to %s:%d-%d persistent\n",
			tunIf, i, ceV4, b.Start, b.End)
	}
	sb.WriteString("\n")

	// ICMP echo-request
	fmt.Fprintf(&sb, "        oifname %q ip protocol icmp icmp type echo-request meta mark set jhash ip saddr . icmp id mod %d\n", tunIf, n)
	for i, b := range p.PortBlocks {
		fmt.Fprintf(&sb, "        oifname %q ip protocol icmp icmp type echo-request meta mark %d snat to %s:%d-%d persistent\n",
			tunIf, i, ceV4, b.Start, b.End)
	}

	sb.WriteString("    }\n")
	sb.WriteString("}\n")

	return sb.String()
}

func WriteNftables(p *mape.Params, cfg Config) (string, error) {
	if err := os.MkdirAll(cfg.RunDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", cfg.RunDir, err)
	}

	nftFile := filepath.Join(cfg.RunDir, "mape.nft")
	if err := os.WriteFile(nftFile, []byte(Ruleset(p, cfg.TunIf)), 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", nftFile, err)
	}

	fmt.Printf("Wrote %s\n", nftFile)
	return nftFile, nil
}

func ApplyNftables(nftFile string) error {
	cmd := exec.Command("nft", "-f", nftFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f %s: %w", nftFile, err)
	}
	fmt.Println("Applied nftables rules")
	return nil
}
