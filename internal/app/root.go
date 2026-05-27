package app

import (
	"fmt"
	"net"

	"github.com/rokoucha/mape-tool/internal/mape"
	"github.com/spf13/cobra"
)

func Execute() error {
	root := &cobra.Command{
		Use:           "mape-tool",
		Short:         "MAP-E tunnel configurator",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newCalcCmd())
	root.AddCommand(newApplyCmd())

	return root.Execute()
}

type bmrFlags struct {
	ruleIPv6   string
	ruleIPv4   string
	eaBits     int
	psidBits   int
	psidOffset int
	brAddr     string
	wanIf      string
}

type bmrConfig struct {
	ruleIPv6   net.IPNet
	ruleIPv4   net.IPNet
	eaBits     int
	psidBits   int
	psidOffset int
	brAddr     net.IP
	wanIf      string
}

func buildBMRConfig(f *bmrFlags) (*bmrConfig, error) {
	_, ruleIPv6, err := net.ParseCIDR(f.ruleIPv6)
	if err != nil {
		return nil, fmt.Errorf("--rule-ipv6 %q: %w", f.ruleIPv6, err)
	}

	_, ruleIPv4, err := net.ParseCIDR(f.ruleIPv4)
	if err != nil {
		return nil, fmt.Errorf("--rule-ipv4 %q: %w", f.ruleIPv4, err)
	}

	if f.eaBits < 1 {
		return nil, fmt.Errorf("--ea-bits must be >= 1, got %d", f.eaBits)
	}
	if f.psidBits < 0 || f.psidBits > 16 {
		return nil, fmt.Errorf("--psid-bits must be 0..16, got %d", f.psidBits)
	}
	if f.psidOffset < 1 || f.psidOffset > 15 {
		return nil, fmt.Errorf("--psid-offset must be 1..15, got %d", f.psidOffset)
	}
	if f.psidOffset+f.psidBits > 16 {
		return nil, fmt.Errorf("--psid-offset + --psid-bits must be <= 16, got %d+%d=%d",
			f.psidOffset, f.psidBits, f.psidOffset+f.psidBits)
	}

	ruleLen, _ := ruleIPv6.Mask.Size()
	if ruleLen+f.eaBits > 64 {
		return nil, fmt.Errorf("rule IPv6 prefix length (%d) + EA bits (%d) = %d exceeds 64: "+
			"findPrefix masks to /64 and would corrupt EA bits",
			ruleLen, f.eaBits, ruleLen+f.eaBits)
	}

	brAddr := net.ParseIP(f.brAddr)
	if brAddr == nil {
		return nil, fmt.Errorf("--br-addr %q: invalid IP", f.brAddr)
	}
	if brAddr.To4() != nil {
		return nil, fmt.Errorf("--br-addr %q: must be an IPv6 address, got IPv4", f.brAddr)
	}

	return &bmrConfig{
		ruleIPv6:   *ruleIPv6,
		ruleIPv4:   *ruleIPv4,
		eaBits:     f.eaBits,
		psidBits:   f.psidBits,
		psidOffset: f.psidOffset,
		brAddr:     brAddr,
		wanIf:      f.wanIf,
	}, nil
}

func addBMRFlags(cmd *cobra.Command, f *bmrFlags) {
	cmd.Flags().StringVar(&f.ruleIPv6, "rule-ipv6", "240b:10::/31", "IPv6 rule prefix")
	cmd.Flags().StringVar(&f.ruleIPv4, "rule-ipv4", "106.72.0.0/15", "IPv4 rule prefix")
	cmd.Flags().IntVar(&f.eaBits, "ea-bits", 25, "EA-bits length")
	cmd.Flags().IntVar(&f.psidBits, "psid-bits", 8, "PSID length / k")
	cmd.Flags().IntVar(&f.psidOffset, "psid-offset", 4, "PSID offset / a")
	cmd.Flags().StringVar(&f.brAddr, "br-addr", "2404:9200:225:100::64", "border router IPv6 address")
	cmd.Flags().StringVar(&f.wanIf, "wan-if", "enp5s0f0", "WAN interface name")
}

func printParams(prefix *net.IPNet, params *mape.Params, wanIf string) {
	fmt.Printf("Prefix:      %s (from %s)\n", prefix, wanIf)
	fmt.Printf("CE IPv4:     %s\n", params.CeIPv4)
	fmt.Printf("PSID:        %d (k=%d bits)\n", params.PSID, params.PSIDBits)
	fmt.Printf("Port blocks: %d blocks\n", len(params.PortBlocks))
	for _, b := range params.PortBlocks {
		fmt.Printf("  %d-%d\n", b.Start, b.End)
	}
	fmt.Printf("Token:       %s\n", params.Token)
	fmt.Println()
}
