package app

import (
	"fmt"

	"github.com/rokoucha/mape-tool/internal/apply"
	"github.com/rokoucha/mape-tool/internal/mape"
	"github.com/spf13/cobra"
)

func newCalcCmd() *cobra.Command {
	f := &bmrFlags{}
	cmd := &cobra.Command{
		Use:   "calc",
		Short: "Calculate MAP-E parameters without applying",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCalc(f)
		},
	}
	addBMRFlags(cmd, f)
	return cmd
}

func runCalc(f *bmrFlags) error {
	cfg, err := buildBMRConfig(f)
	if err != nil {
		return err
	}

	prefix, err := apply.FindPrefix(cfg.wanIf, cfg.ruleIPv6)
	if err != nil {
		return fmt.Errorf("find prefix on %s: %w", cfg.wanIf, err)
	}

	params, err := mape.Derive(*prefix, mape.BMR{
		IPv6Prefix: cfg.ruleIPv6,
		IPv4Prefix: cfg.ruleIPv4,
		EABits:     cfg.eaBits,
		PSIDBits:   cfg.psidBits,
		PSIDOffset: cfg.psidOffset,
		BRAddr:     cfg.brAddr,
	})
	if err != nil {
		return err
	}

	printParams(prefix, params, cfg.wanIf)
	return nil
}
