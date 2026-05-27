package app

import (
	"fmt"

	"github.com/rokoucha/mape-tool/internal/apply"
	"github.com/rokoucha/mape-tool/internal/mape"
	"github.com/spf13/cobra"
)

type applyFlags struct {
	bmrFlags
	tunIf  string
	tunMTU int
	runDir string
	dryRun bool
}

type config struct {
	bmrConfig
	applyConfig apply.Config
}

func newApplyCmd() *cobra.Command {
	f := &applyFlags{}
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply MAP-E tunnel configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApply(f)
		},
	}
	addBMRFlags(cmd, &f.bmrFlags)
	cmd.Flags().StringVar(&f.tunIf, "tun-if", "mape0", "tunnel interface name")
	cmd.Flags().IntVar(&f.tunMTU, "tun-mtu", 1460, "tunnel MTU")
	cmd.Flags().StringVar(&f.runDir, "run-dir", "/run/mape", "directory for mape.nft")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "print what would be done without applying")
	return cmd
}

func buildConfig(f *applyFlags) (*config, error) {
	bmr, err := buildBMRConfig(&f.bmrFlags)
	if err != nil {
		return nil, err
	}
	return &config{
		bmrConfig: *bmr,
		applyConfig: apply.Config{
			WANIf:  bmr.wanIf,
			TunIf:  f.tunIf,
			TunMTU: f.tunMTU,
			RunDir: f.runDir,
			BRAddr: bmr.brAddr,
		},
	}, nil
}

func runApply(f *applyFlags) error {
	cfg, err := buildConfig(f)
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

	if f.dryRun {
		fmt.Println("--- nftables ruleset (dry-run) ---")
		fmt.Print(apply.Ruleset(params, cfg.applyConfig.TunIf))
		return nil
	}

	nftFile, err := apply.WriteNftables(params, cfg.applyConfig)
	if err != nil {
		return fmt.Errorf("write nftables: %w", err)
	}

	return apply.ApplyOps(
		func() error {
			if err := apply.ApplyNetlink(params, cfg.applyConfig, prefix); err != nil {
				return fmt.Errorf("apply netlink: %w", err)
			}
			return nil
		},
		func() error {
			if err := apply.ApplyNftables(nftFile); err != nil {
				return fmt.Errorf("apply nftables: %w", err)
			}
			return nil
		},
		func() error {
			if err := apply.RollbackNetlink(params, cfg.applyConfig, prefix); err != nil {
				return fmt.Errorf("rollback: %w", err)
			}
			return nil
		},
	)
}
