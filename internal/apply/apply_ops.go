package apply

import "fmt"

// ApplyOps runs the full apply sequence with rollback on nftables failure.
// If netlink succeeds but nftables fails, rollback is called to tear down
// the half-applied tunnel so the system does not silently drop traffic.
func ApplyOps(netlink func() error, nftables func() error, rollback func() error) error {
	if err := netlink(); err != nil {
		return err
	}
	if err := nftables(); err != nil {
		if rbErr := rollback(); rbErr != nil {
			return fmt.Errorf("nftables failed (%w); rollback also failed: %v", err, rbErr)
		}
		return err
	}
	return nil
}
