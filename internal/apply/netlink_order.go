package apply

import "fmt"

// netlinkApplyOrder runs MAP-E netlink operations in the correct sequence:
// CE IPv6 must be assigned to the WAN interface before the tunnel is created,
// because the kernel validates the Local address exists at LinkAdd time.
func netlinkApplyOrder(assignWAN func() error, setupTunnel func() error) error {
	if err := assignWAN(); err != nil {
		return err
	}
	return setupTunnel()
}

// netlinkRollbackOrder cleans up after a partial apply: both operations are
// attempted regardless of individual failures so the system is left as clean
// as possible. Errors from both are combined and returned.
func netlinkRollbackOrder(removeAddr func() error, teardownTunnel func() error) error {
	var errs []string
	if err := removeAddr(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := teardownTunnel(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("rollback errors: %v", errs)
	}
	return nil
}
