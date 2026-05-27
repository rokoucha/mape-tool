//go:build !linux

package apply

import (
	"fmt"
	"net"

	"github.com/rokoucha/mape-tool/internal/mape"
)

func FindPrefix(_ string, _ net.IPNet) (*net.IPNet, error) {
	return nil, fmt.Errorf("netlink: not supported on this platform")
}

func ApplyNetlink(_ *mape.Params, _ Config, _ *net.IPNet) error {
	return fmt.Errorf("netlink: not supported on this platform")
}

func RollbackNetlink(_ *mape.Params, _ Config, _ *net.IPNet) error {
	return fmt.Errorf("netlink: not supported on this platform")
}

func teardownTunnel(_ Config) error {
	return fmt.Errorf("netlink: not supported on this platform")
}
