//go:build linux

package apply

import (
	"net"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
)

type stubLink struct{ attrs netlink.LinkAttrs }

func (s *stubLink) Attrs() *netlink.LinkAttrs { return &s.attrs }
func (s *stubLink) Type() string              { return "stub" }

func ip(s string) net.IP { return net.ParseIP(s) }

func makeIp6tnl(local, remote net.IP, proto uint8, flags uint32, mtu int) *netlink.Ip6tnl {
	return &netlink.Ip6tnl{
		LinkAttrs: netlink.LinkAttrs{MTU: mtu},
		Local:     local,
		Remote:    remote,
		Proto:     proto,
		Flags:     flags,
	}
}

func TestTunnelUnchanged(t *testing.T) {
	ceAddr := ip("2001:db8::1")
	brAddr := ip("2404:9200:225:100::64")
	mtu := 1460

	cfg := Config{
		BRAddr: brAddr,
		TunMTU: mtu,
	}

	tests := []struct {
		name   string
		link   netlink.Link
		ceAddr net.IP
		want   bool
	}{
		{
			name:   "non-Ip6tnl link",
			link:   &stubLink{attrs: netlink.LinkAttrs{MTU: mtu}},
			ceAddr: ceAddr,
			want:   false,
		},
		{
			name:   "all params match",
			link:   makeIp6tnl(ceAddr, brAddr, syscall.IPPROTO_IPIP, 0x1, mtu),
			ceAddr: ceAddr,
			want:   true,
		},
		{
			name:   "local address differs",
			link:   makeIp6tnl(ip("2001:db8::2"), brAddr, syscall.IPPROTO_IPIP, 0x1, mtu),
			ceAddr: ceAddr,
			want:   false,
		},
		{
			name:   "remote address differs",
			link:   makeIp6tnl(ceAddr, ip("2404:9200::1"), syscall.IPPROTO_IPIP, 0x1, mtu),
			ceAddr: ceAddr,
			want:   false,
		},
		{
			name:   "proto differs",
			link:   makeIp6tnl(ceAddr, brAddr, syscall.IPPROTO_IPV6, 0x1, mtu),
			ceAddr: ceAddr,
			want:   false,
		},
		{
			name:   "flags differ",
			link:   makeIp6tnl(ceAddr, brAddr, syscall.IPPROTO_IPIP, 0x0, mtu),
			ceAddr: ceAddr,
			want:   false,
		},
		{
			name:   "MTU differs",
			link:   makeIp6tnl(ceAddr, brAddr, syscall.IPPROTO_IPIP, 0x1, 1280),
			ceAddr: ceAddr,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tunnelUnchanged(tt.link, tt.ceAddr, cfg)
			if got != tt.want {
				t.Errorf("tunnelUnchanged() = %v, want %v", got, tt.want)
			}
		})
	}
}
