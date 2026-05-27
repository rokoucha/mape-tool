package apply

import "net"

type Config struct {
	WANIf  string
	TunIf  string
	TunMTU int
	RunDir string
	BRAddr net.IP
}
