package mape

import (
	"encoding/binary"
	"fmt"
	"net"
)

type BMR struct {
	IPv6Prefix net.IPNet
	IPv4Prefix net.IPNet
	EABits     int
	PSIDBits   int // k: PSID length
	PSIDOffset int // a: number of high-order port bits excluded (ports 0..2^(16-a)-1 unused)
	BRAddr     net.IP
}

type PortBlock struct {
	Start int
	End   int
}

type Params struct {
	CeIPv4     net.IP
	PSID       int
	PSIDBits   int // k
	PortBlocks []PortBlock
	Token      string // networkd Token value (e.g. "::6a:483f:6c00:d400")
}

// Derive calculates MAP-E CE parameters from a CE IPv6 prefix and a BMR.
// The CE IPv6 prefix is the /64 (or longer) subnet assigned to the MAP-E
// tunnel via DHCPv6-PD (SubnetId=0 of the ISP-delegated /56).
func Derive(cePDPrefix net.IPNet, bmr BMR) (*Params, error) {
	ruleLen, _ := bmr.IPv6Prefix.Mask.Size()
	pdLen, _ := cePDPrefix.Mask.Size()

	if pdLen < ruleLen+bmr.EABits {
		return nil, fmt.Errorf("prefix /%d too short: need at least /%d to contain %d EA bits after rule prefix /%d",
			pdLen, ruleLen+bmr.EABits, bmr.EABits, ruleLen)
	}

	eaBits, err := extractBits(cePDPrefix.IP, ruleLen, bmr.EABits)
	if err != nil {
		return nil, fmt.Errorf("extract EA bits: %w", err)
	}

	ipv4PrefixLen, _ := bmr.IPv4Prefix.Mask.Size()
	ipv4SuffixBits := 32 - ipv4PrefixLen
	psidBits := bmr.EABits - ipv4SuffixBits
	if psidBits != bmr.PSIDBits {
		return nil, fmt.Errorf("inconsistent PSIDBits: BMR says %d but RFC 7597 §5.1 derives %d (EABits=%d, IPv4PrefixLen=%d)",
			bmr.PSIDBits, psidBits, bmr.EABits, ipv4PrefixLen)
	}

	ipv4Suffix := eaBits >> uint(psidBits)
	psid := eaBits & ((1 << uint(psidBits)) - 1)

	ceIPv4, err := buildIPv4(bmr.IPv4Prefix, ipv4Suffix)
	if err != nil {
		return nil, fmt.Errorf("build CE IPv4: %w", err)
	}

	blocks, err := portBlocks(psid, psidBits, bmr.PSIDOffset)
	if err != nil {
		return nil, err
	}

	token := buildToken(ceIPv4, psid, psidBits)

	return &Params{
		CeIPv4:     ceIPv4,
		PSID:       psid,
		PSIDBits:   psidBits,
		PortBlocks: blocks,
		Token:      token,
	}, nil
}

// extractBits extracts `length` bits from ip starting at bit offset `start`.
// ip must be a 16-byte IPv6 address slice.
func extractBits(ip net.IP, start, length int) (int, error) {
	ip = ip.To16()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv6 address")
	}
	if start < 0 || length < 0 || start+length > 128 {
		return 0, fmt.Errorf("bit range [%d, %d) out of bounds for 128-bit address", start, start+length)
	}
	result := 0
	for i := 0; i < length; i++ {
		bitPos := start + i
		byteIdx := bitPos / 8
		bitIdx := 7 - (bitPos % 8)
		bit := (int(ip[byteIdx]) >> uint(bitIdx)) & 1
		result = (result << 1) | bit
	}
	return result, nil
}

// buildIPv4 constructs the CE IPv4 address by OR-ing suffix into the host
// bits of prefix. suffix width equals 32 - prefixLen, so no shift is needed.
func buildIPv4(prefix net.IPNet, suffix int) (net.IP, error) {
	base := prefix.IP.To4()
	if base == nil {
		return nil, fmt.Errorf("rule IPv4 prefix is not IPv4")
	}
	n := binary.BigEndian.Uint32(base)
	n |= uint32(suffix)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip, nil
}

// portBlocks returns the list of valid port blocks for the given PSID.
// RFC 7597 port assignment: port p belongs to this CE if
//
//	p >> (16-a) != 0  (exclude ports 0..2^(16-a)-1 where the high `a` bits are 0)
//	(p >> q) & ((1<<k)-1) == PSID
//
// where q = 16 - a - k.
func portBlocks(psid, psidBits, psidOffset int) ([]PortBlock, error) {
	a := psidOffset
	k := psidBits
	q := 16 - a - k
	if q < 0 {
		return nil, fmt.Errorf("invalid parameters: a=%d k=%d gives q=%d < 0", a, k, q)
	}
	blockSize := 1 << uint(q)
	numBlocks := (1 << uint(a)) - 1 // 2^a blocks minus the excluded A=0 block
	if numBlocks == 0 {
		return nil, fmt.Errorf("psidOffset=%d produces zero port blocks (mod 0 is invalid in nftables)", a)
	}

	blocks := make([]PortBlock, 0, numBlocks)
	for A := 1; A <= (1<<uint(a))-1; A++ {
		start := (A << uint(16-a)) | (psid << uint(q))
		blocks = append(blocks, PortBlock{
			Start: start,
			End:   start + blockSize - 1,
		})
	}
	return blocks, nil
}

// buildToken computes the networkd Token string for the MAP-E CE IPv6 address.
//
// v6plus (JPNE/NTT) uses a non-RFC IID layout:
//
//	[0x00][IPv4_b0][IPv4_b1][IPv4_b2][IPv4_b3][0x00][PSID][0x00]
//
// RFC 7597 §6 defines [0x0000][IPv4 32-bit][PSID left-aligned 16-bit], which
// differs by a 1-byte shift. v6plus appears to have been implemented against a
// draft revision before the final RFC and the format was never corrected.
func buildToken(ceIPv4 net.IP, psid int, psidBits int) string {
	ip4 := ceIPv4.To4()
	g0 := uint16(ip4[0])
	g1 := uint16(ip4[1])<<8 | uint16(ip4[2])
	g2 := uint16(ip4[3]) << 8
	g3 := uint16(psid) << uint(16-psidBits)
	return fmt.Sprintf("::%x:%x:%x:%x", g0, g1, g2, g3)
}
