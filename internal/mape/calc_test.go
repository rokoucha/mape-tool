package mape

import (
	"net"
	"testing"
)

func mustCIDR(s string) net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *n
}

var nttBMR = BMR{
	IPv6Prefix: mustCIDR("240b:10::/31"),
	IPv4Prefix: mustCIDR("106.72.0.0/15"),
	EABits:     25,
	PSIDBits:   8,
	PSIDOffset: 4,
	BRAddr:     net.ParseIP("2404:9200:225:100::64"),
}

func TestDerive(t *testing.T) {
	// psid=0 のポートブロック: a=4, k=8, q=4, blockSize=16
	psid0Blocks := []PortBlock{
		{4096, 4111}, {8192, 8207}, {12288, 12303}, {16384, 16399},
		{20480, 20495}, {24576, 24591}, {28672, 28687}, {32768, 32783},
		{36864, 36879}, {40960, 40975}, {45056, 45071}, {49152, 49167},
		{53248, 53263}, {57344, 57359}, {61440, 61455},
	}

	tests := []struct {
		name       string
		prefix     string
		wantIPv4   string
		wantPSID   int
		wantK      int
		wantToken  string
		wantBlocks []PortBlock
	}{
		{
			// EA bits = 256 (ipv4Suffix=1, psid=0) → 106.72.0.1
			// bits[31..55]: bit[16]=1, rest=0 → 240b:10:1:0::/64
			name:       "240b:10:1:0::/64",
			prefix:     "240b:10:1:0::/64",
			wantIPv4:   "106.72.0.1",
			wantPSID:   0,
			wantK:      8,
			wantToken:  "::6a:4800:100:0",
			wantBlocks: psid0Blocks,
		},
		{
			// EA bits = 16777216 (ipv4Suffix=65536=0x10000, psid=0) → 106.73.0.0
			// bits[31..55]: bit[0]=1 (IPv6 bit31=1), rest=0 → 240b:11:0:0::/64
			name:       "240b:11:0:0::/64",
			prefix:     "240b:11:0:0::/64",
			wantIPv4:   "106.73.0.0",
			wantPSID:   0,
			wantK:      8,
			wantToken:  "::6a:4900:0:0",
			wantBlocks: psid0Blocks,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := Derive(mustCIDR(tt.prefix), nttBMR)
			if err != nil {
				t.Fatalf("Derive: %v", err)
			}
			if got := params.CeIPv4.String(); got != tt.wantIPv4 {
				t.Errorf("CeIPv4 = %s, want %s", got, tt.wantIPv4)
			}
			if params.PSID != tt.wantPSID {
				t.Errorf("PSID = %d, want %d", params.PSID, tt.wantPSID)
			}
			if params.PSIDBits != tt.wantK {
				t.Errorf("PSIDBits = %d, want %d", params.PSIDBits, tt.wantK)
			}
			if params.Token != tt.wantToken {
				t.Errorf("Token = %s, want %s", params.Token, tt.wantToken)
			}
			if len(params.PortBlocks) != len(tt.wantBlocks) {
				t.Fatalf("len(PortBlocks) = %d, want %d", len(params.PortBlocks), len(tt.wantBlocks))
			}
			for i, b := range params.PortBlocks {
				if b != tt.wantBlocks[i] {
					t.Errorf("PortBlocks[%d] = {%d, %d}, want {%d, %d}", i, b.Start, b.End, tt.wantBlocks[i].Start, tt.wantBlocks[i].End)
				}
			}
		})
	}
}

func TestDeriveNTT(t *testing.T) {
	wantBlocks := []PortBlock{
		{7488, 7503}, {11584, 11599}, {15680, 15695}, {19776, 19791},
		{23872, 23887}, {27968, 27983}, {32064, 32079}, {36160, 36175},
		{40256, 40271}, {44352, 44367}, {48448, 48463}, {52544, 52559},
		{56640, 56655}, {60736, 60751}, {64832, 64847},
	}

	params, err := Derive(mustCIDR("240b:10:3f6c:d400::/56"), nttBMR)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if got := params.CeIPv4.String(); got != "106.72.63.108" {
		t.Errorf("CeIPv4 = %s, want 106.72.63.108", got)
	}
	if params.PSID != 212 {
		t.Errorf("PSID = %d, want 212", params.PSID)
	}
	if params.PSIDBits != 8 {
		t.Errorf("PSIDBits = %d, want 8", params.PSIDBits)
	}
	if params.Token != "::6a:483f:6c00:d400" {
		t.Errorf("Token = %s, want ::6a:483f:6c00:d400", params.Token)
	}
	if len(params.PortBlocks) != len(wantBlocks) {
		t.Fatalf("len(PortBlocks) = %d, want %d", len(params.PortBlocks), len(wantBlocks))
	}
	for i, b := range params.PortBlocks {
		if b != wantBlocks[i] {
			t.Errorf("PortBlocks[%d] = {%d, %d}, want {%d, %d}", i, b.Start, b.End, wantBlocks[i].Start, wantBlocks[i].End)
		}
	}
}

func TestDerivePSID(t *testing.T) {
	// IPv4Prefix=/24 → ipv4SuffixBits=8, psidBits=8
	bmr := BMR{
		IPv6Prefix: mustCIDR("2400:4150::/32"),
		IPv4Prefix: mustCIDR("106.0.0.0/24"),
		EABits:     16,
		PSIDBits:   8,
		PSIDOffset: 4,
		BRAddr:     net.ParseIP("2404:9200:225:100::64"),
	}

	// prefix bytes[4..5] = 0x01, 0x01 → EA bits = 0x0101 = 257
	// ipv4Suffix = 257>>8 = 1 → 106.0.0.1
	// psid = 257 & 0xFF = 1
	// a=4, k=8, q=4 → blockSize=16
	// A=1: start=4096|(1<<4)=4112, end=4127
	// A=15: start=61440|(1<<4)=61456, end=61471
	params, err := Derive(mustCIDR("2400:4150:0101:0000::/64"), bmr)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	if got := params.CeIPv4.String(); got != "106.0.0.1" {
		t.Errorf("CeIPv4 = %s, want 106.0.0.1", got)
	}
	if params.PSID != 1 {
		t.Errorf("PSID = %d, want 1", params.PSID)
	}
	if params.PSIDBits != 8 {
		t.Errorf("PSIDBits = %d, want 8", params.PSIDBits)
	}
	if params.Token != "::6a:0:100:100" {
		t.Errorf("Token = %s, want ::6a:0:100:100", params.Token)
	}
	if len(params.PortBlocks) != 15 {
		t.Fatalf("len(PortBlocks) = %d, want 15", len(params.PortBlocks))
	}
	if params.PortBlocks[0] != (PortBlock{4112, 4127}) {
		t.Errorf("PortBlocks[0] = {%d, %d}, want {4112, 4127}", params.PortBlocks[0].Start, params.PortBlocks[0].End)
	}
	if params.PortBlocks[14] != (PortBlock{61456, 61471}) {
		t.Errorf("PortBlocks[14] = {%d, %d}, want {61456, 61471}", params.PortBlocks[14].Start, params.PortBlocks[14].End)
	}
}

func TestDeriveInconsistentPSIDBits(t *testing.T) {
	// RFC 7597 §5.1: k must equal EABits - (32 - IPv4PrefixLen).
	// For /15 IPv4 prefix and 25 EA bits: k = 25 - 17 = 8.
	// Supplying k=7 is inconsistent and must be rejected.
	bmr := BMR{
		IPv6Prefix: mustCIDR("240b:10::/31"),
		IPv4Prefix: mustCIDR("106.72.0.0/15"),
		EABits:     25,
		PSIDBits:   7, // wrong: should be 8
		PSIDOffset: 4,
		BRAddr:     net.ParseIP("2404:9200:225:100::64"),
	}
	_, err := Derive(mustCIDR("240b:10:3f6c:d400::/56"), bmr)
	if err == nil {
		t.Error("want error for inconsistent PSIDBits, got nil")
	}
}

func TestDerivePrefixTooShort(t *testing.T) {
	// ruleLen=31, EABits=25 → need at least /56; /55 is too short
	_, err := Derive(mustCIDR("240b:10::/55"), nttBMR)
	if err == nil {
		t.Error("want error for prefix too short, got nil")
	}
}

func TestExtractBitsOutOfBounds(t *testing.T) {
	ip := net.ParseIP("2400:4150:0102:0304::").To16()
	// start=120, length=16 → bit positions 120..135, which exceed 128-bit IPv6
	_, err := extractBits(ip, 120, 16)
	if err == nil {
		t.Error("want error for out-of-bounds bit range, got nil")
	}
}

func TestPortBlocksPSIDOffsetZero(t *testing.T) {
	// psidOffset=0 → numBlocks=0 → nftables mod 0 is invalid
	_, err := portBlocks(0, 8, 0)
	if err == nil {
		t.Error("want error for psidOffset=0 producing zero port blocks, got nil")
	}
}

func TestExtractBits(t *testing.T) {
	// 2400:4150:0102:0304:: = 0x24 0x00 0x41 0x50 0x01 0x02 0x03 0x04 ...
	ip := net.ParseIP("2400:4150:0102:0304::").To16()

	tests := []struct {
		start  int
		length int
		want   int
	}{
		{0, 8, 0x24},
		{8, 8, 0x00},
		{32, 8, 0x01},
		{40, 8, 0x02},
		{32, 16, 0x0102},
		{40, 16, 0x0203},
	}

	for _, tt := range tests {
		got, err := extractBits(ip, tt.start, tt.length)
		if err != nil {
			t.Errorf("extractBits(%d, %d): %v", tt.start, tt.length, err)
			continue
		}
		if got != tt.want {
			t.Errorf("extractBits(%d, %d) = 0x%x, want 0x%x", tt.start, tt.length, got, tt.want)
		}
	}
}

func TestPortBlocks(t *testing.T) {
	tests := []struct {
		name       string
		psid       int
		psidBits   int
		psidOffset int
		wantLen    int
		wantFirst  PortBlock
		wantLast   PortBlock
	}{
		{
			// a=4, k=0, q=12, blockSize=4096
			name:       "k=0 a=4 psid=0",
			psid:       0,
			psidBits:   0,
			psidOffset: 4,
			wantLen:    15,
			wantFirst:  PortBlock{4096, 8191},
			wantLast:   PortBlock{61440, 65535},
		},
		{
			// a=4, k=8, q=4, blockSize=16
			// A=1: start=4096|(0<<4)=4096, end=4111
			// A=15: start=61440|(0<<4)=61440, end=61455
			name:       "k=8 a=4 psid=0",
			psid:       0,
			psidBits:   8,
			psidOffset: 4,
			wantLen:    15,
			wantFirst:  PortBlock{4096, 4111},
			wantLast:   PortBlock{61440, 61455},
		},
		{
			// A=1: start=4096|(1<<4)=4112, end=4127
			// A=15: start=61440|(1<<4)=61456, end=61471
			name:       "k=8 a=4 psid=1",
			psid:       1,
			psidBits:   8,
			psidOffset: 4,
			wantLen:    15,
			wantFirst:  PortBlock{4112, 4127},
			wantLast:   PortBlock{61456, 61471},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocks, err := portBlocks(tt.psid, tt.psidBits, tt.psidOffset)
			if err != nil {
				t.Fatalf("portBlocks: %v", err)
			}
			if len(blocks) != tt.wantLen {
				t.Fatalf("len = %d, want %d", len(blocks), tt.wantLen)
			}
			if blocks[0] != tt.wantFirst {
				t.Errorf("first = {%d, %d}, want {%d, %d}", blocks[0].Start, blocks[0].End, tt.wantFirst.Start, tt.wantFirst.End)
			}
			if blocks[len(blocks)-1] != tt.wantLast {
				t.Errorf("last = {%d, %d}, want {%d, %d}", blocks[len(blocks)-1].Start, blocks[len(blocks)-1].End, tt.wantLast.Start, tt.wantLast.End)
			}
		})
	}
}

func TestBuildToken(t *testing.T) {
	tests := []struct {
		ip       net.IP
		psid     int
		psidBits int
		want     string
	}{
		// v6plus IID: [0x00][b0][b1][b2][b3][0x00][PSID][0x00]
		// 106.72.0.0, psid=0, k=8 → g0=0x6a, g1=0x4800, g2=0, g3=0
		{net.IP{106, 72, 0, 0}, 0, 8, "::6a:4800:0:0"},
		// 106.72.63.108, psid=212=0xd4, k=8 → g3=0xd400
		{net.IP{106, 72, 63, 108}, 212, 8, "::6a:483f:6c00:d400"},
		// 106.0.0.1, psid=1, k=8 → g2=0x0100, g3=0x0100
		{net.IP{106, 0, 0, 1}, 1, 8, "::6a:0:100:100"},
	}

	for _, tt := range tests {
		got := buildToken(tt.ip, tt.psid, tt.psidBits)
		if got != tt.want {
			t.Errorf("buildToken(%s, %d, %d) = %s, want %s", tt.ip, tt.psid, tt.psidBits, got, tt.want)
		}
	}
}
