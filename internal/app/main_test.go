package app

import "testing"

func validFlags() *bmrFlags {
	return &bmrFlags{
		ruleIPv6:   "240b:10::/31",
		ruleIPv4:   "106.72.0.0/15",
		eaBits:     25,
		psidBits:   8,
		psidOffset: 4,
		brAddr:     "2404:9200:225:100::64",
		wanIf:      "enp5s0f0",
	}
}

func TestBuildBMRConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*bmrFlags)
		wantErr bool
	}{
		{"valid", func(f *bmrFlags) {}, false},
		{"eaBits zero", func(f *bmrFlags) { f.eaBits = 0 }, true},
		{"eaBits negative", func(f *bmrFlags) { f.eaBits = -1 }, true},
		{"psidBits negative", func(f *bmrFlags) { f.psidBits = -1 }, true},
		{"psidBits over 16", func(f *bmrFlags) { f.psidBits = 17 }, true},
		{"psidOffset zero", func(f *bmrFlags) { f.psidOffset = 0 }, true},
		{"psidOffset negative", func(f *bmrFlags) { f.psidOffset = -1 }, true},
		{"psidOffset over 15", func(f *bmrFlags) { f.psidOffset = 16 }, true},
		{"psidOffset+psidBits over 16", func(f *bmrFlags) { f.psidOffset = 12; f.psidBits = 8 }, true},
		// ruleLen+EABits > 64 would cause findPrefix to mask out EA bits
		{"ruleLen+eaBits over 64", func(f *bmrFlags) { f.ruleIPv6 = "2400::/48"; f.eaBits = 20 }, true},
		{"ruleLen+eaBits exactly 64 is ok", func(f *bmrFlags) { f.ruleIPv6 = "2400::/39"; f.eaBits = 25 }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validFlags()
			tt.modify(f)
			_, err := buildBMRConfig(f)
			if tt.wantErr && err == nil {
				t.Error("want error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("want no error, got %v", err)
			}
		})
	}
}

func TestBuildBMRConfigRejectsIPv4BRAddr(t *testing.T) {
	f := &bmrFlags{
		ruleIPv6:   "240b:10::/31",
		ruleIPv4:   "106.72.0.0/15",
		eaBits:     25,
		psidBits:   8,
		psidOffset: 4,
		brAddr:     "1.2.3.4", // IPv4 must be rejected
		wanIf:      "enp5s0f0",
	}
	_, err := buildBMRConfig(f)
	if err == nil {
		t.Error("want error for IPv4 --br-addr, got nil")
	}
}

func TestBuildBMRConfigAcceptsIPv6BRAddr(t *testing.T) {
	f := &bmrFlags{
		ruleIPv6:   "240b:10::/31",
		ruleIPv4:   "106.72.0.0/15",
		eaBits:     25,
		psidBits:   8,
		psidOffset: 4,
		brAddr:     "2404:9200:225:100::64",
		wanIf:      "enp5s0f0",
	}
	_, err := buildBMRConfig(f)
	if err != nil {
		t.Errorf("want no error for IPv6 --br-addr, got %v", err)
	}
}
