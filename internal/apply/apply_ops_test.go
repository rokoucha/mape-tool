package apply

import (
	"errors"
	"testing"
)

func TestApplyOpsNftablesFailureTriggersRollback(t *testing.T) {
	var calls []string
	nftErr := errors.New("nft failed")

	err := ApplyOps(
		func() error { calls = append(calls, "netlink"); return nil },
		func() error { calls = append(calls, "nftables"); return nftErr },
		func() error { calls = append(calls, "rollback"); return nil },
	)

	if !errors.Is(err, nftErr) {
		t.Errorf("want nftErr, got %v", err)
	}
	want := []string{"netlink", "nftables", "rollback"}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	for i, c := range calls {
		if c != want[i] {
			t.Errorf("calls[%d] = %q, want %q", i, c, want[i])
		}
	}
}

func TestApplyOpsNoRollbackOnSuccess(t *testing.T) {
	var calls []string

	err := ApplyOps(
		func() error { calls = append(calls, "netlink"); return nil },
		func() error { calls = append(calls, "nftables"); return nil },
		func() error { calls = append(calls, "rollback"); return nil },
	)

	if err != nil {
		t.Fatalf("want nil error, got %v", err)
	}
	for _, c := range calls {
		if c == "rollback" {
			t.Error("rollback must not be called on success")
		}
	}
}

func TestApplyOpsNetlinkFailureSkipsNftablesAndRollback(t *testing.T) {
	var calls []string
	netlinkErr := errors.New("netlink failed")

	err := ApplyOps(
		func() error { calls = append(calls, "netlink"); return netlinkErr },
		func() error { calls = append(calls, "nftables"); return nil },
		func() error { calls = append(calls, "rollback"); return nil },
	)

	if !errors.Is(err, netlinkErr) {
		t.Errorf("want netlinkErr, got %v", err)
	}
	for _, c := range calls {
		if c == "nftables" || c == "rollback" {
			t.Errorf("unexpected call: %q", c)
		}
	}
}
