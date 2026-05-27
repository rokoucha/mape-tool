package apply

import (
	"errors"
	"testing"
)

func TestNetlinkRollbackOrderCallsBoth(t *testing.T) {
	var calls []string
	err := netlinkRollbackOrder(
		func() error { calls = append(calls, "removeAddr"); return nil },
		func() error { calls = append(calls, "teardown"); return nil },
	)
	if err != nil {
		t.Fatalf("want nil error, got %v", err)
	}
	want := []string{"removeAddr", "teardown"}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	for i, c := range calls {
		if c != want[i] {
			t.Errorf("calls[%d] = %q, want %q", i, c, want[i])
		}
	}
}

func TestNetlinkRollbackOrderContinuesOnError(t *testing.T) {
	// Both ops are best-effort: teardown must run even if removeAddr fails.
	var calls []string
	err := netlinkRollbackOrder(
		func() error { calls = append(calls, "removeAddr"); return errors.New("addr remove failed") },
		func() error { calls = append(calls, "teardown"); return nil },
	)
	if err == nil {
		t.Error("want error, got nil")
	}
	if len(calls) != 2 {
		t.Errorf("both ops must be attempted, got calls = %v", calls)
	}
}

func TestNetlinkApplyOrder(t *testing.T) {
	var calls []string
	err := netlinkApplyOrder(
		func() error { calls = append(calls, "assignWAN"); return nil },
		func() error { calls = append(calls, "setupTunnel"); return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"assignWAN", "setupTunnel"}
	if len(calls) != len(want) {
		t.Fatalf("call order = %v, want %v", calls, want)
	}
	for i, c := range calls {
		if c != want[i] {
			t.Errorf("calls[%d] = %q, want %q", i, c, want[i])
		}
	}
}
