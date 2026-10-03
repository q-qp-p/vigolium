package network

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/types"
)

func TestPolicyKey(t *testing.T) {
	t.Run("nil options", func(t *testing.T) {
		if got := policyKey(nil); got != "" {
			t.Fatalf("policyKey(nil) = %q, want empty", got)
		}
	})

	t.Run("deny list order does not matter", func(t *testing.T) {
		a := policyKey(&types.Options{ExcludeTargets: []string{"10.0.0.0/8", "169.254.0.0/16"}})
		b := policyKey(&types.Options{ExcludeTargets: []string{"169.254.0.0/16", "10.0.0.0/8"}})
		if a != b {
			t.Fatalf("the same exclusions in a different order are the same policy:\n%q\n%q", a, b)
		}
	})

	t.Run("every shaping field changes the key", func(t *testing.T) {
		base := &types.Options{}
		baseKey := policyKey(base)
		for name, mutate := range map[string]func(*types.Options){
			"exclude_targets":   func(o *types.Options) { o.ExcludeTargets = []string{"10.0.0.0/8"} },
			"restrict_local":    func(o *types.Options) { o.RestrictLocalNetworkAccess = true },
			"system_resolvers":  func(o *types.Options) { o.SystemResolvers = true },
			"dialer_timeout":    func(o *types.Options) { o.DialerTimeout = 7 * time.Second },
			"dialer_keep_alive": func(o *types.Options) { o.DialerKeepAlive = 11 * time.Second },
		} {
			opts := *base
			mutate(&opts)
			if policyKey(&opts) == baseKey {
				t.Errorf("%s does not change the policy key — a dialer built for one policy would be reused for another", name)
			}
		}
	})

	t.Run("an unrelated field does not change the key", func(t *testing.T) {
		// The key must cover exactly what NewDialer reads: including more would
		// make unrelated scans conflict for no reason.
		base := policyKey(&types.Options{})
		if policyKey(&types.Options{Concurrency: 99, RateLimit: 5}) != base {
			t.Fatal("a field NewDialer does not read must not change the policy key")
		}
	})
}

// TestInitRejectsAConflictingPolicy is the tripwire. No behaviour changes today —
// no policy field is assigned anywhere in the tree — but the first code to wire
// one must not be able to land the silent-inheritance bug with it: a second scan
// configured to refuse a host would otherwise reuse a dialer that allows it.
func TestInitRejectsAConflictingPolicy(t *testing.T) {
	if CurrentDialer() != nil {
		t.Skip("global dialer already initialized elsewhere; skipping policy assertions")
	}

	policyA := &types.Options{}
	policyB := &types.Options{ExcludeTargets: []string{"10.0.0.0/8"}}

	if err := Init(policyA); err != nil {
		t.Skipf("cannot initialize dialer in this environment: %v", err)
	}

	// Same policy: reuse, one more reference.
	if err := Init(policyA); err != nil {
		t.Fatalf("same policy must reuse the dialer: %v", err)
	}

	// Different policy: refused, and NO reference taken — so the caller must not
	// Close, and the two references above are still the only ones.
	if err := Init(policyB); !errors.Is(err, ErrDialerPolicyConflict) {
		t.Fatalf("Init with a conflicting policy returned %v, want ErrDialerPolicyConflict", err)
	}
	if CurrentDialer() == nil {
		t.Fatal("a refused Init must not tear down the live dialer")
	}

	Close()
	if CurrentDialer() == nil {
		t.Fatal("the refused Init took a reference it should not have")
	}
	Close()
	if CurrentDialer() != nil {
		t.Fatal("expected nil dialer after the final Close")
	}

	// With nothing holding the old policy, the other one can now be installed.
	if err := Init(policyB); err != nil {
		t.Fatalf("after full teardown, a different policy must be allowed: %v", err)
	}
	Close()
	if CurrentDialer() != nil {
		t.Fatal("expected nil dialer after Close")
	}
}

// TestInitConcurrentPoliciesLeaveABalancedRefcount: whichever policy wins the
// race, every successful Init is paired with exactly one Close and the dialer is
// gone at the end. A refused Init must not leak a reference.
func TestInitConcurrentPoliciesLeaveABalancedRefcount(t *testing.T) {
	if CurrentDialer() != nil {
		t.Skip("global dialer already initialized elsewhere; skipping refcount assertions")
	}

	policyA := &types.Options{}
	policyB := &types.Options{RestrictLocalNetworkAccess: true}

	// One outer reference held for the whole test: policyA therefore wins, and
	// refCount never reaches zero, so the dialer is created and destroyed exactly
	// once. (Racing full teardowns instead would exercise the memguardian
	// lifecycle rather than the refcount under test.)
	if err := Init(policyA); err != nil {
		t.Skipf("cannot initialize dialer in this environment: %v", err)
	}

	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	var acquired int
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			opts := policyA
			if i%2 == 1 {
				opts = policyB
			}
			if err := Init(opts); err != nil {
				if !errors.Is(err, ErrDialerPolicyConflict) {
					t.Errorf("unexpected Init error: %v", err)
				}
				return
			}
			mu.Lock()
			acquired++
			mu.Unlock()
			Close()
		}(i)
	}
	wg.Wait()

	if acquired == 0 {
		t.Fatal("no Init succeeded; policyA should have been reusable throughout")
	}
	if CurrentDialer() == nil {
		t.Fatalf("the outer reference was lost: %d Init/Close pairs did not balance", acquired)
	}

	// Release the outer reference. If any refused Init had leaked one, the dialer
	// would survive this.
	Close()
	if CurrentDialer() != nil {
		t.Fatal("a refused Init leaked a reference")
	}
}
