package spitolas

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
)

func TestCaptureReceiptComplete(t *testing.T) {
	tests := []struct {
		name string
		r    CaptureReceipt
		want bool
	}{
		{"no capture", CaptureReceipt{}, true},
		{"clean", CaptureReceipt{Enabled: true, Accepted: 3, Persisted: 3, DrainComplete: true}, true},
		{"save failures", CaptureReceipt{Enabled: true, Accepted: 3, Persisted: 1, Failed: 2, DrainComplete: true}, false},
		{"refused late records", CaptureReceipt{Enabled: true, Refused: 1, DrainComplete: true}, false},
		{"drain not finished", CaptureReceipt{Enabled: true, Accepted: 3, Persisted: 3}, false},
		{"abandoned", IncompleteCaptureReceipt(), false},
	}
	for _, tt := range tests {
		if got := tt.r.Clean(); got != tt.want {
			t.Errorf("%s: Complete() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestCaptureReceiptAdd(t *testing.T) {
	var sum CaptureReceipt
	sum.Merge(CaptureReceipt{}) // a run without capture contributes nothing
	if sum.Enabled {
		t.Fatal("adding a disabled receipt enabled the sum")
	}
	sum.Merge(CaptureReceipt{Enabled: true, BodiesRetained: true, Accepted: 2, Persisted: 2, DrainComplete: true})
	sum.Merge(CaptureReceipt{Enabled: true, Accepted: 5, Persisted: 3, Failed: 2, DrainComplete: true, Err: "2 dropped"})
	if sum.Accepted != 7 || sum.Persisted != 5 || sum.Failed != 2 || !sum.DrainComplete || sum.Err != "2 dropped" {
		t.Errorf("sum = %+v", sum)
	}
	if sum.Clean() {
		t.Error("a sum containing a lossy run is not complete")
	}
	sum.Merge(IncompleteCaptureReceipt())
	if sum.DrainComplete {
		t.Error("an abandoned run makes the sum's drain incomplete")
	}
}

func TestNewCaptureReceipt(t *testing.T) {
	got := newCaptureReceipt(network.Receipt{Accepted: 4, Persisted: 6, Refused: 1, Failed: 1, DrainComplete: true, Closed: true, Err: "x"}, true, false)
	want := CaptureReceipt{Enabled: true, BodiesRetained: true, Accepted: 4, Persisted: 6, Refused: 1, Failed: 1, DrainComplete: true, Err: "x"}
	if got != want {
		t.Errorf("newCaptureReceipt = %+v, want %+v", got, want)
	}
	// A probe without a sink reports no capture at all, which is complete.
	var res ProbeResult
	if res.Capture.Enabled || !res.Capture.Clean() {
		t.Errorf("zero ProbeResult receipt = %+v", res.Capture)
	}
}

func TestBuildCrawlerConfig_CaptureAndIdentitySettings(t *testing.T) {
	c, err := buildCrawlerConfig(SpiderConfig{TargetURL: "https://example.com/", MaxCaptureBodyBytes: -1, IdentityEmailDomain: "qa.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxCaptureBodyBytes != -1 || c.IdentityEmailDomain != "qa.example.net" {
		t.Errorf("max body=%d identity=%q", c.MaxCaptureBodyBytes, c.IdentityEmailDomain)
	}
	// Unset keeps the crawler defaults.
	c, _ = buildCrawlerConfig(SpiderConfig{TargetURL: "https://example.com/"})
	if c.MaxCaptureBodyBytes != 0 || c.IdentityEmailDomain != "example.com" {
		t.Errorf("defaults: max body=%d identity=%q", c.MaxCaptureBodyBytes, c.IdentityEmailDomain)
	}
}

func TestBuildCrawlerConfig_RequireAuth(t *testing.T) {
	c, err := buildCrawlerConfig(SpiderConfig{TargetURL: "https://example.com/", RequireAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	if !c.RequireAuth {
		t.Error("RequireAuth not mapped onto the crawler config")
	}
	// The public auth-state names are the crawler's.
	for _, s := range []string{AuthNotRequested, AuthConfigured, AuthApplied, AuthFailed} {
		if s == "" || s == "verified" {
			t.Errorf("unexpected auth state %q", s)
		}
	}
}
