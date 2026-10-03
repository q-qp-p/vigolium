package cli

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/database"
)

// setGroupFlags pins the --group-by/--group-limit globals for one test.
func setGroupFlags(t *testing.T, field string, limit int) {
	t.Helper()
	prevField, prevLimit := trafficGroupBy, trafficGroupLimit
	trafficGroupBy, trafficGroupLimit = field, limit
	t.Cleanup(func() { trafficGroupBy, trafficGroupLimit = prevField, prevLimit })
}

// noneChanged reports every flag as untouched.
func noneChanged(string) bool { return false }

func TestValidateTrafficGroupFlagsAcceptsSupportedFields(t *testing.T) {
	for _, field := range []string{"", "method", "STATUS_CODE", " host "} {
		setGroupFlags(t, field, defaultTrafficGroupLimit)
		if err := validateTrafficGroupFlags(noneChanged); err != nil {
			t.Errorf("--group-by %q rejected: %v", field, err)
		}
	}
}

// A name typo must fail before any database is opened, and must say what is
// accepted — the alternative is a read command that touches the file only to
// report that the caller mistyped a flag.
func TestValidateTrafficGroupFlagsRejectsUnknownField(t *testing.T) {
	setGroupFlags(t, "hostname", defaultTrafficGroupLimit)
	err := validateTrafficGroupFlags(noneChanged)
	if err == nil {
		t.Fatal("an unknown --group-by field must be rejected")
	}
	if !strings.Contains(err.Error(), "supported fields:") {
		t.Errorf("error must list the accepted names, got: %v", err)
	}
	var ue usageError
	if !errors.As(err, &ue) {
		t.Errorf("error = %T, want a usage error (exit 2)", err)
	}
}

func TestValidateTrafficGroupFlagsRejectsNegativeLimit(t *testing.T) {
	setGroupFlags(t, "method", -1)
	if err := validateTrafficGroupFlags(noneChanged); err == nil {
		t.Fatal("a negative --group-limit must be rejected")
	}
}

// --group-by replaces the rows with their shape. Pairing it with a renderer is a
// request for two outputs, and silently honoring one of them is how a caller
// comes to believe it got the other.
func TestValidateTrafficGroupFlagsRejectsRenderModes(t *testing.T) {
	for _, conflicting := range trafficGroupConflicts {
		setGroupFlags(t, "method", defaultTrafficGroupLimit)
		err := validateTrafficGroupFlags(func(name string) bool { return name == conflicting })
		if err == nil {
			t.Errorf("--group-by with --%s must be rejected", conflicting)
			continue
		}
		if !strings.Contains(err.Error(), "--"+conflicting) {
			t.Errorf("error must name --%s, got: %v", conflicting, err)
		}
	}
}

// Without --group-by none of the above applies, including the conflicts.
func TestValidateTrafficGroupFlagsIsInertWhenUnset(t *testing.T) {
	setGroupFlags(t, "", -5)
	if err := validateTrafficGroupFlags(func(string) bool { return true }); err != nil {
		t.Errorf("validation must be inert without --group-by, got: %v", err)
	}
}

func TestTrafficFilterFlagForOnlyMapsRunnableHints(t *testing.T) {
	// A hint that cannot be run is worse than no hint: the fields with no listing
	// flag must produce none.
	if flag := trafficFilterFlagFor["ip"]; flag != "" {
		t.Errorf("ip has no listing filter flag; hint = %q, want none", flag)
	}
	if flag := trafficFilterFlagFor["status_code"]; flag != "--status" {
		t.Errorf("status_code hint = %q, want --status", flag)
	}
}

// The groupable set and the hint table are two lists that have to agree. A field
// added to the first and forgotten in the second loses its query hint silently,
// so the absence is asserted to be deliberate (an explicit "" entry) rather than
// an omission.
func TestTrafficFilterFlagCoversEveryGroupableField(t *testing.T) {
	for _, field := range database.GroupableFields() {
		if _, ok := trafficFilterFlagFor[field]; !ok {
			t.Errorf("groupable field %q has no entry in trafficFilterFlagFor; add its listing flag, or \"\" if it has none", field)
		}
	}
	for field := range trafficFilterFlagFor {
		if !slices.Contains(database.GroupableFields(), field) {
			t.Errorf("trafficFilterFlagFor names %q, which is not groupable", field)
		}
	}
}

// `--group-by host --raw=false` is an operator explicitly turning the
// conflicting renderer OFF. Keyed on Changed, the validator rejected it and told
// them to remove the very flag that resolved the conflict.
func TestTrafficGroupAcceptsFalseConflictFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "traffic"}
	var raw bool
	cmd.Flags().BoolVar(&raw, "raw", false, "")
	if err := cmd.Flags().Parse([]string{"--raw=false"}); err != nil {
		t.Fatalf("parse: %v", err)
	}

	setGroupFlags(t, "host", defaultTrafficGroupLimit)

	if err := validateTrafficGroupFlags(func(name string) bool { return flagOn(cmd, name) }); err != nil {
		t.Errorf("--raw=false is not a request to render records: %v", err)
	}

	// The real conflict must still be rejected.
	if err := cmd.Flags().Parse([]string{"--raw=true"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := validateTrafficGroupFlags(func(name string) bool { return flagOn(cmd, name) }); err == nil {
		t.Error("--group-by with --raw=true must still be rejected")
	}
}
