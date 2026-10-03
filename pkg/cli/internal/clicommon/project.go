package clicommon

import (
	"context"
	"fmt"
	"sync"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

var (
	resolvedProjectUUID string
	resolveProjectOnce  sync.Once
	resolveProjectErr   error
	resolveProjectDone  bool
)

// ResolvedProjectUUID returns the UUID this process already resolved, and
// whether there is one to return. False means resolution has not run, or ran
// and failed — in both cases the caller must not present a UUID as this read's
// scope, because the next call could still produce a different one.
//
// Distinct from ResolveProjectUUID: this never resolves, so it is safe on a
// path (an envelope, a follow-up command) that must not open a database or
// touch the active-project file as a side effect of describing a read.
func ResolvedProjectUUID() (string, bool) {
	if !resolveProjectDone || resolveProjectErr != nil {
		return "", false
	}
	return resolvedProjectUUID, resolvedProjectUUID != ""
}

// ResolveProjectUUID returns the effective project UUID, resolved once per
// process. Resolution order:
//  1. projectUUID (from --project-uuid / VIGOLIUM_PROJECT_UUID)
//  2. projectName (DB lookup, opening the database via getDB; from
//     --project-name / VIGOLIUM_PROJECT_NAME)
//  3. ~/.vigolium/active-project file (set by `vigolium project use`)
//  4. database.DefaultProjectUUID
//
// getDB is supplied by the caller so this package needs no knowledge of the
// CLI's global flag state.
func ResolveProjectUUID(getDB func() (*database.DB, error), projectUUID, projectName string) (string, error) {
	resolveProjectOnce.Do(func() {
		resolveProjectDone = true
		switch {
		case projectUUID != "":
			resolvedProjectUUID = projectUUID
		case projectName != "":
			db, err := getDB()
			if err != nil {
				resolveProjectErr = fmt.Errorf("failed to open database for project name lookup: %w", err)
				return
			}
			repo := database.NewRepository(db)
			project, err := repo.GetProjectByName(context.Background(), projectName)
			if err != nil {
				resolveProjectErr = err
				return
			}
			resolvedProjectUUID = project.UUID
		default:
			if persisted, err := config.ReadActiveProject(); err == nil && persisted != "" {
				resolvedProjectUUID = persisted
			} else {
				resolvedProjectUUID = database.DefaultProjectUUID
			}
		}
	})
	return resolvedProjectUUID, resolveProjectErr
}

// ResetProjectResolutionForTest clears the once-per-process resolution so a
// test can drive a different project selection in the same binary. Resolution
// is memoized in a sync.Once, which is right for a CLI process that resolves
// one project and exits, and useless for a test table where every row means a
// different selection — without this, row two silently asserts row one's answer.
//
// Test-only. Production code pins with PinProjectUUID instead.
func ResetProjectResolutionForTest() {
	resolveProjectOnce = sync.Once{}
	resolvedProjectUUID = ""
	resolveProjectErr = nil
	resolveProjectDone = false
}

// PinProjectUUID authoritatively fixes the resolved project UUID and seals the
// resolution so every later ResolveProjectUUID call returns it, regardless of
// call ordering. This exists for --resume, which learns the run's project only
// after startup: mutating the CLI's global flags is not enough because the first
// ResolveProjectUUID call caches its result in a sync.Once. Call it during
// single-threaded startup (before any concurrent resolver use).
func PinProjectUUID(projectUUID string) {
	// Spend the Once so a subsequent ResolveProjectUUID does not overwrite the
	// pin; if it already fired, the Do is a no-op and the direct assignment below
	// still wins.
	resolveProjectOnce.Do(func() {})
	resolvedProjectUUID = projectUUID
	resolveProjectErr = nil
	resolveProjectDone = true
}
