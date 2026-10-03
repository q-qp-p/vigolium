package cli

import "github.com/vigolium/vigolium/pkg/cli/configcmd"

// wire.go registers command groups that have been extracted into their own
// subpackages. Unlike the legacy in-package commands (which self-register via
// init() onto rootCmd), subpackaged groups expose an explicit constructor and
// receive their dependencies here, where the CLI's global flag state lives.
//
// As more groups move out of the flat pkg/cli package they should be wired the
// same way, until rootCmd's children are assembled entirely from explicit
// constructors and the per-file init() registrations are gone.
func init() {
	rootCmd.AddCommand(configcmd.NewCommand(
		configcmd.Deps{
			ConfigFlag: func() string { return globalConfig },
			Force:      func() bool { return globalForce },
			// Always with the default database: `config clean` has just deleted
			// ~/.vigolium, default store included, so regenerating without it
			// would leave the install short of a file the user did not ask to
			// lose. A pinned --db names a different file, which clean never
			// touched.
			Reinitialize: func() error { return initializeVigolium(true) },
			JSON:         func() bool { return globalJSON },
			WriteJSON:    writeConfigEnvelope,
		},
		configcmd.Examples{
			Parent: configExamples,
			Ls:     configLsExamples,
			Set:    configSetExamples,
			Clean:  configCleanExamples,
		},
	))
}

// writeConfigEnvelope lets the extracted config group emit through the CLI's
// shared -j envelope without importing pkg/cli. Passing the writer rather than
// the envelope type keeps the dependency pointing one way, and means a config
// result carries the same schema_version/items/generated_at spine as every other
// machine payload instead of a second shape invented in that package.
func writeConfigEnvelope(command, legacyKey string, items any, total int, extra map[string]any) error {
	env := newAgentEnvelope(command, legacyKey, items, int64(total), 0, total)
	for k, v := range extra {
		env.With(k, v)
	}
	return writeAgentJSON(env)
}
