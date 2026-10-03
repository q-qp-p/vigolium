# Installation

Vigolium ships as a single Go executable with embedded helper programs. The Go
executable is statically linked; the Linux helpers require a glibc-based runtime.
Browser features need a compatible browser. Pick whichever install method fits
your environment — all of them give you the same `vigolium` binary.

## Quick install (recommended)

```bash
curl -fsSL https://vigolium.com/install.sh | bash
```

The installer:

- resolves the latest release from the CDN, downloads the matching binary, and
  **verifies its SHA-256 checksum** before installing;
- installs to `~/.local/bin/vigolium`;
- adds `~/.local/bin` to your `PATH` in the appropriate shell profile
  (`.zshrc`, `.bashrc`/`.bash_profile`, or `config.fish`).

If `~/.local/bin` was not already on your `PATH`, activate it without
restarting your shell:

```bash
export PATH="$HOME/.local/bin:$PATH"
vigolium doctor
```

## npm

The npm package is a thin launcher that pulls the correct prebuilt binary for
your platform as an optional dependency (Node 16+).

```bash
# Global install
npm install -g @vigolium/vigolium

# Or run once without installing
npx @vigolium/vigolium scan -h
```

## Nix

The [official binary flake](https://github.com/vigolium/nix-vigolium) supports
Linux and macOS on x86_64 and aarch64:

```bash
nix run github:vigolium/nix-vigolium -- version
nix profile install github:vigolium/nix-vigolium
```

Nix flakes and `nix-command` must be enabled. Linux requires working user
namespaces for the embedded helpers' FHS runtime. Use `nix profile list` to find
the installed entry name, then `nix profile upgrade <entry-name>` to upgrade.

## Scoop (Windows)

With [Scoop](https://scoop.sh/) installed, add the official bucket:

```powershell
scoop bucket add vigolium https://github.com/vigolium/scoop-bucket
scoop install vigolium
```

This installs the Windows x64 release. Upgrade with `scoop update vigolium` and
remove with `scoop uninstall vigolium`.

The Nix flake and Scoop bucket check new stable GitHub Releases hourly and update
after their installation checks pass. They are distributed directly from these
repositories; central nixpkgs/Scoop main-bucket inclusion is separate.

## Build from source

Requires **Go 1.27+**, `git`, and `make`. No C toolchain is needed.

```bash
git clone https://github.com/vigolium/vigolium.git
cd vigolium
make build
```

`make build` outputs `bin/vigolium` and installs the binary to `$GOPATH/bin`.

> **Do not** run `go build` directly. `make build` injects version metadata and
> guarantees a clean build; an ad-hoc `go build` produces a binary that reports
> the wrong version and may be left stale in the working tree.

To place the binary on your `PATH` explicitly (assuming `$GOPATH/bin` is on it):

```bash
make install
```

Other useful targets:
`make build-all` (cross-compile Linux/macOS/Windows), `make test-unit`
(fast tests), `make lint`. Run `make help` or inspect the `Makefile` for the
full list.

## Docker

```bash
docker pull j3ssie/vigolium:latest

# Run any command — the entrypoint is the vigolium binary
docker run --rm j3ssie/vigolium:latest scan -h

# Scan a target and write a report to the host
docker run --rm -v "$PWD:/out" j3ssie/vigolium:latest \
  scan --stateless -t https://example.com --format jsonl -o /out/results
```

## Verify the installation

```bash
vigolium version     # prints version, build, and commit
vigolium doctor      # validates environment, config, and optional dependencies
```

`vigolium doctor` is the fastest way to confirm everything is wired up
correctly — run it after any install or upgrade.

### Auto-install missing dependencies

Most of Vigolium's core scanning has no external dependencies, but some
optional features need extra tooling (a browser for SPA spidering, nuclei
templates for the known-issue scan, `bun`/`pi` for certain agent drivers). If
`doctor` reports a fixable item, let it install it for you:

```bash
vigolium doctor --fix              # auto-install/fix every failing check
vigolium doctor --fix --only chrome,nuclei   # fix only specific items
```

`--fix` prints the report, installs what's missing, then re-checks and shows
the updated status. `--only` accepts any of:
`nuclei`, `chrome`, `bun`, `claude`, `agent-browser`, `pi`, `piolium`
(it has no effect without `--fix`).

## Updating

`vigolium update` re-runs the official installer to fetch the latest release
and refreshes the local nuclei-templates checkout used by the known-issue scan:

```bash
vigolium update                  # update binary + nuclei templates
vigolium update --skip-templates # only reinstall the binary
vigolium update --skip-binary    # only refresh nuclei templates
vigolium update --force          # skip the confirmation prompt
```

The binary update always installs to `~/.local/bin/vigolium`. If your running
binary lives elsewhere (e.g. a `make install` build in `$GOPATH/bin` or a
Docker image), `update` prints a warning — ensure `~/.local/bin` precedes the
old location on your `PATH`, or upgrade that copy manually.

Vigolium also checks npm for a newer release on startup at most once per day.
Set `VIGOLIUM_DISABLE_UPDATE_CHECK=1` to suppress that notice, or
`VIGOLIUM_AUTO_UPDATE=1` to install and re-exec the newer binary automatically.

> npm and Docker installs are upgraded through their own tooling
> (`npm update -g @vigolium/vigolium` / `docker pull`), not `vigolium update`.

Packages produced by the additional distribution recipes record their package
manager. Releases containing this support disable binary self-updates for those
installs and direct you to the package manager instead. Template-only updates
remain available with `vigolium update --skip-binary`.

AUR, DEB/RPM, Scoop, WinGet, Nix, and Snap packages are built from the templates in
`build/packaging/`. Availability in each registry depends on completing that
channel's publishing setup.

## Where Vigolium stores data

Everything lives under `~/.vigolium/` (override with the `VIGOLIUM_HOME`
environment variable):

| Path | Contents |
|------|----------|
| `~/.vigolium/vigolium-configs.yaml` | Main configuration file |
| `~/.vigolium/database-vgnm.sqlite` | Default SQLite scan database |
| `~/.vigolium/agent-sessions/` | Agentic scan session artifacts |
| `~/.vigolium/prompts/` | User prompt templates |

Initialize the workspace and a starter config explicitly with:

```bash
vigolium init
```

## Uninstall

```bash
rm -f ~/.local/bin/vigolium      # or: $GOPATH/bin/vigolium for source installs
rm -rf ~/.vigolium               # optional: remove config, database, sessions
```

For npm: `npm uninstall -g @vigolium/vigolium`.

## Next steps

- [Quick Start](quick-start.md) — run your first scan in under a minute.
- [Native Scan & Stateless Scanning](native-scan.md) — CLI scan recipes.
- [Setting Up the Agent](setup-agent.md) — wire up AI-driven scanning.
- [Configuration Reference](../configuration.md) — every config knob.
- [Troubleshooting](../troubleshooting.md) — fixes for common issues.
