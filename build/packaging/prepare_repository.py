#!/usr/bin/env python3
"""Create a standalone Nix or Scoop repository from generated release recipes."""

import argparse
import json
from pathlib import Path
import shutil

import channel_release
import generate

SOURCE = Path(__file__).resolve().parent

COMMON = """
## Release updates

The **Update release** GitHub Actions workflow checks the latest published stable
release of `vigolium/vigolium` hourly. It downloads and verifies the five upstream
archives against `checksums.txt`, reads license notices from the release tag, and
tests the candidate before committing it. Ordinary upstream commits and
prereleases do not publish a new package. Older versions cannot replace newer
ones, and version tags are never overwritten.

You can also run the workflow manually with an explicit stable tag. Enable
`force` to test the current version again. Failed validation leaves the current
package in place. GitHub may delay scheduled runs, and disables schedules in
public repositories after 60 days without repository activity; re-enable the
workflow in Actions if that happens.

The publishing job uses this repository's automatic, short-lived `GITHUB_TOKEN`
with `contents: write`. No personal access token, password, or custom secret is
required. Download and test jobs have read-only access.

Recipe generation and automation sources are maintained in
[`vigolium/vigolium/build/packaging`](https://github.com/vigolium/vigolium/tree/main/build/packaging).
The `.github/packaging` copy and pinned Nix package set/Scoop installer are updated
deliberately when the packaging tools change. This initial setup originated from
the packaging changes prepared locally; that source link will be available once
those changes are merged upstream.
"""

READMES = {
    "nix": """# Vigolium for Nix

Official binary flake for [Vigolium](https://github.com/vigolium/vigolium).
Supports x86_64 and aarch64 on Linux and macOS.

```sh
nix run github:vigolium/nix-vigolium -- version
nix profile install github:vigolium/nix-vigolium
```

Enable Nix flakes and the `nix-command` feature in your Nix configuration.
To pin a version, append its tag, such as `github:vigolium/nix-vigolium/v0.5.1`.
For upgrades, use `nix profile list` to find the profile entry name and then
`nix profile upgrade <entry-name>`.

Linux uses an FHS environment for the dynamically linked helpers embedded in
the release binary. Working user namespaces and bubblewrap are required; some
restricted containers cannot run it. Ubuntu's AppArmor restrictions may require
an administrator to permit user namespaces for Nix's exact bubblewrap executable.
The disposable CI runners apply that scoped profile for testing. Configure `spidering.browser_path` for an
external browser when needed. Chromium is not bundled. Configuration and scan
data stay in the user's normal Vigolium directories.

Use Nix to update the binary. The wrapper disables Vigolium's standalone update
check. This flake is distributed directly from this repository; it is not yet
included in the central nixpkgs package collection.
""",
    "scoop": """# Vigolium Scoop bucket

Official Windows x64 package for [Vigolium](https://github.com/vigolium/vigolium).

```powershell
scoop bucket add vigolium https://github.com/vigolium/scoop-bucket
scoop install vigolium
```

Update with `scoop update vigolium` and remove with `scoop uninstall vigolium`.
Configuration and scan data stay in the user's normal Vigolium directories.
The manifest downloads the upstream ZIP and verifies its SHA-256 checksum.

The initial v0.5.1 binary predates Vigolium's new package-manager updater guard.
Use Scoop for binary upgrades; the guard will take effect in a future upstream
binary release. This is a dedicated bucket; it is not yet in Scoop's main bucket.
""",
}


def prepare(packages, channel, destination):
    if destination.exists():
        raise ValueError(f"destination already exists: {destination}")
    # Validate the input before creating a repository directory.
    metadata = packages / ("nix/release.json" if channel == "nix" else "scoop/vigolium.json")
    version = json.loads(metadata.read_text())["version"]
    channel_release.version_tuple("v" + version)
    destination.mkdir(parents=True)
    for name in channel_release.FILES[channel]:
        source = packages / ("nix/" + name if channel == "nix" else "scoop/vigolium.json")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    if channel == "scoop":
        for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            shutil.copyfile(packages / name, destination / name)
    tooling = destination / ".github/packaging"
    tooling.mkdir(parents=True)
    for name in ("generate.py", "channel_release.py"):
        shutil.copyfile(SOURCE / name, tooling / name)
    templates = tooling / "templates"
    templates.mkdir()
    for name in ("aur", "nix", "winget"):
        shutil.copytree(SOURCE / "templates" / name, templates / name)
    shutil.copyfile(SOURCE / "templates/snapcraft.yaml", templates / "snapcraft.yaml")
    validation = (SOURCE / "templates" / f"{channel}-validate.yml").read_text().rstrip()
    workflow = generate.render("channel-release.yml", {
        "CHANNEL": channel, "MINUTE": "17" if channel == "nix" else "37", "VALIDATE_JOB": validation,
    })
    generate.write(destination / ".github/workflows/release.yml", workflow)
    generate.write(destination / "README.md", READMES[channel] + COMMON)
    generate.write(destination / ".gitignore", ".candidate/\n__pycache__/\nresult\nresult-*\n")
    print(f"Prepared {channel} repository for v{version}: {destination}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--channel", choices=channel_release.FILES, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.packages.resolve(), args.channel, args.output.resolve())


if __name__ == "__main__":
    main()
