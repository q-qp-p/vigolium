#!/usr/bin/env python3
"""Prepare and publish owned Nix/Scoop recipes from stable GitHub releases.

Copied with generate.py and its templates into each package repository. GitHub
Actions validates the candidate before running the separate publish command.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import generate

UPSTREAM = "vigolium/vigolium"
FILES = {
    "nix": ("flake.nix", "flake.lock", "package.nix", "release.json", "LICENSE", "THIRD_PARTY_NOTICES.md"),
    "scoop": ("bucket/vigolium.json",),
}


def version_tuple(tag):
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        raise ValueError("a stable vMAJOR.MINOR.PATCH tag is required")
    return tuple(int(part) for part in tag[1:].split("."))


def guard_version(tag, current):
    wanted = version_tuple(tag)
    if current is not None and wanted < version_tuple("v" + current):
        raise ValueError(f"refusing to downgrade {current} to {tag}")


def version_path(channel):
    return "release.json" if channel == "nix" else "bucket/vigolium.json"


def current_version(root, channel):
    path = root / version_path(channel)
    return json.loads(path.read_text())["version"] if path.exists() else None


def run(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout


def release_info(tag):
    if tag:
        version_tuple(tag)
    path = f"repos/{UPSTREAM}/releases/tags/{tag}" if tag else f"repos/{UPSTREAM}/releases/latest"
    release = json.loads(run("gh", "api", path))
    version_tuple(release["tag_name"])
    if release["draft"] or release["prerelease"]:
        raise ValueError("only published stable releases can be packaged")
    if tag and release["tag_name"] != tag:
        raise ValueError("requested tag/release mismatch")
    return release


def output(values):
    text = "".join(f"{key}={value}\n" for key, value in values.items())
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
            stream.write(text)
    print(text, end="")


def prepare(root, channel, tag=None, force=False):
    release = release_info(tag)
    tag = release["tag_name"]
    previous = current_version(root, channel)
    guard_version(tag, previous)
    if previous == tag[1:] and not force:
        output({"validate": "false", "tag": tag, "version": tag[1:]})
        return
    candidate = root / ".candidate"
    if candidate.exists():
        raise ValueError(".candidate already exists; use a clean checkout")
    with tempfile.TemporaryDirectory(prefix="vigolium-release-") as temp:
        temp = Path(temp)
        dist = temp / "dist"
        run("gh", "release", "download", tag, "--repo", UPSTREAM, "--dir", str(dist),
            "--pattern", "vigolium_*.tar.gz", "--pattern", "vigolium_*.zip",
            "--pattern", "checksums.txt", "--pattern", "metadata.json")
        if json.loads((dist / "metadata.json").read_text())["version"] != tag:
            raise ValueError("release tag/metadata mismatch")
        # The license and notices must come from the same immutable release tag.
        notices = temp / "notices"
        notices.mkdir()
        for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            content = run("gh", "api", f"repos/{UPSTREAM}/contents/{name}?ref={tag}",
                          "-H", "Accept: application/vnd.github.raw+json")
            (notices / name).write_text(content)
        recipes = temp / "recipes"
        generate.generate(dist, recipes, "Vigolium maintainers <contact@vigolium.com>", notices)
        candidate.mkdir()
        for name in FILES[channel]:
            source = recipes / ("nix/" + name if channel == "nix" else "scoop/vigolium.json")
            destination = candidate / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
    output({"validate": "true", "tag": tag, "version": tag[1:]})


def publish(root, channel):
    candidate = current_version(root, channel)
    if candidate is None:
        raise ValueError("missing validated candidate")
    tag = "v" + candidate
    previous = json.loads(run("git", "show", f"HEAD:{version_path(channel)}", cwd=root))["version"]
    guard_version(tag, previous)
    run("git", "add", "--", *FILES[channel], cwd=root)
    changed = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=root).returncode
    if changed not in (0, 1):
        raise ValueError("git diff failed")
    if changed == 1:
        run("git", "-c", "user.name=github-actions[bot]", "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit", "-m", f"Update Vigolium to {tag}", cwd=root)
        run("git", "push", "origin", "HEAD:main", cwd=root)
        print(f"Published {tag}")
    else:
        print(f"{tag} is already current")
    # Never replace an existing version tag, including when templates are revised.
    tags = run("git", "tag", "--list", tag, cwd=root).strip()
    if not tags:
        run("git", "tag", tag, cwd=root)
        run("git", "push", "origin", f"refs/tags/{tag}", cwd=root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "publish"))
    parser.add_argument("--channel", required=True, choices=FILES)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--tag", default="")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args.root.resolve(), args.channel, args.tag or None, args.force)
        else:
            publish(args.root.resolve(), args.channel)
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"package release: {error}\n")


if __name__ == "__main__":
    main()
