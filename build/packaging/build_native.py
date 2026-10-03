#!/usr/bin/env python3
"""Build DEB/RPM packages with nFPM from generate.py output; never publishes."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path, default=Path("build/dist-packages"))
    parser.add_argument("--nfpm", default="nfpm")
    args = parser.parse_args()
    root = args.packages.resolve()
    version = json.loads((root / "release.json").read_text())["version"]
    output = root / "native"
    output.mkdir(exist_ok=True)
    artifacts = []
    for arch in ("amd64", "arm64"):
        for kind in ("deb", "rpm"):
            artifact = output / f"vigolium_{version}_{arch}.{kind}"
            if artifact.exists():
                parser.exit(1, f"refusing to overwrite {artifact}\n")
            subprocess.run([
                args.nfpm, "package", "--config", kind + ".json", "--packager", kind,
                "--target", str(artifact),
            ], cwd=root / "linux" / arch, check=True)
            artifacts.append(artifact)
    recipes = output / f"vigolium_{version}_package-recipes.tar.gz"
    with tarfile.open(recipes, "w:gz") as archive:
        for name in ("aur", "nix", "snap", "scoop", "winget", "LICENSE", "THIRD_PARTY_NOTICES.md", "release.json"):
            # A local `nix build` may have left a result symlink to its store.
            # Bundle the recipes, never links to local build outputs.
            archive.add(root / name, arcname=name, filter=lambda entry: None if entry.issym() or entry.islnk() else entry)
    artifacts.append(recipes)
    checksums = []
    for artifact in artifacts:
        with artifact.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        checksums.append(f"{digest}  {artifact.name}\n")
    (output / "package-checksums.txt").write_text("".join(checksums))


if __name__ == "__main__":
    main()
