#!/usr/bin/env python3
"""Generate package recipes from an existing, checksum-verified stable release.

No builds, network requests, registry writes, or package installation occur here.
Run from any directory; generated nFPM configs use paths relative to their folder.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = Path(__file__).resolve().parent / "templates"
TARGETS = ("linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64", "windows_amd64")
REPOSITORY = "https://github.com/vigolium/vigolium"


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def render(name, values):
    text = (TEMPLATES / name).read_text(encoding="utf-8")
    return re.sub(r"@([A-Z_0-9]+)@", lambda m: str(values[m[1]]), text)


def load_release(dist):
    metadata = json.loads((dist / "metadata.json").read_text())
    tag = metadata["version"]
    # Stable versions only: AUR, RPM, Snap and WinGet order prereleases differently.
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        raise ValueError("package channels require a stable vMAJOR.MINOR.PATCH release")
    version = tag[1:]
    checksums = {}
    for line in (dist / "checksums.txt").read_text().splitlines():
        match = re.fullmatch(r"([a-fA-F0-9]{64})\s+\*?([^/\\\s]+)", line)
        if not match or match[2] in checksums:
            raise ValueError("invalid or duplicate checksums.txt entry")
        checksums[match[2]] = match[1].lower()
    assets = {}
    for target in TARGETS:
        extension = "zip" if target.startswith("windows") else "tar.gz"
        name = f"vigolium_{version}_{target}.{extension}"
        path = dist / name
        expected = checksums.get(name)
        if not expected or sha256(path) != expected:
            raise ValueError(f"missing or mismatched SHA-256: {name}")
        assets[target] = {
            "url": f"{REPOSITORY}/releases/download/{tag}/{name}",
            "sha256": expected,
            "hash": "sha256-" + base64.b64encode(bytes.fromhex(expected)).decode(),
            "name": name,
        }
    return metadata, assets


def extract_binary(archive, target, destination):
    """Copy only the expected regular file; never extract archive paths/links."""
    name = "vigolium.exe" if target.startswith("windows") else "vigolium"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if name.endswith(".exe"):
        with zipfile.ZipFile(archive) as source:
            entries = [m for m in source.infolist() if m.filename == name]
            if len(entries) != 1 or entries[0].is_dir():
                raise ValueError(f"expected exactly one {name} in {archive}")
            with source.open(entries[0]) as binary, destination.open("wb") as out:
                shutil.copyfileobj(binary, out)
    else:
        with tarfile.open(archive, "r:gz") as source:
            entries = [m for m in source.getmembers() if m.name in (name, "./" + name)]
            if len(entries) != 1 or not entries[0].isfile():
                raise ValueError(f"expected exactly one regular {name} in {archive}")
            with source.extractfile(entries[0]) as binary, destination.open("wb") as out:
                shutil.copyfileobj(binary, out)
    if destination.stat().st_size == 0:
        raise ValueError(f"empty binary in {archive}")
    destination.chmod(0o755)


def generate(dist, out, maintainer, notices_dir=ROOT):
    metadata, assets = load_release(dist)
    version = metadata["version"][1:]
    values = {
        "VERSION": version, "TAG": metadata["version"],
        "RELEASE_DATE": metadata["build_time"][:10],
        "LICENSE_SHA256": sha256(notices_dir / "LICENSE"),
        "NOTICES_SHA256": sha256(notices_dir / "THIRD_PARTY_NOTICES.md"),
    }
    for target, asset in assets.items():
        values[target.upper() + "_URL"] = asset["url"]
        values[target.upper() + "_SHA256"] = asset["sha256"]
    # Stage beside the destination so a validation failure leaves previous output intact.
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        raise ValueError(f"output already exists: {out}; choose a new --output directory")
    with tempfile.TemporaryDirectory(prefix=".packages-", dir=out.parent) as temp:
        stage = Path(temp) / "packages"
        stage.mkdir()
        for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            shutil.copyfile(notices_dir / name, stage / name)
        write(stage / "release.json", json.dumps({"version": version, "assets": assets}, indent=2) + "\n")
        for name in ("PKGBUILD", ".SRCINFO"):
            write(stage / "aur" / name, render("aur/" + name, values))
        for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            shutil.copyfile(stage / name, stage / "aur" / name)
        for arch in ("amd64", "arm64"):
            target = "linux_" + arch
            binary = stage / "linux" / arch / "vigolium"
            extract_binary(dist / assets[target]["name"], target, binary)
            for kind in ("deb", "rpm"):
                write(binary.parent / (kind + ".package-manager"), kind + "\n")
                config = {
                    "name": "vigolium", "arch": arch, "platform": "linux",
                    "version": version, "release": "1", "maintainer": maintainer,
                    "description": "Web vulnerability scanner and traffic analysis CLI",
                    "homepage": "https://vigolium.com", "license": "MIT",
                    "section": "net", "priority": "optional",
                    "mtime": metadata["build_time"],
                    "depends": ["ca-certificates", "libc6", "libstdc++6", "zlib1g"] if kind == "deb"
                    else ["ca-certificates", "glibc", "libstdc++", "zlib"],
                    "contents": [
                        {"src": "vigolium", "dst": "/usr/lib/vigolium/vigolium", "file_info": {"mode": 0o755}},
                        {"src": kind + ".package-manager", "dst": "/usr/lib/vigolium/.vigolium-package-manager"},
                        {"src": "/usr/lib/vigolium/vigolium", "dst": "/usr/bin/vigolium", "type": "symlink"},
                        {"src": "../../LICENSE", "dst": "/usr/share/licenses/vigolium/LICENSE"},
                        {"src": "../../THIRD_PARTY_NOTICES.md", "dst": "/usr/share/doc/vigolium/THIRD_PARTY_NOTICES.md"},
                    ],
                }
                write(binary.parent / (kind + ".json"), json.dumps(config, indent=2) + "\n")
            snap_values = values | {"ARCH": arch, "URL": assets[target]["url"], "SHA256": assets[target]["sha256"]}
            write(stage / "snap" / arch / "snapcraft.yaml", render("snapcraft.yaml", snap_values))
            for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
                shutil.copyfile(stage / name, stage / "snap" / arch / name)
        write(stage / "scoop" / "vigolium.json", json.dumps({
            "version": version, "description": "Web vulnerability scanner and traffic analysis CLI",
            "homepage": "https://vigolium.com", "license": "MIT",
            "architecture": {"64bit": {"url": assets["windows_amd64"]["url"], "hash": assets["windows_amd64"]["sha256"]}},
            "bin": "vigolium.exe",
            "post_install": "Set-Content -Path \"$dir\\.vigolium-package-manager\" -Value 'scoop' -Encoding ascii",
            "checkver": {"github": REPOSITORY},
        }, indent=2) + "\n")
        winget = stage / "winget" / "manifests" / "v" / "Vigolium" / "Vigolium" / version
        for name in ("Vigolium.Vigolium.yaml", "Vigolium.Vigolium.installer.yaml", "Vigolium.Vigolium.locale.en-US.yaml"):
            write(winget / name, render("winget/" + name, values))
        for name in ("flake.nix", "flake.lock", "package.nix"):
            write(stage / "nix" / name, (TEMPLATES / "nix" / name).read_text())
        for name in ("release.json", "LICENSE", "THIRD_PARTY_NOTICES.md"):
            shutil.copyfile(stage / name, stage / "nix" / name)
        stage.rename(out)
    return version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=ROOT / "build/dist-public")
    parser.add_argument("--output", type=Path, default=ROOT / "build/dist-packages")
    parser.add_argument("--notices-dir", type=Path, default=ROOT, help="source directory at the release tag")
    parser.add_argument("--maintainer", default="Vigolium maintainers <contact@vigolium.com>")
    args = parser.parse_args()
    try:
        version = generate(args.dist.resolve(), args.output.resolve(), args.maintainer, args.notices_dir.resolve())
    except (ValueError, KeyError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(1, f"packaging: {error}\n")
    print(f"Prepared Vigolium {version} packages in {args.output}")


if __name__ == "__main__":
    main()
