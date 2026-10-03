import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("generate", Path(__file__).with_name("generate.py"))
generate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generate)


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.output = self.root / "packages"
        self.version = "1.2.3"
        self.metadata = {"version": "v" + self.version, "build_time": "2026-09-24T16:59:03Z"}
        (self.dist / "metadata.json").write_text(json.dumps(self.metadata))
        for target in generate.TARGETS:
            if target.startswith("windows"):
                with zipfile.ZipFile(self.archive(target), "w") as archive:
                    archive.writestr("vigolium.exe", b"test-windows-binary")
            else:
                with tarfile.open(self.archive(target), "w:gz") as archive:
                    data = b"test-binary-" + target.encode()
                    entry = tarfile.TarInfo("vigolium")
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
        self.checksums()

    def archive(self, target):
        ext = "zip" if target.startswith("windows") else "tar.gz"
        return self.dist / f"vigolium_{self.version}_{target}.{ext}"

    def checksums(self):
        (self.dist / "checksums.txt").write_text("".join(
            f"{generate.sha256(self.archive(target))}  {self.archive(target).name}\n"
            for target in generate.TARGETS
        ))

    def run_generator(self):
        return generate.generate(self.dist, self.output, "Maintainer <test@example.com>")

    def test_generates_consistent_release_recipes(self):
        self.run_generator()
        binary = self.output / "linux/arm64/vigolium"
        self.assertEqual(binary.read_bytes(), b"test-binary-linux_arm64")
        scoop = json.loads((self.output / "scoop/vigolium.json").read_text())
        self.assertEqual(scoop["architecture"]["64bit"]["hash"], generate.sha256(self.archive("windows_amd64")))
        release = json.loads((self.output / "nix/release.json").read_text())
        self.assertEqual(release["version"], self.version)
        self.assertTrue(release["assets"]["linux_arm64"]["hash"].startswith("sha256-"))
        for path in self.output.rglob("*"):
            if path.is_file() and path.name != "vigolium":
                self.assertNotRegex(path.read_text(), r"@[A-Z_0-9]+@", str(path))

    def test_rejects_corruption_before_writing_output(self):
        self.archive("linux_arm64").write_bytes(b"corrupted")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.run_generator()
        self.assertFalse(self.output.exists())

    def test_rejects_incomplete_release(self):
        self.archive("windows_amd64").unlink()
        with self.assertRaises(FileNotFoundError):
            self.run_generator()
        self.assertFalse(self.output.exists())

    def test_rejects_prerelease(self):
        self.metadata["version"] = "v1.2.3-beta"
        (self.dist / "metadata.json").write_text(json.dumps(self.metadata))
        with self.assertRaisesRegex(ValueError, "stable"):
            self.run_generator()

    def test_preserves_previous_output(self):
        self.run_generator()
        marker = self.output / "keep"
        marker.write_text("do not overwrite")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.run_generator()
        self.assertEqual(marker.read_text(), "do not overwrite")

    def test_rejects_link_instead_of_binary(self):
        with tarfile.open(self.archive("linux_amd64"), "w:gz") as archive:
            entry = tarfile.TarInfo("vigolium")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "/tmp/not-a-vigolium-binary"
            archive.addfile(entry)
        self.checksums()
        with self.assertRaisesRegex(ValueError, "regular"):
            self.run_generator()
        self.assertFalse(self.output.exists())

    def test_rejects_duplicate_checksum(self):
        path = self.dist / "checksums.txt"
        contents = path.read_text()
        path.write_text(contents + contents.splitlines()[0] + "\n")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.run_generator()

    def test_existing_github_release_is_never_mutated(self):
        tool_dir = self.root / "tools"
        tool_dir.mkdir()
        log = self.root / "gh-calls"
        gh = tool_dir / "gh"
        gh.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$GH_TEST_LOG"\n[ "$1 $2" = "release view" ]\n')
        gh.chmod(0o755)
        result = subprocess.run(
            ["bash", str(generate.ROOT / "build/scripts/github-release.sh")],
            env=os.environ | {"PATH": str(tool_dir) + os.pathsep + os.environ["PATH"],
                              "VERSION": "v999.0.0", "GH_TEST_LOG": str(log)},
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stderr)
        self.assertEqual(log.read_text(), "release view v999.0.0\n")


if __name__ == "__main__":
    unittest.main()
