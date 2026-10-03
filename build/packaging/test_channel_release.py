import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import channel_release


class ChannelReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "bucket").mkdir()
        self.manifest = self.root / "bucket/vigolium.json"
        self.manifest.write_text(json.dumps({"version": "0.10.0"}))

    def test_downgrades_compare_numeric_versions(self):
        with self.assertRaisesRegex(ValueError, "downgrade"):
            channel_release.guard_version("v0.9.9", "0.10.0")
        channel_release.guard_version("v0.10.0", "0.10.0")
        channel_release.guard_version("v1.0.0", "0.10.0")

    def test_only_stable_tags_can_reach_github(self):
        with patch.object(channel_release, "run") as run:
            for tag in ("latest", "v1.0.0-beta", "v01.0.0", "v1.2.3/../../other"):
                with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "stable"):
                    channel_release.release_info(tag)
            run.assert_not_called()

    def test_already_current_does_not_download_or_write(self):
        with patch.object(channel_release, "release_info", return_value={"tag_name": "v0.10.0"}), \
                patch.object(channel_release, "run") as run, contextlib.redirect_stdout(io.StringIO()) as log:
            channel_release.prepare(self.root, "scoop")
        run.assert_not_called()
        self.assertIn("validate=false", log.getvalue())
        self.assertFalse((self.root / ".candidate").exists())

    def test_prepare_rejects_rollback_before_downloading(self):
        before = self.manifest.read_bytes()
        with patch.object(channel_release, "release_info", return_value={"tag_name": "v0.9.9"}), \
                patch.object(channel_release, "run") as run:
            with self.assertRaisesRegex(ValueError, "downgrade"):
                channel_release.prepare(self.root, "scoop")
        run.assert_not_called()
        self.assertEqual(self.manifest.read_bytes(), before)

    def test_publish_rechecks_current_branch_before_staging(self):
        # A newer version landed while a candidate was being tested.
        with patch.object(channel_release, "run", return_value=json.dumps({"version": "0.11.0"})) as run:
            with self.assertRaisesRegex(ValueError, "downgrade"):
                channel_release.publish(self.root, "scoop")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[:2], ("git", "show"))


if __name__ == "__main__":
    unittest.main()
