"""No-network guard tests for the Hermes isolated GitHub publisher."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[2] / "tools/hermes_gh_autopublish.py"
spec = importlib.util.spec_from_file_location("hermes_gh_autopublish", SOURCE)
pub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pub)


class AutoPublishGuardTests(unittest.TestCase):
    def test_slug_rejects_parent_or_space(self):
        for item in ("../escape", "A", "has space", "-start", "a" * 70):
            with self.subTest(item=item), self.assertRaises(pub.Stop):
                pub.check_task(item)

    def test_allowed_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "safe.py").write_text("value = 1\n")
            pub.validate_files(root, ["safe.py"])

    def test_reject_secret_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("HELLO=world")
            with self.assertRaises(pub.Stop):
                pub.validate_files(root, [".env"])

    def test_reject_secret_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "x.py").write_text("x = '" + "ghp_" + "A" * 36 + "'\n")
            with self.assertRaises(pub.Stop):
                pub.validate_files(root, ["x.py"])

    def test_reject_syntax_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "x.py").write_text("def broken(:\n pass\n")
            with self.assertRaises(pub.Stop):
                pub.validate_files(root, ["x.py"])

    def test_reject_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "link.py").symlink_to("/etc/hosts")
            with self.assertRaises(pub.Stop):
                pub.validate_files(root, ["link.py"])

    def test_reject_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "data.bin").write_bytes(b"hello\x00world")
            with self.assertRaises(pub.Stop):
                pub.validate_files(root, ["data.bin"])

    def test_claim_is_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "claim.json"
            pub.save_once(path, {"message": "test"})
            self.assertEqual(path.read_text().count("test"), 1)
            with self.assertRaises(pub.Stop):
                pub.save_once(path, {"message": "again"})

    def test_workspace_path_is_scoped(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = pub.expected_workspace(Path(tmp), "abc", require=False)
            self.assertEqual(p.parent, Path(tmp).resolve())
            with self.assertRaises(pub.Stop):
                pub.expected_workspace(Path(tmp), "../other", require=False)


if __name__ == "__main__":
    unittest.main()
