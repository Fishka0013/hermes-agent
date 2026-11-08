"""Providerless tests of the fork CI's path and content guard."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "tools/hermes_ci_guard.py"
spec = importlib.util.spec_from_file_location("hermes_ci_guard", SOURCE)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class ForkGateTests(unittest.TestCase):
    def test_safe_python_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "task.py").write_text("value = 42\n")
            self.assertEqual(guard.scan(root, ["task.py"]), 1)

    def test_reject_secret_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("not-a-secret")
            with self.assertRaises(guard.GuardFailure):
                guard.scan(root, [".env"])

    def test_reject_parent_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(guard.GuardFailure):
                guard.checked_path(Path(tmp), "../outside")

    def test_reject_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "link.py").symlink_to("/etc/hosts")
            with self.assertRaises(guard.GuardFailure):
                guard.checked_path(root, "link.py")

    def test_reject_private_key(self):
        with self.assertRaises(guard.GuardFailure):
            guard.check_content("key.txt", b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----\n")

    def test_reject_token_pattern(self):
        with self.assertRaises(guard.GuardFailure):
            guard.check_content("code.txt", b"prefix: " + b"ghp_" + b"A" * 35)

    def test_reject_syntax_error(self):
        with self.assertRaises(guard.GuardFailure):
            guard.check_content("x.py", b"def invalid(:\n pass\n")

    def test_reject_binary(self):
        with self.assertRaises(guard.GuardFailure):
            guard.check_content("x.txt", b"hello\x00world")

    def test_reject_too_many(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(guard.GuardFailure):
                guard.scan(Path(tmp), ["x"] * (guard.MAX_FILES + 1))


if __name__ == "__main__":
    unittest.main()
