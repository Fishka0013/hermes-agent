"""Providerless integration tests using a local bare Git repository and a stub PR client.

No external network, credentials, GitHub API or production Hermes invocation.
"""
from __future__ import annotations

from contextlib import ExitStack
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


PUBLISHER_FILE = Path(__file__).resolve().parents[2] / "tools/hermes_gh_autopublish.py"
spec = importlib.util.spec_from_file_location("pub_github_e2e", PUBLISHER_FILE)
pub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pub)


def git(*args, cwd=None):
    return subprocess.run(
        ["git", *[str(x) for x in args]],
        cwd=cwd, capture_output=True, text=True,
        check=True, timeout=15,
    ).stdout.strip()


class LocalGitDeliveryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.remote = self.base / "remote.git"
        self.source = self.base / "source"
        self.worktrees = self.base / "worktrees"
        git("init", "--bare", "--initial-branch=main", self.remote)
        git("clone", self.remote, self.source)
        git("config", "user.name", "Hermes CI Test", cwd=self.source)
        git("config", "user.email", "hermes-ci@example.invalid", cwd=self.source)
        (self.source / "README.md").write_text("fixture repository\n")
        git("add", "README.md", cwd=self.source)
        git("commit", "-m", "seed", cwd=self.source)
        git("push", "-u", "origin", "main", cwd=self.source)
        self.main_sha = git("rev-parse", "HEAD", cwd=self.source)
        self.origin_patch = patch.object(pub, "ORIGIN", str(self.remote))
        self.origin_patch.start()
        self.addCleanup(self.origin_patch.stop)

    def test_prepare_is_isolated_from_source(self):
        pub.prepare(self.source, self.worktrees, "task-safe-001")
        w = self.worktrees / "task-safe-001"
        self.assertTrue(w.is_dir())
        self.assertEqual(git("rev-parse", "HEAD", cwd=w), self.main_sha)
        self.assertEqual(git("rev-parse", "--abbrev-ref", "HEAD", cwd=w),
                         "hermes/auto/task-safe-001")
        self.assertEqual(git("status", "--porcelain", cwd=self.source), "")
        self.assertEqual(git("ls-remote", "--heads", self.remote,
                             "refs/heads/hermes/auto/task-safe-001"), "")

    def test_publish_creates_only_one_branch_and_pr_without_main_change(self):
        pub.prepare(self.source, self.worktrees, "task-safe-002")
        w = self.worktrees / "task-safe-002"
        (w / "sample.py").write_text("answer = 42\n")
        gh_calls = []
        original_cmd = pub.cmd

        def fake_gh(argv, **kwargs):
            if argv and argv[0] == "gh":
                gh_calls.append(tuple(argv))
                self.assertIn("pr", argv)
                self.assertIn("create", argv)
                return "https://example.invalid/mock-pr"
            return original_cmd(argv, **kwargs)

        with patch.object(pub, "cmd", side_effect=fake_gh):
            pub.publish(self.worktrees, "task-safe-002", "tiny improvement", None)

        new_sha = git("rev-parse", "HEAD", cwd=w)
        self.assertNotEqual(new_sha, self.main_sha)
        self.assertEqual(
            git("ls-remote", "--heads", self.remote, "refs/heads/main").split()[0],
            self.main_sha,
        )
        self.assertEqual(
            git("ls-remote", "--heads", self.remote,
                "refs/heads/hermes/auto/task-safe-002").split()[0],
            new_sha,
        )
        self.assertEqual(len(gh_calls), 1)
        self.assertTrue((self.worktrees / ".receipts" /
                         "task-safe-002.intent.json").exists())
        with self.assertRaisesRegex(pub.Stop, "ALREADY_CLAIMED"):
            pub.publish(self.worktrees, "task-safe-002", "retry prohibited", None)
        self.assertEqual(len(gh_calls), 1)
        self.assertEqual(git("status", "--porcelain", cwd=self.source), "")

    def test_refuses_remote_origin_mismatch_before_checkout(self):
        with patch.object(pub, "ORIGIN", "https://example.invalid/wrong.git"):
            with self.assertRaisesRegex(pub.Stop, "ORIGIN_MISMATCH"):
                pub.prepare(self.source, self.worktrees, "task-safe-003")
        self.assertFalse((self.worktrees / "task-safe-003").exists())


if __name__ == "__main__":
    unittest.main()
