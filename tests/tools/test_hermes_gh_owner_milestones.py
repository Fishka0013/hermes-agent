"""No-network tests of the existing Architecture OwnerEvent integration."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[2] / "tools/hermes_gh_autopublish.py"
spec = importlib.util.spec_from_file_location("gh_milestone", SOURCE)
pub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pub)


class OwnerMilestonesTest(unittest.TestCase):
    def test_bad_task_refused_without_delivery(self):
        with self.assertRaises(AssertionError):
            # Notifier returns a typed refusal, not a network send.
            self.assertNotEqual(pub.report_owner_milestone("../escape", "start"), "NOTIFY_INPUT_REJECTED")
        self.assertEqual(pub.report_owner_milestone("safe-task", "other"), "NOTIFY_INPUT_REJECTED")

    def test_missing_adapter_reports_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                pub.report_owner_milestone("safe-task", "start", adapter_dir=tmp),
                "NOTIFIER_UNAVAILABLE",
            )

    def test_live_contract_calls_existing_owner_event_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "owner_events.py").write_text("# stub imported from sys.modules\n")
            calls = []
            mod = types.ModuleType("owner_events")

            def emit(*args, **kwargs):
                calls.append((args, kwargs))
                return {"status": "SENT"}
            mod.emit = emit

            with patch.dict(sys.modules, {"owner_events": mod}):
                state = pub.report_owner_milestone(
                    "abc-20261108", "done",
                    pr_url="https://github.com/Fishka0013/hermes-agent/pull/4",
                    adapter_dir=root,
                )
            self.assertEqual(state, "SENT")
            self.assertEqual(len(calls), 1)
            args, kw = calls[0]
            self.assertEqual(args[0], root / "data/architecture.sqlite3")
            self.assertEqual(kw["source"], "Hermes")
            self.assertEqual(kw["event_type"], "DONE")
            self.assertEqual(kw["stable_key"], "github-abc-20261108-done")
            self.assertTrue(kw["evidence_locator"].endswith("/pull/4"))

    def test_start_and_blocked_omit_external_locator(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "owner_events.py").touch()
            calls = []
            mod = types.ModuleType("owner_events")
            def emit(*args, **kwargs):
                calls.append(kwargs)
                return {"status": "DELIVERY_UNKNOWN"}
            mod.emit = emit
            with patch.dict(sys.modules, {"owner_events": mod}):
                result1 = pub.report_owner_milestone("safe-task", "start", adapter_dir=root)
                result2 = pub.report_owner_milestone("safe-task", "blocked", adapter_dir=root)
            self.assertEqual((result1,result2), ("DELIVERY_UNKNOWN","DELIVERY_UNKNOWN"))
            self.assertEqual([c["event_type"] for c in calls],["START","PARTIAL"])
            self.assertTrue(all(c["evidence_locator"] is None for c in calls))

    def test_notifier_error_does_not_break_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "owner_events.py").touch()
            mod = types.ModuleType("owner_events")
            def emit(*args, **kwargs):
                raise RuntimeError("transport unreachable")
            mod.emit = emit
            with patch.dict(sys.modules, {"owner_events": mod}):
                self.assertEqual(
                    pub.report_owner_milestone("safe-task", "done", adapter_dir=root),
                    "NOTIFY_ERROR",
                )


if __name__ == "__main__":
    unittest.main()
