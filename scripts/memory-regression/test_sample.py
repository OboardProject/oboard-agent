import json
import tempfile
from contextlib import ExitStack
import unittest
from pathlib import Path
from unittest.mock import patch

import sample


class MeasurementTests(unittest.TestCase):
    def test_events_are_deltas_not_lifetime_totals(self):
        self.assertEqual(sample.delta({"oom": 4, "high": 8}, {"oom": 4, "high": 11}),
                         {"oom": 0, "high": 3})
        for after in ({"oom": 3}, {"other": 4}):
            with self.assertRaises(ValueError):
                sample.delta({"oom": 4}, after)

    def test_membership_has_path_boundary(self):
        self.assertTrue(sample.inside("/bench/run/agent", "/bench/run"))
        self.assertTrue(sample.inside("/bench/run", "/bench/run"))
        self.assertFalse(sample.inside("/bench/runtime", "/bench/run"))

    def test_snapshot_keeps_overlapping_categories_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            group = Path(directory)
            for name, value in {"memory.current": "100", "memory.stat": "anon 60\nfile 30\nshmem 20\n",
                                "memory.events": "oom 0\n", "cpu.stat": "usage_usec 15\n"}.items():
                (group / name).write_text(value)
            result = sample.snapshot(group)
            self.assertEqual(result["memory_current_bytes"], 100)
            self.assertEqual(result["memory_stat"]["shmem"], 20)
            self.assertIsNone(result["memory_peak_bytes"])

    def fixture(self, directory, swap="0", ancestor_swap="max"):
        root = Path(directory).resolve() / "cgroup"
        group = root / "run"
        group.mkdir(parents=True)
        (root / "cgroup.controllers").write_text("memory cpu")
        for base, values in ((root, {"memory.max": "max", "memory.swap.max": ancestor_swap,
                                     "cpu.max": "max 100000"}),
                             (group, {"memory.max": str(128 << 20), "memory.swap.max": swap,
                                      "cpu.max": "max 100000", "memory.current": "100",
                                      "memory.events": "oom 0\noom_kill 0\n",
                                      "memory.stat": "anon 100\n", "cpu.stat": "usage_usec 10\n"})):
            for name, value in values.items():
                (base / name).write_text(value)
        return root, group

    def test_complete_validation_and_membership_rejections(self):
        with tempfile.TemporaryDirectory() as directory:
            root, group = self.fixture(directory)
            roles = {"agent": 1, "kernel": 2, "forwarder0": 3, "controller": 4, "load": 5}
            members = {1: "/run", 2: "/run", 3: "/run", 4: "/outside", 5: "/outside"}
            with patch("sample.CGROUP_ROOT", root), patch("sample.platform.system", return_value="Linux"), \
                    patch("sample.membership", side_effect=lambda pid: members[pid]):
                limits = sample.validate(group, roles, 128, 0)
                self.assertEqual(limits[0]["swap_max"], "max")
                for role in ("agent", "kernel", "forwarder0", "controller", "load"):
                    pid = roles[role]
                    previous = members[pid]
                    members[pid] = "/run/child"
                    with self.assertRaises(sample.IdentityError):
                        sample.validate(group, roles, 128, 0)
                    members[pid] = previous
                (root / "memory.swap.max").write_text("0")
                self.assertEqual(sample.validate(group, roles, 128, 0)[0]["swap_max"], "0")
                (group / "memory.swap.max").write_text("1024")
                with self.assertRaisesRegex(ValueError, "ancestor swap limit"):
                    sample.validate(group, roles, 128, 1024)
                (root / "memory.swap.max").write_text("max")
                self.assertEqual(sample.validate(group, roles, 128, 1024)[0]["swap_max"], "max")

    def test_exit_reports_preserve_oom_when_process_disappears(self):
        for disappears in (False, True):
            with self.subTest(disappears=disappears), tempfile.TemporaryDirectory() as directory:
                root, group = self.fixture(directory)
                output = Path(directory) / "report.json"
                dead = False

                def member(pid):
                    if dead and pid == 1:
                        raise FileNotFoundError()
                    return "/run" if pid in (1, 2) else "/outside"

                def sleep(_):
                    nonlocal dead
                    if disappears:
                        dead = True
                        (group / "memory.events").write_text("oom 1\noom_kill 1\n")

                argv = ["sample.py", "--cgroup", str(group), "--budget-mib", "128",
                        "--swap-bytes", "0", "--agent-pid", "1", "--kernel-pid", "2",
                        "--controller-pid", "3", "--load-pid", "4", "--controller-repo", directory,
                        "--agent-repo", directory, "--phase", "steady", "--duration", "1",
                        "--interval", "0.5", "--output", str(output), "--isolated-synthetic-fixture"]
                with ExitStack() as stack:
                    for target, kwargs in (
                        ("sample.CGROUP_ROOT", {"new": root}),
                        ("sample.platform.system", {"return_value": "Linux"}),
                        ("sample.membership", {"side_effect": member}),
                        ("sample.process_start", {"return_value": "start"}),
                        ("sample.git_snapshot", {"return_value": {"commit": "synthetic"}}),
                        ("sample.time.sleep", {"side_effect": sleep}),
                        ("sample.time.monotonic", {"side_effect": [0, 0, 0.5, 1, 1, 1]}),
                        ("sys.argv", {"new": argv})):
                        stack.enter_context(patch(target, **kwargs))
                    self.assertEqual(sample.main(), 1 if disappears else 2)
                report = json.loads(output.read_text())
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertEqual(report["component"], "measurement_only")
                self.assertEqual(report["memory_events_delta"]["oom_kill"], int(disappears))
                if disappears:
                    self.assertEqual(report["process_failure"], "process unavailable for agent")
                    self.assertIn("oom_failure", report)
                    self.assertEqual(report["status"], "failed")
                else:
                    self.assertEqual(report["status"], "incomplete")
                    self.assertEqual(report["measurement_status"], "collected")
                with patch("sys.argv", argv):
                    with self.assertRaises(FileExistsError):
                        sample.main()

    def test_non_linux_is_explicit_failure(self):
        with patch("sample.platform.system", return_value="Darwin"):
            with self.assertRaisesRegex(ValueError, "Linux cgroup v2 required"):
                sample.validate(Path("/irrelevant"), {}, 128, 0)


if __name__ == "__main__":
    unittest.main()
