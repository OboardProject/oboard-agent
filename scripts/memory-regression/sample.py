#!/usr/bin/env python3
"""Read-only cgroup v2 measurement component; not a complete workload benchmark."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time

BUDGETS = (128, 256, 512, 1024)
CGROUP_ROOT = Path("/sys/fs/cgroup")


class IdentityError(ValueError):
    pass


def validate_identity(group, roles, starts=None):
    name = "/" + str(group.resolve(strict=True).relative_to(CGROUP_ROOT))
    for role, pid in roles.items():
        try:
            member = membership(pid)
            expected = role in ("agent", "kernel") or role.startswith("forwarder")
            if (expected and member != name) or (not expected and inside(member, name)):
                raise IdentityError(f"incorrect cgroup membership for {role}")
            if starts is not None and process_start(pid) != starts[role]:
                raise IdentityError(f"process identity changed for {role}")
        except (OSError, StopIteration) as error:
            raise IdentityError(f"process unavailable for {role}") from error


def counters(text):
    return {key: int(value) for key, value in (line.split() for line in text.splitlines())}


def delta(before, after):
    if before.keys() != after.keys() or any(after[k] < before[k] for k in before):
        raise ValueError("counter reset or schema change during measurement")
    return {k: after[k] - before[k] for k in before}


def membership(pid):
    lines = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    return next(line[3:] for line in lines if line.startswith("0::"))


def inside(path, parent):
    return path == parent or path.startswith(parent.rstrip("/") + "/")


def process_start(pid):
    # comm may contain spaces and parentheses.
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def git_snapshot(repo):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], timeout=10)
    files = git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")
    digest = hashlib.sha256()
    for name in sorted(set(files) - {b""}):
        path = repo / os.fsdecode(name)
        digest.update(name + b"\0")
        if path.is_symlink():
            digest.update(b"symlink\0" + os.fsencode(os.readlink(path)))
        elif path.is_file():
            digest.update(str(path.stat().st_mode & 0o777).encode() + b"\0")
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
        else:
            digest.update(b"missing\0")
    return {"commit": git("rev-parse", "HEAD").decode().strip(),
            "dirty": bool(git("status", "--porcelain")),
            "worktree_sha256": digest.hexdigest()}


def snapshot(group):
    def read(name):
        return (group / name).read_text().strip()
    peak = group / "memory.peak"
    return {"monotonic_seconds": time.monotonic(),
            "memory_current_bytes": int(read("memory.current")),
            "memory_peak_bytes": int(peak.read_text()) if peak.exists() else None,
            "memory_stat": counters(read("memory.stat")),
            "memory_events": counters(read("memory.events")),
            "cpu_stat": counters(read("cpu.stat"))}


def validate(group, roles, budget, swap):
    root = CGROUP_ROOT
    if platform.system() != "Linux" or not (root / "cgroup.controllers").exists():
        raise ValueError("Linux cgroup v2 required; no measurements performed")
    group = group.resolve(strict=True)
    relative = group.relative_to(root)
    if str(relative) == ".":
        raise ValueError("a private delegated cgroup is required, never the root")
    validate_identity(group, roles)
    if len(set(roles.values())) != len(roles):
        raise ValueError("each role needs a distinct process")
    if (group / "memory.max").read_text().strip() != str(budget << 20):
        raise ValueError("memory.max does not match requested group budget")
    if (group / "memory.swap.max").read_text().strip() != str(swap):
        raise ValueError("memory.swap.max does not match explicit swap policy")
    # A stricter ancestor would invalidate the nominal test budget.
    ancestor_limits = []
    for ancestor in group.parents:
        if ancestor == root.parent:
            break
        memory = (ancestor / "memory.max")
        if memory.exists():
            value = memory.read_text().strip()
            if value != "max" and int(value) < budget << 20:
                raise ValueError("ancestor memory limit is below requested budget")
        swap_file = ancestor / "memory.swap.max"
        swap_value = swap_file.read_text().strip() if swap_file.exists() else None
        if swap_value is not None and swap_value != "max" and int(swap_value) < swap:
            raise ValueError("ancestor swap limit is below requested swap policy")
        ancestor_limits.append({"depth": len(ancestor.parts),
                                "memory_max": memory.read_text().strip() if memory.exists() else None,
                                "swap_max": swap_value,
                                "cpu_max": (ancestor / "cpu.max").read_text().strip()
                                if (ancestor / "cpu.max").exists() else None})
    return ancestor_limits


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cgroup", type=Path, required=True)
    parser.add_argument("--budget-mib", type=int, choices=BUDGETS, required=True)
    parser.add_argument("--swap-bytes", type=int, required=True)
    for role in ("agent", "kernel", "controller", "load"):
        parser.add_argument(f"--{role}-pid", type=int, required=True)
    parser.add_argument("--forwarder-pid", type=int, action="append", default=[])
    parser.add_argument("--controller-repo", type=Path, required=True)
    parser.add_argument("--agent-repo", type=Path, required=True)
    parser.add_argument("--phase", choices=("warmup", "steady", "burst", "recovery"), required=True)
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--isolated-synthetic-fixture", action="store_true", required=True,
                        help="attest externally isolated, synthetic fixture (not an isolation mechanism)")
    args = parser.parse_args()
    if not (0.1 <= args.interval <= 60 and args.interval <= args.duration <= 3600):
        parser.error("require 0.1 <= interval <= 60 and interval <= duration <= 3600")
    if args.swap_bytes < 0:
        parser.error("swap-bytes must be nonnegative")
    roles = {role: getattr(args, role + "_pid") for role in ("agent", "kernel", "controller", "load")}
    roles.update({f"forwarder{i}": pid for i, pid in enumerate(args.forwarder_pid)})
    roles["sampler"] = os.getpid()
    report = {"schema_version": 1, "status": "incomplete", "component": "measurement_only",
              "missing_evidence": ["verified TCP and UDP workloads", "throughput and success rate",
                                   "latency percentiles", "independent Agent control responsiveness",
                                   "configuration reapply", "network isolation enforcement",
                                   "binary provenance and build tags", "audit settings",
                                   "fresh cgroup lifetime peak", "repeatability and interference"],
              "samples": []}
    # Exclusive creation protects any prior evidence. Reports contain no command lines/configuration.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        try:
            ancestors = validate(args.cgroup, roles, args.budget_mib, args.swap_bytes)
            starts = {role: process_start(pid) for role, pid in roles.items()}
            report.update({"architecture": platform.machine(), "kernel": platform.release(),
                           "phase": args.phase, "budget_bytes": args.budget_mib << 20,
                           "swap_max_bytes": args.swap_bytes, "interval_seconds": args.interval,
                           "requested_duration_seconds": args.duration, "roles": roles,
                           "cpu_max": (args.cgroup / "cpu.max").read_text().strip(),
                           "ancestor_limits": ancestors,
                           "controller": git_snapshot(args.controller_repo),
                           "agent": git_snapshot(args.agent_repo)})
            deadline = time.monotonic() + args.duration
            while True:
                report["samples"].append(snapshot(args.cgroup))
                validate(args.cgroup, roles, args.budget_mib, args.swap_bytes)
                validate_identity(args.cgroup, roles, starts)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(args.interval, remaining))
            report["measurement_status"] = "collected"
        except IdentityError as error:
            report["status"] = "failed"
            report["failure"] = "process identity validation failed"
            report["process_failure"] = str(error)
        except (OSError, ValueError, StopIteration, subprocess.SubprocessError):
            report["status"] = "failed"
            report["failure"] = "platform, fixture, identity, counter or provenance validation failed"
        finally:
            if report["samples"]:
                if report["status"] == "failed":
                    try:
                        report["samples"].append(snapshot(args.cgroup))
                    except (OSError, ValueError):
                        report["final_sample_status"] = "unavailable"
                try:
                    first, last = report["samples"][0], report["samples"][-1]
                    report["memory_events_delta"] = delta(first["memory_events"], last["memory_events"])
                    report["cpu_stat_delta"] = delta(first["cpu_stat"], last["cpu_stat"])
                    report["observed_peak_bytes"] = max(s["memory_current_bytes"] for s in report["samples"])
                    if any(report["memory_events_delta"].get(k, 0) for k in ("oom", "oom_kill", "oom_group_kill")):
                        report["status"] = "failed"
                        report["oom_failure"] = "OOM observed in exploratory budget"
                except ValueError:
                    report["status"] = "failed"
                    report["counter_failure"] = "counter reset or schema change during measurement"
            json.dump(report, output, indent=2)
            output.write("\n")
    print(f"{report['status']}: measurement component only; not a benchmark acceptance result")
    return 1 if report["status"] == "failed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
