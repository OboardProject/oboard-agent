#!/usr/bin/env python3
"""Opt-in Linux synthetic fixture runner. Exit 2 means incomplete evidence, not pass."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid

import sample

HERE = Path(__file__).resolve().parent


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_fixture(fixture):
    if fixture.get('synthetic_only') is not True or fixture.get('external_network_isolation') is not True:
        raise ValueError('explicit synthetic and external isolation attestations required')
    for role in ('agent', 'kernel', 'controller'):
        if role not in fixture['processes']:
            raise ValueError('missing role')
    for role, spec in fixture['processes'].items():
        if role not in ('agent', 'kernel', 'controller') and not role.startswith('forwarder-'):
            raise ValueError('unknown role')
        binary = Path(spec['binary'])
        if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError('absolute executable required')
        if not isinstance(spec['args'], list) or not all(isinstance(x, str) for x in spec['args']):
            raise ValueError('argument array required')
        cwd = Path(spec['cwd'])
        if not cwd.is_absolute() or not cwd.is_dir() or cwd.stat().st_mode & 0o077:
            raise ValueError('private explicit fixture cwd required')
        for config in spec['configs']:
            if not Path(config).is_absolute() or not Path(config).is_file():
                raise ValueError('explicit config file required')
    if not {'with_utls', 'with_gvisor'} <= set(fixture['declared_build_tags']):
        raise ValueError('required declared tags missing')
    if not 1 <= fixture['proxy_port'] <= 65535:
        raise ValueError('invalid loopback port')


def launch(command, cwd, owned, group=None, stdin=None):
    def enter():
        # Runs in the single-threaded fork child, before exec of any measured binary.
        with (group / 'cgroup.procs').open('w') as stream:
            stream.write(str(os.getpid()))
    process = subprocess.Popen(command, cwd=cwd, stdin=stdin or subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               env={'PATH': '/usr/bin:/bin', 'HOME': str(cwd), 'LANG': 'C',
                                    'PYTHONDONTWRITEBYTECODE': '1'},
                               start_new_session=True, preexec_fn=enter if group else None)
    owned.append(process)
    return process


def read_credentials(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('credentials require a mode-0600 regular file')
        data = os.read(fd, 2049)
        if len(data) > 2048:
            raise ValueError('credential input too large')
        credentials = json.loads(data)
        if not isinstance(credentials, dict) or any(
                not isinstance(credentials.get(key), str) or
                not 1 <= len(credentials[key].encode()) <= 255
                for key in ('username', 'password')):
            raise ValueError('invalid credentials')
        # Normalize to the one-line stdin contract without reopening the source.
        payload = json.dumps({key: credentials[key] for key in ('username', 'password')},
                             ensure_ascii=False, separators=(',', ':')).encode() + b'\n'
        if len(payload) > 2048:
            raise ValueError('credential input too large')
        return payload
    finally:
        os.close(fd)


def cleanup(owned, group, limitations=None):
    errors = []
    if limitations is None:
        limitations = []
    if group is not None:
        try:
            (group / 'cgroup.kill').write_text('1')
        except OSError:
            errors.append('cgroup_kill_failed')
    for process in reversed(owned):
        # poll/wait may already have released the PID for reuse. Never signal it.
        if process.returncode is not None:
            if 'reaped_session_descendants_unverified' not in limitations:
                limitations.append('reaped_session_descendants_unverified')
            continue
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            errors.append('process_group_kill_failed')
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            errors.append('process_wait_failed')
    if group is not None:
        deadline = time.monotonic() + 5
        while True:
            try:
                group.rmdir()
                break
            except OSError:
                if time.monotonic() >= deadline:
                    errors.append('owned_cgroup_cleanup_failed')
                    break
                time.sleep(.05)
    return errors


def execute(args, report):
    if platform.system() != 'Linux':
        raise ValueError('Linux required')
    report['stage'] = 'fixture_validation'
    fixture = json.loads(args.fixture.read_text())
    validate_fixture(fixture)
    credentials_data = read_credentials(args.credentials)
    parent = args.parent.resolve(strict=True)
    if parent == sample.CGROUP_ROOT or not parent.is_relative_to(sample.CGROUP_ROOT):
        raise ValueError('private delegated parent required')
    if 'memory' not in (parent / 'cgroup.subtree_control').read_text().split():
        raise ValueError('parent must already delegate memory; host settings are never changed')
    report.update({'architecture': platform.machine(), 'kernel': platform.release(),
                   'controller_repo': sample.git_snapshot(args.controller_repo),
                   'agent_repo': sample.git_snapshot(args.agent_repo),
                   'declared_build_tags': fixture['declared_build_tags'],
                   'build_tags_verified': False, 'budget_mib': args.budget_mib,
                   'swap_bytes': args.swap_bytes, 'interval': args.interval,
                   'audit_enabled_declared': fixture.get('audit_enabled') is True,
                   'interference_absent_declared': fixture.get('interference_absent') is True,
                   'external_isolation_verified': False, 'binaries': {}})
    owned, group = [], None
    try:
        report['stage'] = 'cgroup_creation'
        candidate = parent / ('oboard-measure-' + uuid.uuid4().hex)
        candidate.mkdir()
        group = candidate
        if not (group / 'cgroup.kill').exists():
            raise ValueError('cgroup.kill required for descendant cleanup')
        (group / 'memory.max').write_text(str(args.budget_mib << 20))
        (group / 'memory.swap.max').write_text(str(args.swap_bytes))
        report['group_cpu_max'] = (group / 'cpu.max').read_text().strip() if (group / 'cpu.max').exists() else None
        report['initial'] = sample.snapshot(group)
        roles = {'sampler': os.getpid()}
        report['stage'] = 'process_start_and_identity'
        for role, spec in fixture['processes'].items():
            expected = sha(spec['binary'])
            process = launch([spec['binary'], *spec['args']], Path(spec['cwd']), owned,
                             None if role == 'controller' else group)
            roles[role] = process.pid
            actual = sha(f'/proc/{process.pid}/exe')
            if expected != actual:
                raise ValueError('running executable does not match fixture binary')
            report['binaries'][role] = {'sha256': actual, 'pid': process.pid,
                                      'configs_sha256': [sha(p) for p in spec['configs']]}
        starts = {role: sample.process_start(pid) for role, pid in roles.items()}
        report['ancestor_limits'] = sample.validate(group, roles, args.budget_mib, args.swap_bytes)
        report['stage'] = 'listener_readiness'
        deadline = time.monotonic() + 30
        while True:
            sample.validate_identity(group, roles, starts)
            try:
                with socket.create_connection(('127.0.0.1', fixture['proxy_port']), timeout=.2):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise ValueError('listener readiness timeout')
                time.sleep(.1)
        report['samples'] = []
        for mode in ('idle', 'reconnect', 'transfer'):
            report['stage'] = 'load_' + mode
            read_fd, write_fd = os.pipe()
            with os.fdopen(read_fd, 'rb') as credentials:
                try:
                    os.write(write_fd, credentials_data)
                finally:
                    os.close(write_fd)
                command = [sys.executable, str(HERE / 'load.py'), '--proxy-host', '127.0.0.1',
                           '--proxy-port', str(fixture['proxy_port']), '--protocol', 'both',
                           '--mode', mode, '--duration', str(args.duration),
                           '--output', str(args.output / (mode + '.json'))]
                load = launch(command, args.output, owned, stdin=credentials)
            current = dict(roles, load=load.pid)
            current_starts = dict(starts, load=sample.process_start(load.pid))
            deadline = time.monotonic() + args.duration * 4 + 30
            while load.poll() is None:
                sample.validate_identity(group, current, current_starts)
                sample.validate(group, current, args.budget_mib, args.swap_bytes)
                if any(path.is_dir() for path in group.iterdir()):
                    raise ValueError('unexpected nested cgroup')
                report['samples'].append(dict(sample.snapshot(group), mode=mode))
                if time.monotonic() >= deadline:
                    raise ValueError('load timeout')
                time.sleep(args.interval)
            if load.wait() != 0:
                raise ValueError('load correctness failure')
        for role, spec in fixture['processes'].items():
            if sha(f'/proc/{roles[role]}/exe') != report['binaries'][role]['sha256']:
                raise ValueError('running binary changed')
        report['stage'] = 'collection_finished_incomplete'
    finally:
        if group is not None:
            try:
                report['final'] = sample.snapshot(group)
                report['events_delta'] = sample.delta(report['initial']['memory_events'], report['final']['memory_events'])
                report['oom_failure'] = any(v for k, v in report['events_delta'].items() if k in ('oom', 'oom_kill', 'oom_group_kill'))
            except (OSError, KeyError, ValueError):
                report['final_sample_unavailable'] = True
        report['cleanup_limitations'] = []
        report['cleanup_errors'] = cleanup(owned, group, report['cleanup_limitations'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('fixture', 'parent', 'controller-repo', 'agent-repo', 'credentials', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--budget-mib', type=int, choices=sample.BUDGETS, required=True)
    parser.add_argument('--swap-bytes', type=int, required=True)
    parser.add_argument('--duration', type=float, default=10)
    parser.add_argument('--interval', type=float, default=.5)
    args = parser.parse_args()
    if not 1 <= args.duration <= 300 or not .1 <= args.interval <= 10 or args.swap_bytes < 0:
        parser.error('invalid measurement bounds')
    if platform.system() != 'Linux':
        parser.error('Linux cgroup v2 required; no processes started')
    args.output = args.output.absolute()
    args.output.mkdir(mode=0o700)  # Exclusive run directory; never replace evidence.
    report = {'benchmark_complete': False, 'missing_evidence': [
        'Agent authenticated control roundtrips under pressure', 'repeated configuration application',
        'SOCKS listener ownership and kernel runtime digest', 'QUIC workload',
        'independent external network isolation proof', 'repeated matrix runs and variation',
        'build tags attestation verification']}
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    previous_term = signal.signal(signal.SIGTERM, interrupted)
    try:
        execute(args, report)
    except (Exception, KeyboardInterrupt) as error:
        report['failure'] = type(error).__name__  # Never log fixture arguments or credentials.
    finally:
        signal.signal(signal.SIGTERM, previous_term)
    failed = report.get('failure') or report.get('cleanup_errors') or report.get('oom_failure') or report.get('final_sample_unavailable')
    with (args.output / 'run.json').open('x') as stream:
        os.chmod(stream.name, 0o600)
        json.dump(report, stream, indent=2)
    print('Fixture failed; inspect private report.' if failed else 'Measurements collected; benchmark evidence INCOMPLETE.')
    return 1 if failed else 2


if __name__ == '__main__':
    sys.exit(main())
