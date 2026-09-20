#!/usr/bin/env python3
"""Build locally sourced fixtures or fail closed on stale source/binary evidence."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def output(*args):
    return subprocess.check_output(args)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def snapshot(root):
    paths = sorted(set(output('git', '-C', str(root), 'ls-files', '-z', '--cached', '--others', '--exclude-standard').split(b'\0')) - {b''})
    h = hashlib.sha256()
    for raw in paths:
        path = root / os.fsdecode(raw)
        h.update(raw + b'\0')
        if path.is_symlink():
            h.update(b'link:' + os.fsencode(os.readlink(path)))
        elif path.is_file():
            h.update(str(path.stat().st_mode & 0o777).encode() + b':' + digest(path).encode())
        else:
            h.update(b'missing')
        h.update(b'\0')
    return {'head': output('git', '-C', str(root), 'rev-parse', 'HEAD').decode().strip(),
            'status_sha256': hashlib.sha256(output('git', '-C', str(root), 'status', '--porcelain=v1', '-z', '--untracked-files=all')).hexdigest(),
            'content_sha256': h.hexdigest()}


def binary(path):
    metadata = output('go', 'version', '-m', str(path)).decode().splitlines()[1:]
    tags = [line.split('=', 1)[1] for line in metadata if '\t-tags=' in line]
    if tags != ['with_utls,with_gvisor']:
        raise ValueError('fixture does not have the exact required build tags')
    return {'sha256': digest(path), 'go_build_metadata': metadata}


def main():
    mode = sys.argv[1]
    agent = Path(__file__).resolve().parent.parent
    controller_value = os.environ.get('OBOARD_PROCESS_CONTROLLER_ROOT')
    controller = Path(controller_value).resolve(strict=True) if controller_value else None
    controller_snapshot = snapshot(controller) if controller else {'status': 'not_used/unavailable'}
    manifest = Path(os.environ['OBOARD_PROCESS_MANIFEST']).resolve()
    paths = [Path(os.environ[key]).resolve() for key in ('OBOARD_PROCESS_KERNEL', 'OBOARD_PROCESS_KERNEL_NEXT')]
    if any(path.name != 'oboard-sb' for path in paths):
        raise ValueError('use separate directories with basename oboard-sb for kernel command selection')
    sources = {'agent': snapshot(agent), 'controller': controller_snapshot}
    if mode == 'build':
        workspace = Path(os.environ['OBOARD_PROCESS_WORKSPACE']).resolve(strict=True)
        for key in ('GOCACHE', 'GOMODCACHE', 'GOTMPDIR'):
            cache = Path(os.environ[key]).resolve()
            if not cache.is_relative_to(workspace) or any(cache.is_relative_to(root) for root in (agent, controller) if root is not None):
                raise ValueError(key + ' must be inside the external workspace, outside product repositories')
            cache.mkdir(parents=True, exist_ok=True)
        dist = (workspace / 'dist').resolve()
        for path in [manifest] + paths:
            if not path.is_relative_to(dist) or any(path.is_relative_to(root) for root in (agent, controller) if root is not None):
                raise ValueError('fixture output must be under workspace dist, outside product repositories')
            path.parent.mkdir(parents=True, exist_ok=True)
        if len(set(paths)) != 2 or manifest in paths:
            raise ValueError('fixture paths must be distinct')
        manifest.unlink(missing_ok=True)
        for index, path in enumerate(paths):
            flags = '-X github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/version.Build=process-fixture-' + str(index)
            subprocess.run(['go', 'build', '-trimpath', '-tags', 'with_utls,with_gvisor', '-ldflags', flags, '-o', str(path), './cmd/oboard-sb'], cwd=agent / 'kernel/oboard-sb', check=True, env={**os.environ, 'GOWORK': 'off', 'CGO_ENABLED': '0'})
        if sources['agent'] != snapshot(agent):
            raise ValueError('source changed during fixture build; no manifest issued')
        evidence = {'schema': 1, 'sources': sources, 'binaries': [binary(p) for p in paths]}
        manifest.write_text(json.dumps(evidence, indent=2) + '\n')
    elif mode == 'verify':
        evidence = json.loads(manifest.read_text())
        expected = {'schema': 1, 'sources': sources, 'binaries': [binary(p) for p in paths]}
        if (evidence.get('schema') != 1 or evidence.get('sources', {}).get('agent') != sources['agent']
                or evidence.get('binaries') != expected['binaries']):
            raise ValueError('fixture provenance mismatch; rebuild from the current Agent/kernel source')
        expected['controller_scope'] = 'metadata only: no Controller binary built or used by this entry'
        expected['controller_at_build'] = evidence['sources']['controller']
        print(json.dumps(expected, sort_keys=True))
    else:
        raise ValueError('expected build or verify')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print('process fixture provenance failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
