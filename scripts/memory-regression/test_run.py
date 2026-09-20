import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import run


class RunnerTests(unittest.TestCase):
    def test_non_linux_refuses_before_fixture_or_process_access(self):
        with patch.object(run.platform, 'system', return_value='Darwin'), patch.object(run, 'launch') as launch:
            with self.assertRaisesRegex(ValueError, 'Linux required'):
                run.execute(Mock(), {})
            launch.assert_not_called()

    def test_fixture_requires_private_explicit_synthetic_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'binary'
            binary.write_bytes(b'fixture')
            binary.chmod(0o700)
            config = root / 'config'
            config.write_text('{}')
            spec = {'binary': str(binary), 'args': [], 'cwd': str(root), 'configs': [str(config)]}
            fixture = {'synthetic_only': True, 'external_network_isolation': True,
                       'processes': dict.fromkeys(('agent', 'kernel', 'controller'), spec),
                       'proxy_port': 12345, 'declared_build_tags': ['with_utls', 'with_gvisor']}
            run.validate_fixture(fixture)
            fixture['synthetic_only'] = False
            with self.assertRaises(ValueError):
                run.validate_fixture(fixture)
            fixture['synthetic_only'] = True
            root.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'private'):
                run.validate_fixture(fixture)
            root.chmod(0o700)

    def test_child_enters_group_before_exec_and_external_does_not(self):
        with tempfile.TemporaryDirectory() as directory:
            group = Path(directory)
            owned = []
            with patch.object(run.subprocess, 'Popen') as popen:
                run.launch(['/test/bin'], group, owned, group)
                kwargs = popen.call_args.kwargs
                self.assertTrue(kwargs['start_new_session'])
                kwargs['preexec_fn']()
                self.assertEqual((group / 'cgroup.procs').read_text(), str(os.getpid()))
                run.launch(['/test/controller'], group, owned)
                self.assertIsNone(popen.call_args.kwargs['preexec_fn'])
                self.assertEqual(len(owned), 2)

    def test_cleanup_never_signals_reaped_pid_that_could_be_reused(self):
        process = Mock(pid=123, returncode=0)
        limitations = []
        with patch.object(run.os, 'killpg') as kill:
            self.assertEqual(run.cleanup([process], None, limitations), [])
        kill.assert_not_called()
        process.wait.assert_not_called()
        self.assertEqual(limitations, ['reaped_session_descendants_unverified'])

    def test_fifo_credentials_rejected_without_blocking_or_starting_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'credentials'
            os.mkfifo(path, 0o600)
            real_open = os.open
            def nonblocking_open(name, flags):
                self.assertTrue(flags & os.O_NONBLOCK)
                self.assertTrue(flags & os.O_NOFOLLOW)
                return real_open(name, flags)
            with patch.object(run.os, 'open', side_effect=nonblocking_open), patch.object(run, 'launch') as launch:
                with self.assertRaisesRegex(ValueError, 'regular file'):
                    run.read_credentials(path)
                launch.assert_not_called()

    def test_cleanup_failure_is_not_swallowed(self):
        process = Mock(pid=123, returncode=None)
        with patch.object(run.os, 'killpg', side_effect=PermissionError):
            self.assertEqual(run.cleanup([process], None), ['process_group_kill_failed'])
        process.wait.assert_called_once()


if __name__ == '__main__':
    unittest.main()
