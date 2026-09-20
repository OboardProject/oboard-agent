import contextlib
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest

spec = importlib.util.spec_from_file_location("memory_load", Path(__file__).with_name("load.py"))
load = importlib.util.module_from_spec(spec)
spec.loader.exec_module(load)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        control = self.request
        control.settimeout(1)
        try:
            self.serve(control)
        except (OSError, load.LoadError):
            pass

    def serve(self, control):
        if load.exact(control, 3) != b"\x05\x01\x02":
            return
        control.sendall(b"\x05\x02")
        version, length = load.exact(control, 2)
        user = load.exact(control, length)
        password = load.exact(control, load.exact(control, 1)[0])
        if version != 1 or user != b"synthetic" or password != b"private-fixture":
            control.sendall(b"\x01\x01")
            return
        control.sendall(b"\x01\x00")
        version, command, reserved, atyp = load.exact(control, 4)
        if (version, reserved, atyp) != (5, 0, 1):
            return
        target = socket.inet_ntoa(load.exact(control, 4)), int.from_bytes(load.exact(control, 2), "big")
        load.loopback(target[0])
        with self.server.lock:
            self.server.commands.append(command)
        if command == 1:
            with socket.create_connection(target, timeout=1) as upstream:
                control.sendall(b"\x05\x00\x00" + load.endpoint(upstream.getsockname()))
                while True:
                    ready, _, _ = select.select([upstream, control], [], [], 1)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(65535)
                        if not data:
                            return
                        destination = upstream if source is control else control
                        if source is upstream and self.server.fault == "payload":
                            data = bytes([data[0] ^ 1]) + data[1:]
                        destination.sendall(data)
                        with self.server.lock:
                            self.server.relayed += len(data)
        elif command == 3:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                relay.bind(("127.0.0.1", 0))
                upstream.settimeout(1)
                control.sendall(b"\x05\x00\x00" + load.endpoint(relay.getsockname()))
                while True:
                    ready, _, _ = select.select([relay, control], [], [], 1)
                    if not ready or control in ready:
                        return
                    data, sender = relay.recvfrom(65535)
                    if sender != target or data[:4] != b"\x00\x00\x00\x01":
                        return
                    destination = socket.inet_ntoa(data[4:8]), int.from_bytes(data[8:10], "big")
                    load.loopback(destination[0])
                    upstream.sendto(data[10:], destination)
                    response, address = upstream.recvfrom(65535)
                    if self.server.fault == "endpoint":
                        address = (address[0], address[1] ^ 1)
                    relay.sendto(b"\x00\x00\x00" + load.endpoint(address) + response, sender)
                    with self.server.lock:
                        self.server.relayed += len(response) * 2


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = False
    block_on_close = True
    request_queue_size = 128


@contextlib.contextmanager
def proxy(fault=None):
    with Server(("127.0.0.1", 0), Handler) as server:
        server.lock = threading.Lock()
        server.commands = []
        server.relayed = 0
        server.fault = fault
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(2)
            if thread.is_alive():
                raise AssertionError("fixture thread leaked")


def args(port, protocol="both", mode="transfer"):
    result = load.parser().parse_args([
        "--proxy-host", "127.0.0.1", "--proxy-port", str(port),
        "--protocol", protocol, "--mode", mode, "--duration", ".04",
        "--idle-seconds", ".005", "--concurrency", "2", "--max-operations", "20",
        "--payload-bytes", "64", "--output", "unused"])
    load.validate(result)
    return result


class LoadTests(unittest.TestCase):
    def test_real_socket_fixture_all_modes_and_protocols(self):
        # This is a synthetic SOCKS fixture, NOT evidence of real kernel behavior.
        for mode in ("idle", "reconnect", "transfer"):
            with self.subTest(mode=mode), proxy() as server:
                report = load.run(args(server.server_address[1], mode=mode), (b"synthetic", b"private-fixture"))
                self.assertEqual(report["status"], "load_component_pass")
                self.assertFalse(report["benchmark_complete"])
                self.assertIn("agent_control_responsiveness", report["missing_evidence"])
                self.assertEqual({1, 3}, set(server.commands))
                count = 0
                for phase in report["phases"]:
                    self.assertGreater(phase["summary"]["completed"], 0)
                    self.assertEqual(phase["summary"]["errors"], 0)
                    self.assertEqual({"tcp", "udp"}, {s["protocol"] for s in phase["samples"]})
                    count += phase["summary"]["verified_roundtrip_bytes"]
                self.assertEqual(server.relayed, count)
                if mode == "reconnect":
                    self.assertEqual(len(server.commands), sum(p["summary"]["completed"] for p in report["phases"]))

    def test_payload_and_udp_endpoint_mismatch_fail(self):
        for fault, protocol, error in (("payload", "tcp", "payload_mismatch"), ("endpoint", "udp", "udp_endpoint_or_frame_mismatch")):
            with self.subTest(fault=fault), proxy(fault) as server:
                report = load.run(args(server.server_address[1], protocol), (b"synthetic", b"private-fixture"))
                self.assertEqual(report["status"], "load_failed")
                self.assertTrue(all(p["summary"]["completed"] == 0 for p in report["phases"]))
                self.assertEqual({error}, {s["error"] for p in report["phases"] for s in p["samples"]})

    def test_no_proxy_cannot_succeed_by_direct_echo(self):
        with socket.socket() as unavailable:
            unavailable.bind(("127.0.0.1", 0))
            report = load.run(args(unavailable.getsockname()[1]), (b"synthetic", b"private-fixture"))
        self.assertEqual(report["status"], "load_failed")
        self.assertTrue(all(p["summary"]["completed"] == 0 for p in report["phases"]))

    def test_cli_private_exclusive_report_and_no_secret(self):
        with proxy() as server, tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            command = [sys.executable, str(Path(load.__file__)), "--proxy-host", "127.0.0.1", "--proxy-port", str(server.server_address[1]), "--output", str(output), "--duration", ".03", "--max-operations", "16"]
            credentials = b'{"username":"synthetic","password":"private-fixture"}\n'
            result = subprocess.run(command, input=credentials, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(b"private-fixture", output.read_bytes() + result.stdout + result.stderr)
            original = output.read_bytes()
            result = subprocess.run(command, input=credentials, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(original, output.read_bytes())
            output.unlink()
            result = subprocess.run(command, input=b'{"username":"synthetic","password":"wrong-secret"}', capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(b"wrong-secret", output.read_bytes() + result.stdout + result.stderr)
            self.assertEqual(json.loads(output.read_text())["status"], "load_failed")

    def test_bounds_and_loopback_only(self):
        for address in ("localhost", "192.0.2.1", "0.0.0.0", "::1"):
            with self.assertRaises(ValueError):
                load.loopback(address)
        for field, value in (("duration", float("nan")), ("timeout", float("inf")), ("concurrency", 65), ("payload_bytes", 60001), ("max_operations", 25001)):
            parameters = args(12345)
            setattr(parameters, field, value)
            with self.assertRaises(ValueError):
                load.validate(parameters)
        self.assertEqual(load.summary([], 1)["latency_ms"]["p99"], None)


if __name__ == "__main__":
    unittest.main()
