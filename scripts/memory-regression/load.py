#!/usr/bin/env python3
"""Bounded synthetic loopback load through an explicit authenticated SOCKS5 proxy."""
import argparse
import concurrent.futures
import ipaddress
import json
import math
import os
import secrets
import select
import socket
import struct
import sys
import threading
import time


MISSING_EVIDENCE = [
    "real_kernel_identity_and_path_proof", "shared_cgroup_limits_and_membership",
    "agent_control_responsiveness", "configuration_apply_under_load",
    "QUIC", "resource_samples_and_repeated_baseline", "external_network_isolation",
]


class LoadError(Exception):
    pass


def loopback(value):
    try:
        address = ipaddress.IPv4Address(value)
        if address.is_loopback:
            return str(address)
    except ipaddress.AddressValueError:
        pass
    raise ValueError("explicit IPv4 loopback address required")


def exact(sock, count):
    result = b""
    timeout = sock.gettimeout()
    deadline = time.monotonic() + timeout if timeout is not None else None
    try:
        while len(result) < count:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise LoadError("read_deadline_exceeded")
                sock.settimeout(remaining)
            part = sock.recv(count - len(result))
            if not part:
                raise LoadError("proxy_closed")
            result += part
        return result
    finally:
        sock.settimeout(timeout)


def endpoint(address):
    return b"\x01" + socket.inet_aton(address[0]) + struct.pack("!H", address[1])


def authenticate(sock, username, password):
    sock.sendall(b"\x05\x01\x02")
    if exact(sock, 2) != b"\x05\x02":
        raise LoadError("authentication_method_rejected")
    sock.sendall(b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password)
    if exact(sock, 2) != b"\x01\x00":
        raise LoadError("authentication_rejected")


def request(sock, command, target):
    sock.sendall(b"\x05" + bytes([command]) + b"\x00" + endpoint(target))
    head = exact(sock, 4)
    if head[:3] != b"\x05\x00\x00" or head[3] != 1:
        raise LoadError("proxy_reply_rejected")
    return socket.inet_ntoa(exact(sock, 4)), struct.unpack("!H", exact(sock, 2))[0]


class Echo:
    """One bounded select loop; never dials or forwards to another endpoint."""
    def __enter__(self):
        self.stop = threading.Event()
        self.tcp = socket.socket()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.clients = set()
        try:
            self.tcp.bind(("127.0.0.1", 0))
            self.tcp.listen(128)
            self.udp.bind(("127.0.0.1", 0))
            self.tcp.setblocking(False)
            self.udp.setblocking(False)
            self.thread = threading.Thread(target=self.run, name="synthetic-echo")
            self.thread.start()
            return self
        except BaseException:
            self.tcp.close()
            self.udp.close()
            raise

    def run(self):
        while not self.stop.is_set():
            ready, _, _ = select.select([self.tcp, self.udp, *self.clients], [], [], 0.05)
            for sock in ready:
                try:
                    if sock is self.tcp:
                        client, _ = sock.accept()
                        client.settimeout(0.2)
                        if len(self.clients) >= 128:
                            client.close()
                        else:
                            self.clients.add(client)
                    elif sock is self.udp:
                        data, address = sock.recvfrom(65535)
                        sock.sendto(data, address)
                    else:
                        data = sock.recv(65535)
                        if not data:
                            self.clients.remove(sock)
                            sock.close()
                        else:
                            sock.sendall(data)
                except OSError:
                    if sock in self.clients:
                        self.clients.remove(sock)
                        sock.close()
        for client in self.clients:
            client.close()
        self.clients.clear()

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(30)
        self.tcp.close()
        self.udp.close()
        if self.thread.is_alive():
            raise LoadError("echo_shutdown_timeout")


class Session:
    def __init__(self, proxy, credentials, protocol, target, timeout):
        self.control = None
        self.udp = None
        self.protocol = protocol
        self.target = target
        try:
            self.control = socket.create_connection(proxy, timeout=timeout)
            authenticate(self.control, *credentials)
            if protocol == "tcp":
                request(self.control, 1, target)
            else:
                self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.udp.bind(("127.0.0.1", 0))
                self.udp.settimeout(timeout)
                self.relay = request(self.control, 3, self.udp.getsockname())
                loopback(self.relay[0])
                if not self.relay[1]:
                    raise LoadError("invalid_udp_relay")
                self.udp.connect(self.relay)
        except BaseException:
            self.close()
            raise

    def exchange(self, payload):
        if self.protocol == "tcp":
            self.control.sendall(payload)
            response = exact(self.control, len(payload))
        else:
            self.udp.send(b"\x00\x00\x00" + endpoint(self.target) + payload)
            packet = self.udp.recv(65535)
            if packet[:10] != b"\x00\x00\x00" + endpoint(self.target):
                raise LoadError("udp_endpoint_or_frame_mismatch")
            response = packet[10:]
        if response != payload:
            raise LoadError("payload_mismatch")

    def close(self):
        for sock in (self.udp, self.control):
            if sock is not None:
                sock.close()


def summary(samples, elapsed):
    completed = [s for s in samples if s["error"] is None]
    latencies = sorted(s["latency_ms"] for s in completed)
    def percentile(p):
        return latencies[max(0, math.ceil(len(latencies) * p) - 1)] if latencies else None
    byte_count = sum(s["bytes"] for s in completed)
    return {"offered": len(samples), "completed": len(completed),
            "errors": len(samples) - len(completed), "verified_roundtrip_bytes": byte_count,
            "elapsed_seconds": elapsed, "throughput_bytes_per_second": byte_count / elapsed,
            "latency_ms": {"p50": percentile(.50), "p95": percentile(.95), "p99": percentile(.99)}}


def run_phase(args, credentials, echo, phase, concurrency):
    started = time.monotonic()
    started_at = time.time()
    deadline = started + args.duration
    samples = []
    lock = threading.Lock()
    offered = 0
    barrier = threading.Barrier(concurrency)
    def worker(worker_id):
        nonlocal offered
        session = None
        try:
            barrier.wait(timeout=5)
            while time.monotonic() < deadline:
                with lock:
                    if offered >= args.max_operations:
                        break
                    operation = offered
                    offered += 1
                protocol = args.protocol if args.protocol != "both" else ("tcp" if worker_id % 2 == 0 else "udp")
                target = echo.tcp.getsockname() if protocol == "tcp" else echo.udp.getsockname()
                begin = time.monotonic()
                error = None
                try:
                    if session is None:
                        session = Session((args.proxy_host, args.proxy_port), credentials, protocol, target, args.timeout)
                    if args.mode == "idle":
                        time.sleep(min(args.idle_seconds, max(0, deadline - time.monotonic())))
                    payload = secrets.token_bytes(args.payload_bytes)
                    session.exchange(payload)
                except LoadError as exc:
                    error = str(exc)
                except (OSError, ValueError):
                    error = "transport_failure"
                finally:
                    if session is not None and (error or args.mode == "reconnect"):
                        session.close()
                        session = None
                sample = {"operation": operation, "worker": worker_id, "protocol": protocol,
                          "offset_seconds": begin - started, "latency_ms": (time.monotonic() - begin) * 1000,
                          "bytes": args.payload_bytes * 2 if error is None else 0, "error": error}
                with lock:
                    samples.append(sample)
        finally:
            if session is not None:
                session.close()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(worker, i) for i in range(concurrency)]
        for future in futures:
            future.result()
    elapsed = time.monotonic() - started
    return {"phase": phase, "started_at_unix": started_at,
            "concurrency": concurrency, "summary": summary(samples, elapsed),
            "operation_cap_reached": offered == args.max_operations,
            "samples": sorted(samples, key=lambda s: s["operation"])}


def run(args, credentials):
    phases = []
    with Echo() as echo:
        for phase in ("warmup", "steady", "burst", "recovery"):
            count = args.concurrency * (args.burst_multiplier if phase == "burst" else 1)
            phases.append(run_phase(args, credentials, echo, phase, count))
    valid = all(p["summary"]["offered"] > 0 and p["summary"]["errors"] == 0 for p in phases)
    if args.protocol == "both":
        valid = valid and all({s["protocol"] for s in p["samples"]} == {"tcp", "udp"} for p in phases)
    return {"schema_version": 1, "status": "load_component_pass" if valid else "load_failed",
            "benchmark_complete": False, "missing_evidence": MISSING_EVIDENCE,
            "parameters": {k: v for k, v in vars(args).items() if k != "output"},
            "byte_semantics": "verified application payload sent plus echoed; no protocol overhead",
            "phases": phases}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--proxy-host", type=loopback, required=True)
    p.add_argument("--proxy-port", type=int, required=True)
    p.add_argument("--protocol", choices=("tcp", "udp", "both"), default="both")
    p.add_argument("--mode", choices=("idle", "reconnect", "transfer"), default="transfer")
    p.add_argument("--duration", type=float, default=10, help="seconds per phase")
    p.add_argument("--timeout", type=float, default=1)
    p.add_argument("--idle-seconds", type=float, default=1)
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--burst-multiplier", type=int, default=2)
    p.add_argument("--payload-bytes", type=int, default=1024)
    p.add_argument("--max-operations", type=int, default=10000, help="per-phase bound")
    p.add_argument("--output", required=True)
    return p


def validate(args):
    if not (1 <= args.proxy_port <= 65535 and 1 <= args.concurrency <= 32
            and 1 <= args.burst_multiplier <= 4 and args.concurrency * args.burst_multiplier <= 64
            and 1 <= args.payload_bytes <= 60000 and 1 <= args.max_operations <= 25000
            and .01 <= args.duration <= 300 and .01 <= args.timeout <= 5
            and .001 <= args.idle_seconds <= 10):
        raise ValueError("load parameters out of bounds")
    if args.protocol == "both" and (args.concurrency < 2 or args.max_operations < args.concurrency):
        raise ValueError("both protocols require at least two workers and one operation per worker")


def main():
    args = parser().parse_args()
    try:
        validate(args)
        # Bounded input; never echo credentials or include parser exceptions in reports.
        data = sys.stdin.buffer.readline(2049)
        if len(data) > 2048:
            raise ValueError("credential input too large")
        credentials = json.loads(data)
        username, password = credentials["username"].encode(), credentials["password"].encode()
        if not (1 <= len(username) <= 255 and 1 <= len(password) <= 255):
            raise ValueError("credential length")
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            report = run(args, (username, password))
            json.dump(report, output, indent=2, allow_nan=False)
            output.write("\n")
        return 0 if report["status"] == "load_component_pass" else 1
    except (ValueError, KeyError, TypeError, AttributeError, OSError, LoadError):
        print("load validation or execution failed (details withheld)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
