"""Descubrimiento IPv4 controlado por ICMP y TCP."""

from __future__ import annotations

import concurrent.futures
import csv
import errno
import ipaddress
import json
import platform
import re
import socket
import subprocess  # nosec B404
import threading
import time
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path

from sarevat.validators import ValidationError, validate_ipv4, validate_ipv4_network

DEFAULT_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    161: "SNMP-TCP",
    443: "HTTPS",
    830: "NETCONF",
    3389: "RDP",
}


class PortState(StrEnum):
    OPEN = "open"
    REFUSED = "refused"
    TIMEOUT = "timeout"
    UNREACHABLE = "unreachable"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class HostResult:
    ip: str
    alive: bool
    hostname: str | None = None
    mac: str | None = None


@dataclass(frozen=True, slots=True)
class PortResult:
    ip: str
    port: int
    service: str
    state: PortState
    latency_ms: float | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ScanPolicy:
    max_hosts: int = 1024
    max_workers: int = 64
    timeout_seconds: float = 0.7
    rate_limit_per_second: int = 200

    def __post_init__(self) -> None:
        if not 1 <= self.max_hosts <= 65_536:
            raise ValidationError("max_hosts fuera de rango seguro.")
        if not 1 <= self.max_workers <= 128:
            raise ValidationError("max_workers fuera de rango seguro.")
        if not 0.1 <= self.timeout_seconds <= 30:
            raise ValidationError("Timeout fuera de rango seguro.")


class _RateLimiter:
    def __init__(self, rate: int) -> None:
        self.interval = 1 / max(1, rate)
        self.lock = threading.Lock()
        self.next_slot = 0.0

    def wait(self) -> None:
        with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next_slot - now)
            self.next_slot = max(now, self.next_slot) + self.interval
        if delay:
            time.sleep(delay)


def _ping_once(ip: str, timeout_seconds: float) -> bool:
    timeout_ms = max(100, int(timeout_seconds * 1000))
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, round(timeout_seconds))), ip]
    try:
        result = subprocess.run(  # nosec B603
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds + 1.5,
            check=False,
            shell=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None


def _arp_mac(ip: str) -> str | None:
    try:
        result = subprocess.run(  # nosec B603 B607
            ["arp", "-a", ip],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", result.stdout, re.I)
    return match.group(0).replace("-", ":").lower() if match else None


def ping_sweep(
    network: str | ipaddress.IPv4Network,
    *,
    policy: ScanPolicy | None = None,
    resolve_dns: bool = False,
    resolve_mac: bool = False,
) -> list[HostResult]:
    policy = policy or ScanPolicy()
    item = validate_ipv4_network(network) if isinstance(network, str) else network
    host_count = item.num_addresses if item.prefixlen >= 31 else item.num_addresses - 2
    if host_count > policy.max_hosts:
        raise ValidationError(f"{item} contiene {host_count} hosts; limite: {policy.max_hosts}.")
    hosts = list(item.hosts())
    limiter = _RateLimiter(policy.rate_limit_per_second)

    def scan(address: ipaddress.IPv4Address) -> HostResult:
        limiter.wait()
        ip = str(address)
        alive = _ping_once(ip, policy.timeout_seconds)
        return HostResult(
            ip=ip,
            alive=alive,
            hostname=_reverse_dns(ip) if alive and resolve_dns else None,
            mac=_arp_mac(ip) if alive and resolve_mac else None,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=policy.max_workers) as executor:
        results = list(executor.map(scan, hosts))
    return sorted(results, key=lambda result: ipaddress.ip_address(result.ip))


def scan_tcp_port(ip: str, port: int, *, timeout: float = 0.7, service: str = "unknown") -> PortResult:
    address = str(validate_ipv4(ip))
    if not 1 <= port <= 65_535:
        raise ValidationError("Puerto TCP fuera de rango.")
    started = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((address, port))
    except TimeoutError:
        return PortResult(address, port, service, PortState.TIMEOUT, detail="timeout")
    except OSError as exc:
        return PortResult(address, port, service, PortState.ERROR, detail=str(exc))
    finally:
        sock.close()
    latency = round((time.perf_counter() - started) * 1000, 2)
    if result == 0:
        state = PortState.OPEN
    elif result in {errno.ECONNREFUSED, 10061}:
        state = PortState.REFUSED
    elif result in {errno.ETIMEDOUT, 10035, 10060}:
        state = PortState.TIMEOUT
    elif result in {errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065}:
        state = PortState.UNREACHABLE
    else:
        state = PortState.ERROR
    return PortResult(address, port, service, state, latency, detail=str(result))


def scan_tcp_ports(
    ip: str,
    ports: dict[int, str] | None = None,
    *,
    policy: ScanPolicy | None = None,
) -> list[PortResult]:
    policy = policy or ScanPolicy()
    address = str(validate_ipv4(ip))
    targets = ports or DEFAULT_PORTS
    if len(targets) > 1024:
        raise ValidationError("Demasiados puertos para una sola operacion.")
    limiter = _RateLimiter(policy.rate_limit_per_second)

    def scan(item: tuple[int, str]) -> PortResult:
        limiter.wait()
        return scan_tcp_port(address, item[0], timeout=policy.timeout_seconds, service=item[1])

    workers = min(policy.max_workers, max(1, len(targets)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(scan, targets.items()))
    return sorted(results, key=lambda result: result.port)


def export_scan_json(results: list[HostResult] | list[PortResult], path: Path) -> Path:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps([asdict(item) for item in results], indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return path


def export_scan_csv(results: list[HostResult] | list[PortResult], path: Path) -> Path:
    if not results:
        raise ValidationError("No hay resultados para exportar.")
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [asdict(item) for item in results]
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return path
