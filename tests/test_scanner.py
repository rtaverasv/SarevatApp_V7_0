from __future__ import annotations

import socket

import pytest

from sarevat.scanner import PortState, ScanPolicy, ping_sweep, scan_tcp_port, scan_tcp_ports
from sarevat.validators import ValidationError


class FakeSocket:
    result = 0

    def settimeout(self, _: float) -> None:
        pass

    def connect_ex(self, _: tuple[str, int]) -> int:
        return self.result

    def close(self) -> None:
        pass


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (0, PortState.OPEN),
        (10061, PortState.REFUSED),
        (10035, PortState.TIMEOUT),
        (10060, PortState.TIMEOUT),
        (10065, PortState.UNREACHABLE),
    ],
)
def test_tcp_states(monkeypatch: pytest.MonkeyPatch, code: int, expected: PortState) -> None:
    FakeSocket.result = code
    monkeypatch.setattr(socket, "socket", lambda *_: FakeSocket())
    assert scan_tcp_port("192.0.2.1", 22).state is expected


def test_parallel_port_scan_is_sorted(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeSocket.result = 0
    monkeypatch.setattr(socket, "socket", lambda *_: FakeSocket())
    results = scan_tcp_ports(
        "192.0.2.1",
        {443: "HTTPS", 22: "SSH"},
        policy=ScanPolicy(max_workers=2, rate_limit_per_second=1000),
    )
    assert [item.port for item in results] == [22, 443]


def test_ping_sweep_is_mocked_and_ipv4_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sarevat.scanner._ping_once", lambda *_: True)
    results = ping_sweep(
        "192.0.2.0/30",
        policy=ScanPolicy(max_hosts=2, max_workers=2, rate_limit_per_second=1000),
    )
    assert [item.ip for item in results] == ["192.0.2.1", "192.0.2.2"]
    assert all(item.alive for item in results)
    with pytest.raises(ValidationError):
        ping_sweep("2001:db8::/126")
    with pytest.raises(ValidationError):
        ping_sweep("10.0.0.0/8", policy=ScanPolicy(max_hosts=1024))
