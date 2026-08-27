from __future__ import annotations

from pathlib import Path

import pytest

from sarevat.scanner import (
    HostResult,
    PortResult,
    PortState,
    ScanPolicy,
    _arp_mac,
    _ping_once,
    _reverse_dns,
    export_scan_csv,
    export_scan_json,
    scan_tcp_port,
    scan_tcp_ports,
)
from sarevat.validators import ValidationError


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_hosts": 0},
        {"max_workers": 0},
        {"timeout_seconds": 0.01},
    ],
)
def test_scan_policy_rejects_unsafe_limits(kwargs: dict[str, float | int]) -> None:
    with pytest.raises(ValidationError):
        ScanPolicy(**kwargs)


def test_ping_platforms_and_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    class Result:
        returncode = 0

    def fake_run(command: list[str], **_: object) -> Result:
        calls.append(command)
        return Result()

    monkeypatch.setattr("sarevat.scanner.subprocess.run", fake_run)
    monkeypatch.setattr("sarevat.scanner.platform.system", lambda: "Linux")
    assert _ping_once("192.0.2.1", 0.5)
    assert calls[0][:3] == ["ping", "-c", "1"]
    monkeypatch.setattr("sarevat.scanner.platform.system", lambda: "Windows")
    assert _ping_once("192.0.2.1", 0.5)
    assert calls[1][:3] == ["ping", "-n", "1"]
    monkeypatch.setattr(
        "sarevat.scanner.subprocess.run", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("missing"))
    )
    assert not _ping_once("192.0.2.1", 0.5)


def test_dns_and_arp_success_and_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sarevat.scanner.socket.gethostbyaddr", lambda _: ("router.lab", [], []))
    assert _reverse_dns("192.0.2.1") == "router.lab"
    monkeypatch.setattr(
        "sarevat.scanner.socket.gethostbyaddr", lambda _: (_ for _ in ()).throw(OSError("dns"))
    )
    assert _reverse_dns("192.0.2.1") is None

    class Result:
        stdout = "  192.0.2.1          aa-bb-cc-dd-ee-ff     dynamic"

    monkeypatch.setattr("sarevat.scanner.subprocess.run", lambda *_args, **_kwargs: Result())
    assert _arp_mac("192.0.2.1") == "aa:bb:cc:dd:ee:ff"
    monkeypatch.setattr(
        "sarevat.scanner.subprocess.run", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("arp"))
    )
    assert _arp_mac("192.0.2.1") is None


def test_tcp_invalid_and_unhandled_socket_error(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        scan_tcp_port("192.0.2.1", 0)

    class BrokenSocket:
        def settimeout(self, _: float) -> None:
            pass

        def connect_ex(self, _: tuple[str, int]) -> int:
            raise OSError("broken")

        def close(self) -> None:
            pass

    monkeypatch.setattr("sarevat.scanner.socket.socket", lambda *_: BrokenSocket())
    assert scan_tcp_port("192.0.2.1", 22).state is PortState.ERROR

    class TimeoutSocket(BrokenSocket):
        def connect_ex(self, _: tuple[str, int]) -> int:
            raise TimeoutError

    monkeypatch.setattr("sarevat.scanner.socket.socket", lambda *_: TimeoutSocket())
    assert scan_tcp_port("192.0.2.1", 22).state is PortState.TIMEOUT

    class UnknownResultSocket(BrokenSocket):
        def connect_ex(self, _: tuple[str, int]) -> int:
            return 99999

    monkeypatch.setattr("sarevat.scanner.socket.socket", lambda *_: UnknownResultSocket())
    assert scan_tcp_port("192.0.2.1", 22).state is PortState.ERROR


def test_too_many_ports_and_export_paths(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        scan_tcp_ports("192.0.2.1", dict.fromkeys(range(1, 1026), "x"))
    host_json = export_scan_json([HostResult("192.0.2.1", True)], tmp_path / "hosts.json")
    port_csv = export_scan_csv([PortResult("192.0.2.1", 22, "SSH", PortState.OPEN)], tmp_path / "ports.csv")
    assert '"alive": true' in host_json.read_text(encoding="utf-8")
    assert "service" in port_csv.read_text(encoding="utf-8-sig")
    with pytest.raises(ValidationError):
        export_scan_csv([], tmp_path / "empty.csv")
