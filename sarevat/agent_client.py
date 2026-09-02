"""Cliente local que conecta Sarevat 7.0 con la GUI web mediante HTTPS."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from sarevat.agent_runtime import AgentJobError, execute_agent_job
from sarevat.security import redact_text

ENDPOINT = os.environ.get("SAREVAT_ENDPOINT", "").rstrip("/")
AGENT_ID = os.environ.get("SAREVAT_AGENT_ID", "")
TOKEN = os.environ.get("SAREVAT_ENROLLMENT_TOKEN", "")
POLL_SECONDS = max(3, int(os.environ.get("SAREVAT_POLL_SECONDS", "8")))
RUNTIME = Path(os.environ.get("SAREVAT_RUNTIME", "./sarevat-runtime"))


def _request(path: str, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(f"{ENDPOINT}{path}", data=data, method=method)
    request.add_header("Authorization", f"Bearer {TOKEN}")
    request.add_header("X-Sarevat-Agent", AGENT_ID)
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=25) as response:  # nosec B310
        return json.loads(response.read().decode())


def _secret_name(reference: str) -> str:
    normalized = "".join(char if char.isalnum() else "_" for char in reference.upper())
    return f"SAREVAT_SECRET_{normalized}"


def _credentials(payload: dict[str, Any]) -> dict[str, str]:
    reference = str(payload.get("vaultReference", ""))
    password = os.environ.get(_secret_name(reference), "")
    if not password:
        raise AgentJobError(f"No existe el secreto local {_secret_name(reference)}")
    return {
        "username": str(payload.get("username", "")),
        "password": password,
        "secret": os.environ.get(f"{_secret_name(reference)}_ENABLE", ""),
    }


def _runtime_job(job: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    payload = dict(job.get("payload", {}))
    connection = payload.get("connection") or {
        "transport": "ssh",
        "host": payload.get("managementIp", ""),
        "port": payload.get("sshPort", 22),
    }
    kind = str(job.get("kind", ""))
    if kind == "snapshot":
        kind = "discover"
    return ({**payload, "kind": kind, "connection": connection}, _credentials(payload))


def process_once() -> None:
    job = _request("/api/agent/jobs").get("job")
    if not job:
        return
    try:
        runtime_job, credentials = _runtime_job(job)
        result = execute_agent_job(runtime_job, credentials, RUNTIME)
        status = "succeeded" if result.get("status") == "succeeded" else "failed"
    except Exception as error:
        status, result = "failed", {"message": redact_text(str(error))[:500]}
    _request(f"/api/agent/jobs/{job['id']}", "POST", {"status": status, "result": result})


def main() -> None:
    if not ENDPOINT or not AGENT_ID or not TOKEN:
        raise SystemExit("Define SAREVAT_ENDPOINT, SAREVAT_AGENT_ID y SAREVAT_ENROLLMENT_TOKEN.")
    if not ENDPOINT.startswith("https://"):
        raise SystemExit("SAREVAT_ENDPOINT debe usar HTTPS.")
    while True:
        try:
            process_once()
        except (urllib.error.URLError, TimeoutError, ValueError) as error:
            print(f"Sarevat agent: {redact_text(str(error))}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
