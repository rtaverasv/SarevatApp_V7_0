"""Preparación segura de lotes; no conecta ni aplica cambios por sí sola."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, time
from pathlib import Path

from sarevat.inventory import ConnectionProfile


@dataclass(frozen=True, slots=True)
class BatchPreview:
    group: str
    profiles: tuple[ConnectionProfile, ...]
    max_concurrent: int
    gradual_size: int
    pause_on_failure: bool = True

    def __post_init__(self) -> None:
        if not self.profiles:
            raise ValueError("El grupo no tiene equipos para preparar un lote.")
        if not 1 <= self.max_concurrent <= len(self.profiles):
            raise ValueError("La concurrencia debe estar entre 1 y la cantidad de equipos.")
        if not 1 <= self.gradual_size <= len(self.profiles):
            raise ValueError("El despliegue inicial debe incluir al menos un equipo válido.")

    @property
    def first_stage(self) -> tuple[ConnectionProfile, ...]:
        return self.profiles[: self.gradual_size]

    @property
    def remaining(self) -> tuple[ConnectionProfile, ...]:
        return self.profiles[self.gradual_size :]


@dataclass(frozen=True, slots=True)
class MaintenanceWindow:
    start: time
    end: time

    def allows(self, current: time) -> bool:
        if self.start <= self.end:
            return self.start <= current <= self.end
        return current >= self.start or current <= self.end


@dataclass(frozen=True, slots=True)
class BatchItemResult:
    profile: ConnectionProfile
    success: bool
    message: str


@dataclass(frozen=True, slots=True)
class BatchRun:
    results: tuple[BatchItemResult, ...]
    paused: bool

    @property
    def pending(self) -> tuple[str, ...]:
        return tuple(item.profile.name for item in self.results if item.message == "pendiente")


class BatchHistoryStore:
    """Historial local redactado de resultados por grupo."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def add(self, group: str, run: BatchRun) -> None:
        records = self.list()
        records.append(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "group": group,
                "paused": run.paused,
                "results": [
                    {"profile": item.profile.name, "success": item.success, "message": item.message}
                    for item in run.results
                ],
            }
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        content = json.dumps(records[-100:], indent=2, ensure_ascii=False) + "\n"
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, self.path)

    def list(self, group: str | None = None) -> list[dict[str, object]]:
        if not self.path.exists():
            return []
        try:
            records = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("No se pudo leer el historial de lotes.") from exc
        if not group:
            return records
        return [item for item in records if str(item.get("group", "")).casefold() == group.casefold()]


def run_gradual_batch(
    preview: BatchPreview,
    execute_one: Callable[[ConnectionProfile], BatchItemResult],
    *,
    window: MaintenanceWindow | None = None,
    current_time: time | None = None,
) -> BatchRun:
    """Ejecuta prueba inicial y detiene las etapas restantes ante un fallo."""
    if window and current_time and not window.allows(current_time):
        pending = tuple(BatchItemResult(item, False, "pendiente") for item in preview.profiles)
        return BatchRun(pending, True)
    results: list[BatchItemResult] = []
    for profile in preview.first_stage:
        result = execute_one(profile)
        results.append(result)
        if preview.pause_on_failure and not result.success:
            results.extend(
                BatchItemResult(item, False, "pendiente") for item in preview.profiles[len(results) :]
            )
            return BatchRun(tuple(results), True)
    remaining = list(preview.remaining)
    while remaining:
        stage, remaining = remaining[: preview.max_concurrent], remaining[preview.max_concurrent :]
        with ThreadPoolExecutor(max_workers=preview.max_concurrent) as pool:
            stage_results = list(pool.map(execute_one, stage))
        results.extend(stage_results)
        if preview.pause_on_failure and any(not item.success for item in stage_results):
            results.extend(BatchItemResult(item, False, "pendiente") for item in remaining)
            return BatchRun(tuple(results), True)
    return BatchRun(tuple(results), False)
