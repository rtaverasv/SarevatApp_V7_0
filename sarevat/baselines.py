"""Referencias locales redactadas para detectar cambios de configuración."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from sarevat.drafts import configuration_diff
from sarevat.security import redact_text

BASELINE_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class ConfigurationBaseline:
    """Copia local redactada; no es una copia de recuperación del equipo."""

    hostname: str
    captured_at: str
    running_config: str

    @classmethod
    def from_config(cls, hostname: str, running_config: str) -> ConfigurationBaseline:
        if not running_config.strip():
            raise ValueError("No hay configuración disponible para guardar como referencia.")
        return cls(
            hostname=hostname.strip() or "equipo-desconocido",
            captured_at=datetime.now(UTC).isoformat(),
            running_config=redact_text(running_config),
        )

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ConfigurationBaseline:
        return cls(
            hostname=str(data["hostname"]),
            captured_at=str(data["captured_at"]),
            running_config=str(data["running_config"]),
        )


class BaselineStore:
    """Almacena una única referencia local mediante reemplazo atómico."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> ConfigurationBaseline:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("No se pudo leer la referencia local.") from exc
        if payload.get("schema_version") != BASELINE_SCHEMA_VERSION:
            raise ValueError("La versión de la referencia local no es compatible.")
        baseline = payload.get("baseline")
        if not isinstance(baseline, dict):
            raise ValueError("La referencia local está incompleta.")
        return ConfigurationBaseline.from_dict(baseline)

    def save(self, baseline: ConfigurationBaseline) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema_version": BASELINE_SCHEMA_VERSION, "baseline": baseline.to_dict()}
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(temporary, self.path)


def compare_with_baseline(baseline: ConfigurationBaseline, running_config: str) -> str:
    """Devuelve un diff redactado, sin inferir que toda diferencia sea un fallo."""
    return configuration_diff(baseline.running_config, redact_text(running_config))
