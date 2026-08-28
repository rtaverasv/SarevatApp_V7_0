"""Borradores seguros y comparación textual de configuraciones."""

from __future__ import annotations

import difflib
import json
import os
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from sarevat.models import CommandPlan
from sarevat.security import redact_command, redact_text

DRAFT_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class PlanDraft:
    """Vista reutilizable de un plan que excluye secretos por diseño."""

    id: str
    name: str
    service: str
    commands: tuple[str, ...]
    warnings: tuple[str, ...]
    created_at: str

    @classmethod
    def from_plan(cls, plan: CommandPlan) -> PlanDraft:
        return cls(
            id=uuid.uuid4().hex,
            name=plan.name,
            service=plan.service,
            commands=tuple(redact_command(command) for command in plan.commands),
            warnings=plan.warnings,
            created_at=datetime.now(UTC).isoformat(),
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> PlanDraft:
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            service=str(data["service"]),
            commands=tuple(str(item) for item in data.get("commands", [])),
            warnings=tuple(str(item) for item in data.get("warnings", [])),
            created_at=str(data["created_at"]),
        )


class DraftStore:
    """Persistencia local atómica de vistas de planes, limitada a 100 elementos."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def list_drafts(self) -> list[PlanDraft]:
        if not self.path.exists():
            return []
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("No se pudieron leer los borradores locales.") from exc
        if payload.get("schema_version") != DRAFT_SCHEMA_VERSION:
            raise ValueError("La versión de los borradores no es compatible.")
        return [PlanDraft.from_dict(item) for item in payload.get("drafts", [])]

    def add_plan(self, plan: CommandPlan) -> PlanDraft:
        draft = PlanDraft.from_plan(plan)
        drafts = [*self.list_drafts(), draft][-100:]
        self._save(drafts)
        return draft

    def remove(self, draft_id: str) -> bool:
        drafts = self.list_drafts()
        remaining = [draft for draft in drafts if draft.id != draft_id]
        if len(remaining) == len(drafts):
            return False
        self._save(remaining)
        return True

    def _save(self, drafts: list[PlanDraft]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema_version": DRAFT_SCHEMA_VERSION, "drafts": [draft.to_dict() for draft in drafts]}
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(temporary, self.path)


def configuration_diff(before: str, after: str) -> str:
    """Devuelve un diff unificado y redactado entre dos configuraciones."""
    return "\n".join(
        difflib.unified_diff(
            redact_text(before).splitlines(),
            redact_text(after).splitlines(),
            fromfile="configuración actual",
            tofile="configuración propuesta",
            lineterm="",
        )
    )
