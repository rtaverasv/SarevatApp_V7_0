"""Preparación segura de lotes; no conecta ni aplica cambios por sí sola."""

from __future__ import annotations

from dataclasses import dataclass

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
