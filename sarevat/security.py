"""Deteccion de errores IOS, comandos de riesgo y redaccion de secretos."""

from __future__ import annotations

import re
from collections.abc import Iterable

IOS_ERROR_EXPRESSIONS = (
    r"%\s*Invalid input",
    r"%\s*Incomplete command",
    r"%\s*Ambiguous command",
    r"%\s*Authorization failed",
    r"%\s*Command authorization failed",
    r"%\s*Error",
    r"%\s*Failed",
    r"not supported",
    r"command rejected",
)
IOS_ERROR_PATTERN = "|".join(f"(?:{item})" for item in IOS_ERROR_EXPRESSIONS)
_IOS_ERROR_RE = re.compile(IOS_ERROR_PATTERN, re.IGNORECASE)

_SENSITIVE_LINE_PATTERNS = (
    re.compile(r"(?i)(\busername\s+\S+?[^\r\n\"]*?\s(?:secret|password)\s+)(?:\d+\s+)?[^\s\"\\]+"),
    re.compile(r"(?i)(\benable\s+(?:secret|password)\s+)(?:\d+\s+)?[^\s\"\\]+"),
    re.compile(r"(?i)(\bsnmp-server\s+community\s+)[^\s\"\\]+"),
    re.compile(r"(?i)(\b(?:key-string|pre-shared-key|community-string)\s+)[^\s\"\\]+"),
    re.compile(r"(?im)^(\s*password\s+)(?:\d+\s+)?\S+"),
)

_DANGEROUS_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^reload(?:\s|$)", re.I), "reinicia el equipo"),
    (re.compile(r"^(?:write\s+erase|erase)(?:\s|$)", re.I), "elimina configuracion"),
    (re.compile(r"^(?:delete|format)(?:\s|$)", re.I), "elimina datos"),
    (re.compile(r"^configure\s+replace(?:\s|$)", re.I), "reemplaza la configuracion"),
    (
        re.compile(r"^copy\s+\S+\s+(?:running-config|startup-config)(?:\s|$)", re.I),
        "sobrescribe configuracion",
    ),
    (re.compile(r"^default\s+interface(?:\s|$)", re.I), "restablece una interfaz"),
    (re.compile(r"^clear(?:\s|$)", re.I), "borra estado operativo"),
    (re.compile(r"^debug\s+all(?:\s|$)", re.I), "puede saturar el equipo"),
    (re.compile(r"^crypto\s+key\s+zeroize(?:\s|$)", re.I), "elimina claves criptograficas"),
    (
        re.compile(r"^no\s+(?:aaa|username|router|vlan|interface)(?:\s|$)", re.I),
        "elimina configuracion critica",
    ),
    (re.compile(r"^shutdown(?:\s|$)", re.I), "deshabilita una interfaz o servicio"),
)


def find_ios_errors(output: str) -> tuple[str, ...]:
    """Devuelve las lineas de IOS que representan errores conocidos."""
    errors: list[str] = []
    for line in output.splitlines():
        if _IOS_ERROR_RE.search(line) and line.strip() not in errors:
            errors.append(line.strip())
    return tuple(errors)


def redact_text(text: str) -> str:
    """Oculta secretos comunes sin destruir el resto del contexto del log."""
    redacted = text
    for pattern in _SENSITIVE_LINE_PATTERNS:
        redacted = pattern.sub(r"\1********", redacted)
    return redacted


def redact_command(command: str) -> str:
    return redact_text(command)


def dangerous_reasons(command: str) -> tuple[str, ...]:
    normalized = command.strip()
    if normalized.lower().startswith("do "):
        normalized = normalized[3:].lstrip()
    return tuple(reason for pattern, reason in _DANGEROUS_RULES if pattern.search(normalized))


def plan_dangerous_reasons(commands: Iterable[str]) -> dict[str, tuple[str, ...]]:
    return {command: reasons for command in commands if (reasons := dangerous_reasons(command))}
