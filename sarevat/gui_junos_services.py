"""Pantallas Tkinter para candidatos de servicios Junos.

La logica de construccion y validacion permanece en :mod:`sarevat.juniper.services`.
Este mixin solamente recoge datos de la interfaz y los entrega a la revision comun.
"""

from __future__ import annotations

from sarevat.juniper.services import (
    build_dns_candidate,
    build_ntp_candidate,
    build_snmpv3_candidate,
    build_ssh_hardening_candidate,
    build_syslog_candidate,
)
from sarevat.models import NetworkPlatform


class JunosServicePagesMixin:
    """Agrupa formularios de NTP, syslog, DNS, SNMPv3 y SSH para la GUI."""

    def _junos_ntp_candidate_page(self) -> None:
        if not self.session or self.session.platform is not NetworkPlatform.JUNIPER_JUNOS:
            return
        session = self.session
        management_address = str(session.reconnect_params.get("host", "")) if session.reconnect_params else ""
        self._simple_plan_form(
            "Servidor NTP Junos",
            (("Servidor NTP IPv4", "server"),),
            lambda data: build_ntp_candidate(data, session.facts, management_address),
            notice=(
                "El equipo debe poder alcanzar el servidor NTP desde gestion. "
                "La aplicacion usa commit confirmed y verifica la configuracion desde otra sesion SSH."
            ),
        )

    def _junos_syslog_candidate_page(self) -> None:
        if not self.session or self.session.platform is not NetworkPlatform.JUNIPER_JUNOS:
            return
        session = self.session
        management_address = str(session.reconnect_params.get("host", "")) if session.reconnect_params else ""
        self._simple_plan_form(
            "Colector syslog Junos",
            (("Colector syslog IPv4", "server"),),
            lambda data: build_syslog_candidate(data, session.facts, management_address),
            notice=(
                "Se configurara facility any con severidad notice. "
                "El colector debe ser alcanzable desde gestion."
            ),
        )

    def _junos_dns_candidate_page(self) -> None:
        if not self.session or self.session.platform is not NetworkPlatform.JUNIPER_JUNOS:
            return
        session = self.session
        management_address = str(session.reconnect_params.get("host", "")) if session.reconnect_params else ""
        self._simple_plan_form(
            "Resolvedores DNS Junos",
            (("DNS primario IPv4", "primary"), ("DNS secundario IPv4 (opcional)", "secondary")),
            lambda data: build_dns_candidate(data, session.facts, management_address),
            notice=(
                "Los servidores se agregan sin eliminar los existentes. "
                "Verifica su alcance desde gestion."
            ),
        )

    def _junos_snmpv3_candidate_page(self) -> None:
        if not self.session or self.session.platform is not NetworkPlatform.JUNIPER_JUNOS:
            return
        session = self.session
        management_address = str(session.reconnect_params.get("host", "")) if session.reconnect_params else ""
        self._simple_plan_form(
            "SNMPv3 Junos seguro",
            (
                ("Grupo SNMPv3", "group"),
                ("Usuario SNMPv3", "username"),
                ("Clave de autenticacion", "auth_password"),
                ("Clave de privacidad", "privacy_password"),
            ),
            lambda data: build_snmpv3_candidate(data, session.facts, management_address),
            hidden={"auth_password", "privacy_password"},
            notice=(
                "Requiere engine ID SNMP ya configurado; se validara antes de aplicar. "
                "Las claves solo existen durante esta sesion y se redactan en toda evidencia local."
            ),
        )

    def _junos_ssh_hardening_candidate_page(self) -> None:
        if not self.session or self.session.platform is not NetworkPlatform.JUNIPER_JUNOS:
            return
        session = self.session
        management_address = str(session.reconnect_params.get("host", "")) if session.reconnect_params else ""
        self._simple_plan_form(
            "Endurecimiento SSH Junos",
            (
                ("Limite de sesiones (1-250)", "connection_limit"),
                ("Intentos por minuto (1-250)", "rate_limit"),
            ),
            lambda data: build_ssh_hardening_candidate(data, session.facts, management_address),
            notice=(
                "Solo fija SSHv2 y limites; no modifica puerto ni autenticacion. "
                "Usa valores que no bloqueen a los operadores autorizados."
            ),
        )
