"""Pantalla de candidato de gestion Junos para la interfaz grafica."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from sarevat.juniper.services import build_management_candidate, preferred_management_interface
from sarevat.models import NetworkPlatform
from sarevat.validators import ValidationError


class JunosManagementPageMixin:
    """Aisla el formulario de hostname e IPv4 de gestion de la ventana principal."""

    def _junos_management_candidate_page(self) -> None:
        if not self.session or self.session.platform is not NetworkPlatform.JUNIPER_JUNOS:
            return
        session = self.session
        self._clear()
        self._page_header(
            "Candidato de gestión Junos",
            "Se valida y muestra un candidato. La aplicación remota aún permanece bloqueada.",
        )
        form = ttk.Frame(self.content, style="Card.TFrame", padding=(22, 20))
        form.pack(fill="x")
        initial_hostname = session.facts.hostname if session.facts.hostname != "desconocido" else ""
        hostname = tk.StringVar(value=initial_hostname)
        interface = tk.StringVar(value=preferred_management_interface(session.facts))
        address = tk.StringVar()
        netmask = tk.StringVar(value="255.255.255.0")
        fields = (
            ("Hostname", hostname),
            ("Interfaz descubierta", interface),
            ("IPv4 de gestión", address),
            ("Máscara IPv4", netmask),
        )
        for label, value in fields:
            ttk.Label(
                form, text=label, background="#ffffff", foreground="#526777", font=("Segoe UI", 10)
            ).pack(anchor="w")
            if value is interface:
                ttk.Combobox(
                    form, textvariable=value, values=tuple(session.facts.interfaces), state="readonly"
                ).pack(fill="x", pady=(2, 8))
            else:
                ttk.Entry(form, textvariable=value).pack(fill="x", pady=(2, 8))
        ttk.Label(
            form,
            text=(
                "El candidato no será enviado ni guardado. La futura ejecución requerirá una "
                "prueba autorizada con commit confirmed."
            ),
            background="#ffffff",
            foreground="#526777",
            wraplength=680,
        ).pack(anchor="w", pady=(4, 8))

        def prepare() -> None:
            try:
                self._review_and_execute_plan(
                    build_management_candidate(
                        {
                            "hostname": hostname.get(),
                            "interface": interface.get(),
                            "address": address.get(),
                            "netmask": netmask.get(),
                        },
                        session.facts,
                    )
                )
            except ValidationError as exc:
                messagebox.showwarning("Datos por corregir", str(exc), parent=self)

        ttk.Button(
            form, text="Validar y preparar candidato", style="Primary.TButton", command=prepare
        ).pack(fill="x", pady=(8, 0))
