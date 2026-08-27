# Registro de cambios

Este documento conserva una explicación cronológica de las modificaciones hechas
al proyecto. Las entradas más recientes aparecen primero.

## Formato

Cada entrada debe incluir:

- Fecha y hora local con zona horaria.
- Resumen del cambio.
- Motivo.
- Archivos afectados.
- Verificación realizada y resultado.

## Historial

### 2026-08-27 15:21:13 -04:00 — Sincronización de V7.0 y roadmap unificado

- **Cambio:** se sincronizó el árbol ejecutable de SarevatApp 7.0 con la copia
  completa: módulos de `sarevat/`, punto de entrada, README, dependencias,
  configuración de proyecto y 12 archivos de pruebas. Se sustituyó el roadmap
  por una versión unificada que conserva como base el plan más desarrollado de
  comparación, validación y certificación, e incorpora las fases de evolución
  operativa del repositorio.
- **Motivo:** disponer en el branch `Mods` de una línea base completa y de un
  único orden de implementación, sin ampliar el alcance IPv4 hacia IPv6.
- **Archivos afectados:** `SarevatApp_V7_0.py`, `sarevat/`, `tests/`,
  `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`, `README.md`,
  `ROADMAP.md` y `REGISTRO_CAMBIOS.md`.
- **Verificación:** se confirmó la presencia de los 12 archivos de pruebas, la
  configuración de pytest/Ruff y las dependencias de desarrollo. Se ejecutaron
  118 pruebas con cobertura: 1,324/1,324 líneas y 99% de ramas; Ruff y Bandit
  finalizaron sin hallazgos y `pip check` no detectó dependencias rotas.

### 2026-08-27 10:06:43 -04:00 — Creación del registro obligatorio

- **Cambio:** se creó este historial y una instrucción persistente para exigir su
  actualización con cada modificación futura del repositorio.
- **Motivo:** mantener una trazabilidad fechada y comprensible de la evolución del
  proyecto a partir de esta solicitud.
- **Archivos afectados:** `AGENTS.md` y `REGISTRO_CAMBIOS.md`.
- **Verificación:** se confirmó mediante búsqueda de contenido que ambos documentos
  incluyen la fecha, la explicación, los archivos afectados y el resultado de las
  verificaciones como datos obligatorios; también se revisó el formato de espacios.
  No se ejecutaron pruebas de la aplicación porque el cambio solo incorpora
  documentación del proceso.
