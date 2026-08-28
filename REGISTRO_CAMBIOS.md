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

### 2026-08-27 20:13:10 -04:00 — Fase 3: inventario, perfiles y borradores seguros

- **Cambio:** se añadió un inventario JSON con esquema versionado, perfiles SSH
  y serial sin secretos, actualización de modelo/versión/serial tras el
  descubrimiento y un menú sencillo para crear, consultar, conectar y eliminar
  perfiles. Se añadieron borradores redactados de planes y una utilidad para
  comparar configuraciones sin exponer secretos. Se actualizaron las pruebas y
  la guía de uso.
- **Motivo:** reducir la repetición de datos de conexión sin almacenar
  contraseñas ni hacer más complejo el flujo habitual de la aplicación.
- **Archivos afectados:** `sarevat/inventory.py`, `sarevat/drafts.py`,
  `sarevat/cli.py`, `tests/test_inventory.py`, `tests/test_drafts.py`,
  `tests/test_cli_round2.py`, `README.md` y `REGISTRO_CAMBIOS.md`.
- **Verificación:** `125 passed`; cobertura total de 1,655 líneas ejecutables y
  92% de ramas. Ruff, Bandit, `pip check` y `git diff --check` finalizaron sin
  errores. No se realizaron conexiones a equipos Cisco reales.

### 2026-08-27 16:12:59 -04:00 — Entorno de validación y ajuste de rollback

- **Cambio:** se creó el entorno virtual local `.venv` con Python 3.12 y se
  instalaron las dependencias de desarrollo. Se ajustó el mensaje posterior a
  un rollback para conservar la causa del fallo controlado junto con la
  confirmación de restauración.
- **Motivo:** habilitar las comprobaciones completas del proyecto y mostrar al
  operador por qué se revirtió un plan, sin perder el mensaje de recuperación.
- **Archivos afectados:** `.venv/` (ignorado por Git),
  `sarevat/cisco/executor.py` y `REGISTRO_CAMBIOS.md`.
- **Verificación:** `119 passed`; cobertura de 1,341 líneas ejecutables y 99%
  de ramas. Ruff, Bandit, `pip check` y `git diff --check` finalizaron sin
  errores. No se realizaron conexiones a equipos Cisco reales.

### 2026-08-27 16:06:51 -04:00 — Fase 2: protocolo de laboratorio y matriz

- **Cambio:** se añadió el protocolo de piloto controlado y una matriz inicial
  de compatibilidad por plataforma, modelo, versión, licencia, servicios y
  recuperación.
- **Motivo:** separar de forma visible las pruebas locales de la certificación
  de Cisco IOS/IOS-XE y evitar prometer compatibilidad sin evidencia.
- **Archivos afectados:** `LABORATORIO_COMPATIBILIDAD.md` y
  `REGISTRO_CAMBIOS.md`.
- **Verificación:** se revisó que el protocolo conserve dry-run, checkpoint,
  postcheck y rollback, y que la matriz inicie todas las plataformas como “No
  certificado”. No se ejecutaron pruebas de laboratorio: no hay CML, EVE-NG,
  GNS3 ni equipo Cisco autorizado disponible en este checkout.

### 2026-08-27 16:06:21 -04:00 — Fase 1: validación reproducible y CI

- **Cambio:** se declaró el backend de empaquetado, se añadió el flujo de GitHub
  Actions para pruebas, estilo, seguridad y dependencias en Python 3.11 y 3.12,
  y se incorporó el script local `scripts/validar_calidad.ps1`. Se añadieron
  postchecks semánticos para configuraciones iniciales, rutas estáticas, DHCP
  relay y cifrado de contraseñas, junto con una prueba de rollback cuando no
  hay evidencia observada. También se actualizó la guía de instalación con
  rutas relativas y el comando `sarevat`.
- **Motivo:** hacer repetible la verificación de calidad sin añadir opciones ni
  complejidad al menú que usa el operador.
- **Archivos afectados:** `pyproject.toml`, `.github/workflows/calidad.yml`,
  `scripts/validar_calidad.ps1`, `README.md`, `sarevat/models.py`,
  `sarevat/cisco/executor.py`, `sarevat/cisco/services.py`,
  `tests/test_executor.py`, `tests/test_executor_edges.py` y
  `REGISTRO_CAMBIOS.md`.
- **Verificación:** se revisó que el workflow instale dependencias, el paquete y
  ejecute pytest, Ruff, Bandit y `pip check`; `compileall`, el análisis de
  sintaxis de PowerShell, la lectura TOML y `git diff --check` finalizaron sin
  errores. La ejecución local completa no fue posible porque falta `.venv` y
  el intérprete de respaldo no incluye las herramientas de desarrollo; `pip
  check` del intérprete de respaldo pasó.

### 2026-08-27 15:58:00 -04:00 — Fase 0: línea base verificable de V7.0

- **Cambio:** se añadió `LINEA_BASE_V7_0.md` con la identidad Git congelada,
  alcance, inventario funcional y procedimiento de comparación previo a toda
  integración externa.
- **Motivo:** evitar que una copia distinta introduzca regresiones sin una
  referencia objetiva y conservar el alcance Cisco IOS/IOS-XE exclusivamente
  IPv4.
- **Archivos afectados:** `LINEA_BASE_V7_0.md` y `REGISTRO_CAMBIOS.md`.
- **Verificación:** se confirmó el commit `94baaeae78c93cbd0f3c6e17e7972cdd4e32923a`,
  el árbol Git `d70a4a2686c37e6c20faf634905edb739bdacf36`, 12 archivos de
  pruebas y 25 archivos Python. Las comprobaciones de pytest, Ruff y Bandit
  no se ejecutaron: no existe `.venv` en este checkout y el intérprete de
  respaldo no incluye esas herramientas. `pip check` finalizó correctamente.

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
