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

### 2026-08-31 22:36:45 -04:00

- Se corrigió la pantalla de conexión de la GUI alpha. Cuando se abría sin haber seleccionado un perfil, el formulario intentaba obtener un puerto serial de un perfil inexistente; la excepción detenía el dibujo de todos los campos y dejaba visible solo el encabezado.
- Se aisló la obtención del objetivo de conexión en `profile_connection_target`, que devuelve vacío sin perfil y selecciona correctamente IPv4 o puerto serial cuando sí existe. Se añadió una prueba para los tres casos, evitando que una pantalla nueva vuelva a depender de un perfil guardado.
- Archivos afectados: `sarevat/gui.py`, `tests/test_gui.py` y `REGISTRO_CAMBIOS.md`.
- Comprobaciones: compilación, Ruff, Bandit y pruebas específicas de GUI aprobadas (`5 passed`). La verificación visual automática no está disponible en este entorno; se requiere reiniciar la ventana ya abierta para cargar el código corregido. No se realizaron conexiones Cisco reales.

### 2026-08-31 21:24:30 -04:00

- Se completó la operación de la GUI alpha sobre equipos conectados sin retirar PowerShell: tras descubrir el equipo muestra las catorce herramientas ya disponibles en la consola, incluyendo servicios, IPv4 por interfaz, consola libre, configuración inicial, guardado, comparación, revisión, NTP/syslog, SNMPv3, AAA, referencias y endurecimiento.
- Los planes de configuración usan el mismo `CiscoExecutor` de la aplicación: vista previa con secretos ocultos, dry-run, respaldo cifrado con frase temporal, checkpoint, postchecks, reporte JSON/CSV y rollback opcional. Los planes peligrosos requieren una confirmación reforzada; AAA exige además `CONSOLA_LISTA` al preparar y `AAA_APLICAR` al aplicar, para proteger el acceso de recuperación.
- Se añadieron controles de sesión para serializar comandos Netmiko, impedir una segunda conexión mientras hay una sesión abierta, cerrar y auditar correctamente la sesión, registrar la consola libre sin secretos y actualizar el inventario cuando se conecta mediante un perfil. La GUI mantiene las credenciales solo durante la conexión actual.
- VLSM puede preparar una configuración por cada interfaz calculada, usando automáticamente la primera IPv4 utilizable, la máscara y el tipo de subred. El escáner incorpora DNS inverso, consulta opcional de la caché ARP y exportaciones con fecha para no sobrescribir resultados. Los perfiles permiten grupos y la preparación de lotes pide los mismos límites de concurrencia y prueba inicial que PowerShell; sigue sin ejecutar lotes, tal como la versión de consola.
- Se actualizó la guía de la GUI para reflejar sus capacidades reales, sus confirmaciones y la condición alpha. PowerShell permanece intacto como alternativa operativa.
- Archivos afectados: `sarevat/gui.py`, `README.md` y `REGISTRO_CAMBIOS.md`.
- Comprobaciones: `162 passed` con cobertura, Ruff, Bandit, `pip check` y `git diff --check` aprobados mediante `scripts/validar_calidad.ps1`. No se realizaron conexiones a equipos Cisco reales; la certificación por modelo, IOS/IOS-XE y cableado serial sigue pendiente de laboratorio o hardware autorizado.

### 2026-08-31 20:13:17 -04:00

- Se añadió la interfaz gráfica opcional `SarevatApp_GUI_alpha.py` y el módulo `sarevat/gui.py`, sin cambiar el punto de entrada de PowerShell. La alpha conserva el orden del menú principal y ofrece conexión y descubrimiento en modo lectura, VLSM IPv4, escaneo autorizado e inventario de perfiles.
- La conexión SSH valida IPv4 y solicita credenciales temporales. La conexión serial muestra puerto y baudrate; puede solicitar usuario, password y enable secret solo si la consola lo requiere. Ningún secreto se almacena en perfiles ni archivos de la aplicación.
- Se ajustó la navegación y los formularios de la alpha: SSH y consola serial actualizan sus campos al cambiar de método; VLSM presenta primero Red Base, Excluir IP y la decisión de trabajar con subredes; el escaneo se prepara antes de pedir una segunda confirmación para iniciar; e Inventario muestra sus ocho opciones antes de abrir el detalle correspondiente.
- Se corrigió la pantalla de conexión de la alpha: su contenedor usaba dos mecanismos de distribución incompatibles, lo que podía dejar los campos sin mostrarse. Ahora utiliza una distribución única y vuelve a presentar los campos SSH o serial según la selección.
- Las configuraciones de IOS se mantienen exclusivamente en PowerShell durante la alpha. Se documentó el comando de inicio y ese límite en `README.md`.
- Archivos afectados: `SarevatApp_GUI_alpha.py`, `sarevat/gui.py`, `tests/test_gui.py`, `pyproject.toml`, `README.md` y `REGISTRO_CAMBIOS.md`. Comprobaciones: 162 pruebas automatizadas aprobadas, compilación y calidad estática aprobadas. No se realizaron conexiones a equipos reales.

### 2026-08-31 19:58:14 -04:00

- Se añadió autenticación opcional para conexiones por consola serial. Si el equipo solicita acceso por la línea de consola, SarevatApp pregunta el usuario (solo si aplica), password y enable secret para esa conexión; no los guarda en perfiles, registros ni inventario.
- Se actualizó la maqueta de interfaz: al seleccionar consola serial muestra Puerto serial y Baudrate en lugar de una IPv4, y se incorporó una flecha de retorno al menú principal en la parte superior de cada pantalla propuesta. En el menú principal la flecha no aparece, para no sugerir una salida o un retorno inexistente.
- Se ajustaron las pruebas de conexión serial para confirmar tanto el acceso directo sin credenciales como el envío temporal de credenciales cuando el operador lo indica.
- Archivos afectados: `sarevat/cli.py`, `tests/test_cli_connections.py`, `tests/test_cli_round2.py` y `work/gui-flujo-sarevat.html`. Comprobaciones: pruebas de conexión y menús, 34 aprobadas; suite completa, 158 aprobadas.

### 2026-08-31 19:34:34 -04:00

- Se añadió `work/gui-flujo-sarevat.html`, una maqueta interactiva de referencia para una futura interfaz gráfica. Mantiene el orden real del menú de PowerShell: conectar a equipo Cisco, planificar VLSM IPv4, escanear IPv4 e inventario y perfiles.
- La pantalla de inicio evita datos ficticios; los equipos y grupos aparecen únicamente en Inventario y perfiles. La conexión muestra sus datos esenciales y aclara que las credenciales se piden al conectar, sin guardarlas.
- Se comprobó que el archivo contiene marcado HTML literal, que los controles del menú actualizan su contenido localmente y que el árbol del repositorio no fue modificado fuera de esta maqueta y su registro. No se ejecutaron pruebas automatizadas: es una propuesta visual aislada que no forma parte de la aplicación ejecutable.

### 2026-08-31 18:45:00 -04:00 — Fase 5: motor de despliegue gradual

- **Cambio:** se añadió un motor de lotes con etapa inicial, concurrencia
  limitada, ventana de mantenimiento y pausa de equipos pendientes ante un
  fallo. Se añadió historial local filtrable por grupo y una opción para verlo
  desde Inventario. No conecta equipos por sí solo.
- **Motivo:** establecer las salvaguardas verificables antes de integrar la
  ejecución real de configuraciones por grupo.
- **Archivos afectados:** `sarevat/batches.py`, `sarevat/cli.py`,
  `tests/test_batches.py` y `REGISTRO_CAMBIOS.md`.
- **Verificación:** `157 passed`; cobertura total de 2,174 líneas ejecutables y
  90% de ramas. Ruff, Bandit, `pip check` y `git diff --check` finalizaron sin
  errores. No se realizaron conexiones Cisco reales.
  No se realizaron conexiones Cisco reales.

### 2026-08-31 18:37:31 -04:00 — VLSM: flujo guiado por cantidad de subredes

- **Cambio:** tras introducir la red base, VLSM pregunta si se trabajará con
  subredes. Si la respuesta es sí, solicita la cantidad y cada nombre; si es
  no, calcula inmediatamente hosts, rango, gateway y broadcast de la red base.
  Se eliminó el cierre por campo vacío y la necesidad de escribir comandos como
  `salir` en campos numéricos.
- **Motivo:** hacer la navegación más clara y evitar errores de entrada durante
  el cálculo VLSM y la preparación de interfaces.
- **Archivos afectados:** `sarevat/cli.py`, `tests/test_cli_round2.py` y
  `REGISTRO_CAMBIOS.md`.
- **Verificación:** `155 passed`; cobertura total de 2,098 líneas ejecutables y
  91% de ramas. Ruff, Bandit, `pip check` y `git diff --check` finalizaron sin
  errores. No se realizaron conexiones a equipos Cisco reales.

### 2026-08-31 18:11:03 -04:00 — VLSM: cálculo automático y validación inmediata

- **Cambio:** VLSM asigna gateway automáticamente a las LAN y no lo reserva en
  enlaces punto a punto ni loopbacks. Las loopbacks exigen una dirección y usan
  `/32`; los enlaces punto a punto admiten hasta dos y usan `/31`. Cada subred
  se comprueba contra la red base antes de aceptar la siguiente.
- **Motivo:** evitar errores manuales de gateway, tipo de enlace y capacidad al
  planificar o preparar interfaces para equipos Cisco.
- **Archivos afectados:** `sarevat/vlsm.py`, `sarevat/cli.py`,
  `tests/test_cli_round2.py`, `tests/test_vlsm_validators_edges.py` y
  `REGISTRO_CAMBIOS.md`.
- **Verificación:** `155 passed`; cobertura total de 2,072 líneas ejecutables y
  92% de ramas. Ruff, Bandit, `pip check` y `git diff --check` finalizaron sin
  errores. No se realizaron conexiones a equipos Cisco reales.

### 2026-08-31 18:00:05 -04:00 — VLSM: etiquetas más claras

- **Cambio:** se reemplazaron las etiquetas visibles “Red base CIDR” y
  “Exclusiones CIDR” por “Introducir Red Base” y “Excluir IP”.
- **Motivo:** reducir terminología técnica en el flujo VLSM sin alterar la
  validación IPv4 ni el formato de entrada esperado.
- **Archivos afectados:** `sarevat/cli.py` y `REGISTRO_CAMBIOS.md`.
- **Verificación:** `35 passed` en pruebas de VLSM y navegación; Ruff y
  `git diff --check` finalizaron sin errores. No se realizaron conexiones Cisco
  reales.

### 2026-08-31 17:44:00 -04:00 — Fase 5: preparación gradual de lotes

- **Cambio:** se añadió la preparación de un lote por grupo con límite de
  concurrencia, primer grupo de prueba y equipos restantes. Esta vista no
  conecta ni aplica configuraciones.
- **Motivo:** permitir revisar el despliegue gradual antes de habilitar
  operaciones masivas sobre equipos reales.
- **Archivos afectados:** `sarevat/batches.py`, `sarevat/cli.py`,
  `tests/test_batches.py`, `README.md` y `REGISTRO_CAMBIOS.md`.
- **Verificación:** las pruebas específicas de lotes, inventario y CLI pasaron
  (`39 passed`); Ruff finalizó sin errores. Falta la batería completa al cerrar
  el bloque de la Fase 5. No se realizaron conexiones Cisco reales.

### 2026-08-31 17:37:59 -04:00 — Fase 6: respaldos cifrados por frase temporal

- **Cambio:** los respaldos redactados se cifran con AES-GCM y una clave derivada
  de la frase que el operador introduce al aplicar un plan. La frase no se
  persiste; el archivo detecta una frase incorrecta o una alteración.
- **Motivo:** proteger los respaldos locales sin almacenar contraseñas, claves
  ni frases secretas dentro de la aplicación.
- **Archivos afectados:** `sarevat/backup_crypto.py`,
  `sarevat/cisco/executor.py`, `sarevat/cli.py`, `requirements.txt`,
  `tests/test_backup_crypto.py`, `README.md` y `REGISTRO_CAMBIOS.md`.
- **Verificación:** `154 passed`; cobertura total de 2,024 líneas ejecutables y
  92% de ramas. Ruff, Bandit, `pip check` y `git diff --check` finalizaron sin
  errores. No se realizaron conexiones a equipos Cisco reales.

### 2026-08-28 20:13:52 -04:00 — Fase 4: plantilla de observabilidad por sitio

- **Cambio:** la plantilla de NTP y syslog ahora permite seleccionar sucursal o
  núcleo. El perfil de núcleo añade únicamente marcas de tiempo de depuración;
  ambos perfiles conservan dry-run, confirmación, checkpoint y rollback.
- **Motivo:** completar plantillas por sitio sin modificar VTY, usuarios, AAA,
  SNMP, claves o credenciales.
- **Archivos afectados:** `sarevat/cisco/services.py`, `sarevat/cli.py`,
  `tests/test_discovery_services.py`, `README.md` y `REGISTRO_CAMBIOS.md`.
- **Verificación:** `152 passed`; cobertura total de 1,977 líneas ejecutables y
  93% de ramas. Ruff, Bandit, `pip check` y `git diff --check` finalizaron sin
  errores. No se realizaron conexiones a equipos Cisco reales.

### 2026-08-28 06:37:05 -04:00 — Preparación del piloto Cisco autorizado

- **Cambio:** se añadió una preflight local de un solo comando y una guía para
  el piloto de las 11:00. La guía define el orden de prueba, los criterios para
  detenerse, la evidencia que debe registrarse y las protecciones adicionales
  para AAA y SNMPv3.
- **Motivo:** llegar a la prueba con un flujo claro de observación, dry-run,
  recuperación y registro, sin presentar la validación local como certificación
  de hardware Cisco.
- **Archivos afectados:** `scripts/preflight_prueba_real.ps1`,
  `PRUEBA_REAL_11AM.md`, `README.md` y `REGISTRO_CAMBIOS.md`.
- **Verificación:** `151 passed`; cobertura total de 1,968 líneas ejecutables y
  93% de ramas. Ruff, Bandit, `pip check`, validación sintáctica de PowerShell
  y `git diff --check` finalizaron sin errores. No se realizaron conexiones a
  equipos Cisco reales.

### 2026-08-27 21:21:14 -04:00 — Fase 5: organización inicial por grupos

- **Cambio:** se añadieron grupos opcionales a los perfiles de inventario. Un
  equipo puede pertenecer a varios grupos, que se normalizan y se pueden
  consultar desde el menú de inventario. Esta entrega no conecta ni aplica
  configuraciones a varios equipos.
- **Motivo:** preparar una organización clara y segura antes de incorporar
  cualquier operación por lotes.
- **Archivos afectados:** `sarevat/inventory.py`, `sarevat/cli.py`,
  `tests/test_inventory.py`, `tests/test_cli_round2.py`, `README.md` y
  `REGISTRO_CAMBIOS.md`.
- **Verificación:** `151 passed`; cobertura total de 1,968 líneas ejecutables y
  93% de ramas. Ruff, Bandit, `pip check` y `git diff --check` finalizaron sin
  errores. No se realizaron conexiones a equipos Cisco reales.

### 2026-08-27 21:19:10 -04:00 — Fase 4: revisión y plantillas seguras

- **Cambio:** se añadió una auditoría de seguridad que revisa SSH v2, NTP,
  syslog, SNMPv3, AAA y cifrado básico de contraseñas sin enviar comandos de
  configuración. La sesión permite comparar la configuración descubierta con
  un archivo local, y los resultados de planes se exportan como JSON y CSV con
  secretos redactados. Se añadió una plantilla conjunta de NTP y syslog con el
  mismo dry-run, confirmación y rollback del resto de la aplicación. Se
  incorporaron plantillas para SNMPv3 y AAA local: SNMPv3 no elimina usuarios
  ni comunidades existentes y sus claves se piden ocultas; AAA exige que el
  usuario local ya exista, la confirmación literal `CONSOLA_LISTA`, dry-run y
  una segunda confirmación de alto impacto antes de enviar comandos. Se añadió
  una referencia local redactada para detectar cambios de configuración sin
  remediarlos automáticamente, y un plan separado de endurecimiento básico que
  solo incorpora SSH v2 y cifrado de contraseñas cuando faltan, sin modificar
  VTY, usuarios, AAA, SNMP ni claves RSA.
- **Motivo:** hacer visible el estado de seguridad y los cambios propuestos sin
  modificar equipos ni persistir credenciales, evitando que una configuración
  de AAA o SNMPv3 afecte innecesariamente el acceso o el monitoreo existente.
- **Archivos afectados:** `sarevat/compliance.py`, `sarevat/reporting.py`,
  `sarevat/security.py`, `sarevat/cisco/services.py`, `sarevat/cli.py`,
  `sarevat/baselines.py`,
  `tests/test_compliance.py`, `tests/test_reporting.py`,
  `tests/test_discovery_services.py`, `tests/test_cli_round2.py`,
  `tests/test_validators_security.py`, `tests/test_baselines.py`, `README.md`
  y `REGISTRO_CAMBIOS.md`.
- **Verificación:** `150 passed`; cobertura total de 1,939 líneas ejecutables y
  93% de ramas. Ruff, Bandit, `pip check` y `git diff --check` finalizaron sin
  errores. No se realizaron conexiones a equipos Cisco reales.

### 2026-08-27 20:27:41 -04:00 — Fase 3: inventario, perfiles, comparación y reportes

- **Cambio:** se añadió un inventario JSON con esquema versionado, perfiles SSH
  y serial sin secretos, actualización de modelo/versión/serial tras el
  descubrimiento y un menú sencillo para crear, consultar, conectar y eliminar
  perfiles. Se añadieron borradores redactados de planes y una utilidad para
  comparar configuraciones sin exponer secretos. Se añadieron comparación de
  una configuración descubierta con un archivo local y reportes JSON/CSV para
  dry-run y aplicación. Las credenciales continúan solicitándose en cada
  conexión, sin persistirlas. Se mejoró el mensaje para una IPv4 inválida en un
  perfil y se ampliaron las pruebas de inventario, borradores, menús, conexión
  reutilizable y reportes.
- **Motivo:** reducir la repetición de datos de conexión sin almacenar
  contraseñas ni hacer más complejo el flujo habitual de la aplicación.
- **Archivos afectados:** `sarevat/inventory.py`, `sarevat/drafts.py`,
  `sarevat/reporting.py`, `sarevat/security.py`, `sarevat/cli.py`,
  `tests/test_inventory.py`, `tests/test_drafts.py`, `tests/test_reporting.py`,
  `tests/test_cli_connections.py`, `tests/test_cli_round2.py`, `README.md` y
  `REGISTRO_CAMBIOS.md`.
- **Verificación:** `136 passed`; cobertura total de 1,725 líneas ejecutables y
  95% de ramas. Ruff, Bandit, `pip check` y `git diff --check` finalizaron sin
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
