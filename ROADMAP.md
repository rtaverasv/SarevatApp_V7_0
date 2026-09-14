# Roadmap unificado de SarevatApp 7.0

## Propósito y alcance

SarevatApp 7.0 administra actualmente equipos Cisco IOS/IOS-XE por SSH o
consola serial y permanece exclusivamente en IPv4. Mantiene dos formas de uso
sobre la misma capa de validaciones y planes: PowerShell/terminal y GUI Alpha.
IPv6 no forma parte del alcance. La extensión multi-fabricante se planifica
como una iniciativa explícita, con detección segura y adaptadores separados;
no se declarará soporte Juniper ni de otra marca hasta validarlo.

La referencia funcional es `SarevatApp_V7_0.py`, el paquete `sarevat/` y la
GUI `SarevatApp_GUI_alpha.py`. La última validación local aprobó 181 pruebas,
Ruff, Bandit y `pip check`; también hay CI para Python 3.11 y 3.12. Estos
resultados no certifican compatibilidad con equipos Cisco reales.

## Reglas de operación

- No declarar soporte real por mocks, cobertura o dry-run: se requiere CML,
  EVE-NG, GNS3 o hardware Cisco autorizado.
- Toda configuración debe seguir este orden: validar, vista previa redactada,
  dry-run, confirmación, respaldo, checkpoint, postchecks y rollback.
- No persistir passwords, enable secrets ni claves SNMP. Las credenciales se
  solicitan para cada conexión y los respaldos se cifran con una frase temporal.
- AAA y SNMPv3 son cambios de alto impacto: requieren recuperación por consola,
  confirmaciones adicionales y revisión manual antes de aplicar.
- Las operaciones por lote se preparan y revisan primero; no se habilita la
  aplicación masiva hasta validar el flujo en laboratorio.

## Estado por fases

| Fase | Estado | Resultado actual | Pendiente principal |
|---|---|---|---|
| 0. Línea base y control de cambios | Completada | Repositorio unificado, `main` actualizado, respaldo `backup/main-antes-gui`, changelog y CI activos. | Mantener la comparación antes de integrar fuentes externas. |
| 1. Confianza y regresión automatizada | Completada localmente | 163 pruebas; validadores, VLSM, escáner, CLI, SSH/serial simulados, servicios, executor, rollback y reportes. Ruff, Bandit y `pip check` aprobados. | Añadir pruebas visuales de GUI cuando exista un entorno gráfico automatizable. |
| 2. Laboratorio y compatibilidad | Parcial (Junos) | Un equipo Junos autorizado validó SSH, descubrimiento, candidato y prechecks de solo lectura por SarevatApp. | Probar cambios Junos recuperables y el flujo Cisco: serial, dry-run, checkpoint, rollback, AAA y SNMPv3; crear matriz de compatibilidad. |
| 3. Inventario y flujo reutilizable | Completada localmente | Perfiles sin secretos, grupos, borradores redactados, diff, historial y reportes JSON/CSV. La GUI y PowerShell los comparten. | Confirmar persistencia y rutas de `runtime/` en la laptop y en equipos de uso real. |
| 4. Seguridad, plantillas y cumplimiento | Completada localmente | NTP/syslog por sitio, SSH, SNMPv3, AAA local protegido, hardening, auditoría de solo lectura, referencia segura y detección de drift. | Validar comandos y postchecks por plataforma; documentar excepciones por versión IOS. |
| 5. Lotes y experiencia de usuario | Parcial | Motor gradual, concurrencia, ventana, pausa por fallo e historial; GUI Alpha funcional con navegación, sesión única, VLSM, escáner e inventario. | Validar la GUI con laboratorio y decidir cuándo habilitar ejecución real y controlada de lotes. |
| 6. Entrega y certificación continua | Parcial | Respaldos redactados cifrados, reportes JSON/CSV, guía de uso, preflight y registro de cambios. | Empaquetar como `.exe`, definir retención de respaldos, preparar releases y publicar una matriz de soporte certificada. |

## Capacidades entregadas

- Base multi-fabricante local: la GUI puede detectar por SSH Cisco IOS/IOS-XE,
  Junos y Huawei VRP. Junos ofrece inventario y prechecks de solo lectura,
  además de candidatos de gestión en vista previa; Huawei y marcas no
  certificadas no reciben comandos de descubrimiento ni configuración.
- Conexión Cisco por SSH IPv4 y consola serial; la consola muestra puerto,
  baudrate y autenticación opcional en lugar de pedir una IP.
- Descubrimiento de equipo, inventario de interfaces y consola libre auditada.
- Planificación VLSM IPv4 con gateway, broadcast y hosts automáticos; permite
  preparar una configuración por interfaz calculada.
- Escaneo IPv4 autorizado con segunda confirmación, DNS inverso, caché ARP y
  exportación de resultados.
- 23 planes de servicios y protocolos, configuración inicial, IPv4 de interfaz,
  NTP/syslog, SNMPv3, AAA, hardening, referencias y drift.
- Respaldo cifrado, checkpoint en el equipo, detección de errores IOS,
  postchecks, rollback opcional y auditoría redactada.
- GUI Alpha funcional y PowerShell conservado como alternativa. La GUI no se
  considera certificada hasta pasar pruebas de laboratorio.

## Próximo sprint recomendado

1. Ejecutar el preflight y una prueba de descubrimiento de solo lectura por SSH
   en un equipo autorizado.
2. Repetir la prueba por consola serial, con y sin autenticación de línea.
3. Validar un dry-run y un cambio de bajo riesgo con checkpoint y rollback;
   dejar AAA, SNMPv3 y cambios de acceso para una sesión de prueba separada.
4. Registrar modelo, versión IOS/IOS-XE, licencia, comandos aceptados y
   postchecks en la matriz de compatibilidad.
5. Corregir cualquier diferencia de laboratorio antes de habilitar lotes reales
   o declarar la GUI estable.
6. Tras el laboratorio, empaquetar una versión de prueba `.exe` y validarla en
   una laptop limpia conservando el código fuente y la opción PowerShell.

## Iniciativa previa: base multi-fabricante y detección de plataforma

Prioridad P0 antes de ampliar automatizaciones de configuración. Hoy la
selección `router`/`switch` representa el rol del equipo, no su fabricante:
la conexión y el descubrimiento asumen Cisco IOS. Por ello no se deben enviar
comandos Cisco a un Juniper ni inferir la marca solo por el tipo de equipo.

1. **Modelo neutral y capacidades.** Incorporar fabricante/plataforma,
   versión, familia y nivel de confianza de detección, separados de
   `router`/`switch`; definir las operaciones que cada plataforma admite.
2. **Sondeo de solo lectura.** Abrir transporte SSH o serial genérico,
   reconocer de forma prudente banner, prompt y salida de identificación; pedir
   confirmación al usuario si la confianza es insuficiente. Antes de esa
   confirmación no se aplicará ninguna configuración.
3. **Adaptadores por plataforma.** Extraer el comportamiento actual a un
   adaptador Cisco IOS/IOS-XE y crear un adaptador Junos independiente. Cada
   adaptador encapsulará descubrimiento, normalización de hechos, comandos
   permitidos, postchecks y errores propios de su CLI.
4. **Primer alcance Junos: lectura e inventario.** Implementar descubrimiento
   e inventario Junos de solo lectura, presentar las capacidades reales y
   ocultar o marcar como no disponibles las funciones Cisco que no apliquen.
5. **Cambios Junos y validación.** Diseñar los planes Junos con su flujo de
   configuración, revisión, confirmación, commit y recuperación; probarlos en
   laboratorio autorizado antes de habilitarlos. No se reutilizará sintaxis
   Cisco para Junos.
6. **Matriz y pruebas.** Añadir fixtures saneados de Cisco y Juniper, pruebas
   de detección y regresión por adaptador, y una matriz de modelos/versiones
   certificados.

Estado local actual: modelo de plataforma, detección SSH por Netmiko y
adaptadores separados ya existen. Cisco conserva su ejecutor actual; Junos
realiza inventario de lectura, genera candidatos de gestión validados y cuenta
con prechecks de solo lectura visibles en la GUI, parser de errores, contrato
de `commit check` / `commit confirmed` y un ejecutor que bloquea por código
todo intento no-dry-run. No existe ruta de aplicación remota.
Huawei puede ser identificado pero no tiene inventario ni configuración
certificados. Ninguna de estas capacidades declara compatibilidad real hasta
completar la aceptación con hardware autorizado.

### Evidencia de aceptación Junos en laboratorio

El 14 de septiembre de 2026 se validó con un equipo Junos autorizado, por SSH
directo a su interfaz de gestión, que SarevatApp descubre la plataforma y sus
hechos básicos. También se validaron un candidato bloqueado de vista previa y
los prechecks de consulta de hostname e interfaz. No se enviaron comandos de
configuración, no se ejecutó `commit` y la aplicación remota Junos sigue
deshabilitada. Los identificadores y direcciones del laboratorio no se
conservan en el repositorio.

El asistente serial se construirá sobre esta base. La primera entrega del
asistente conservará alcance Cisco, pero quedará aislada en el adaptador
Cisco para que el soporte Junos no obligue a rehacerla.

## Próximo desarrollo: asistente de equipo nuevo por serial

Prioridad P0. El objetivo es preparar un router virgen desde SarevatApp sin
depender de PuTTY, dejando la consola externa solo como mecanismo de
recuperación. Se implementará en cuatro etapas:

1. **Lógica y pruebas locales.** Validar COM, velocidad, interfaz, IPv4,
   máscara, hostname, dominio, usuario y secretos temporales; generar un
   `CommandPlan` redactado que incluya IP de gestión, RSA y SSH. No aplica
   comandos a un equipo real.
2. **Asistente visual.** Solicitar los datos en campos separados, permitir
   `enable secret` aunque la consola no pida autenticación, mostrar la vista
   previa y exigir confirmación antes de cualquier aplicación.
3. **Verificación controlada.** Tras aplicar por serial, consultar estado de
   interfaz, IP y disponibilidad SSH. La persistencia será una acción separada,
   nunca automática.
4. **Prueba de aceptación en INFOTEP.** Usar el Cisco 1841 identificado, sin
   guardar configuración inicialmente; registrar versión IOS, prompts y
   compatibilidad SSH antigua antes de habilitar el flujo para otros equipos.

### Fases detalladas de implementación

| Fase | Alcance | Criterio de salida |
|---|---|---|
| 0. Base de plataforma | Completar el modelo fabricante/plataforma, detección de solo lectura y selección confirmada de adaptador; Cisco primero, Junos sin cambios habilitados. | Ningún equipo desconocido recibe sintaxis Cisco; las pruebas cubren detección, incertidumbre y fallback seguro. |
| 1. Definición segura | Fijar datos obligatorios, límites del flujo y la regla de que persistir configuración es opcional. | Contrato de entradas, resultados esperados y riesgos documentados. |
| 2. Lógica de bootstrap | Validar COM, baudrate, interfaz, IPv4, máscara, hostname, dominio, usuario y secretos temporales; generar el `CommandPlan` Cisco redactado. | Pruebas unitarias cubren planes válidos, errores y ausencia de secretos en registros. |
| 3. Ejecución serial segura | Reconocer prompts `Router>`, `Router#` y autenticación mediante el adaptador Cisco; permitir `enable secret` sin login de consola; detectar errores IOS y detenerse. | Simulaciones cubren consola abierta, autenticada y fallos IOS sin enviar comandos no previstos. |
| 4. Asistente visual | Implementar flujo por pasos, campos separados, vista previa, dry-run, confirmación y cancelación; exponer fabricante detectado, confianza y capacidades. | Navegación y mensajes verificados visualmente sin ocultar ni persistir secretos. |
| 5. Verificación y registro | Consultar estado de interfaz, IP y SSH; ofrecer registrar el perfil sin passwords y con su plataforma confirmada. | El flujo termina en descubrimiento de solo lectura o informa un error accionable. |
| 6. Pruebas locales completas | Ejecutar regresión, fixtures Cisco/Juniper, integración simulada, Ruff, Bandit y revisión de cambios. | Suite completa aprobada antes de usar hardware. |
| 7. Aceptación en INFOTEP | Probar el Cisco 1841 por serial sin persistencia, luego validar IP, SSH y descubrimiento desde SarevatApp. | Evidencia de comportamiento real, matriz IOS y diferencias documentadas. |
| 8. Cierre y entrega | Actualizar guía, matriz de compatibilidad y evidencia; promover solo cambios validados en `Mods-GUI`. | Rama sincronizada, `Mods` intacta y respaldo retenido hasta confirmar estabilidad. |

## Criterio de salida para GUI estable

La GUI podrá dejar de llamarse Alpha cuando complete, como mínimo, una prueba
autorizada de SSH y serial, descubrimiento, VLSM, dry-run, respaldo cifrado,
checkpoint, rollback y manejo seguro de un error de IOS. Debe conservarse la
evidencia de la prueba y la matriz de compatibilidad antes de usarla para
cambios operativos.

## Validación mínima local

```powershell
python -m pytest -q --cov=sarevat --cov-branch --cov-report=term-missing
python -m ruff check SarevatApp_V7_0.py sarevat tests
python -m bandit -q -r sarevat SarevatApp_V7_0.py
python -m pip check
```
