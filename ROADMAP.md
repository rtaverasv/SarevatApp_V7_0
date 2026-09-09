# Roadmap unificado de SarevatApp 7.0

## Propósito y alcance

SarevatApp 7.0 administra equipos Cisco IOS/IOS-XE por SSH o consola serial y
permanece exclusivamente en IPv4. Mantiene dos formas de uso sobre la misma
capa de validaciones y planes: PowerShell/terminal y GUI Alpha. IPv6 y otros
fabricantes requieren una iniciativa independiente, aprobada y probada.

La referencia funcional es `SarevatApp_V7_0.py`, el paquete `sarevat/` y la
GUI `SarevatApp_GUI_alpha.py`. La última validación local aprobó 163 pruebas,
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
| 2. Laboratorio y compatibilidad | Pendiente P0 | Preflight, guía de piloto y comportamiento fail-fast preparados. | Probar SSH, serial, dry-run, checkpoint, rollback, AAA y SNMPv3 en equipos autorizados; crear matriz IOS/IOS-XE, modelo, licencia y capacidades. |
| 3. Inventario y flujo reutilizable | Completada localmente | Perfiles sin secretos, grupos, borradores redactados, diff, historial y reportes JSON/CSV. La GUI y PowerShell los comparten. | Confirmar persistencia y rutas de `runtime/` en la laptop y en equipos de uso real. |
| 4. Seguridad, plantillas y cumplimiento | Completada localmente | NTP/syslog por sitio, SSH, SNMPv3, AAA local protegido, hardening, auditoría de solo lectura, referencia segura y detección de drift. | Validar comandos y postchecks por plataforma; documentar excepciones por versión IOS. |
| 5. Lotes y experiencia de usuario | Parcial | Motor gradual, concurrencia, ventana, pausa por fallo e historial; GUI Alpha funcional con navegación, sesión única, VLSM, escáner e inventario. | Validar la GUI con laboratorio y decidir cuándo habilitar ejecución real y controlada de lotes. |
| 6. Entrega y certificación continua | Parcial | Respaldos redactados cifrados, reportes JSON/CSV, guía de uso, preflight y registro de cambios. | Empaquetar como `.exe`, definir retención de respaldos, preparar releases y publicar una matriz de soporte certificada. |

## Capacidades entregadas

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
