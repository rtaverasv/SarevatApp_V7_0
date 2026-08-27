# Analisis del proyecto SarevatApp 7.0

## Resumen ejecutivo

SarevatApp ya tiene un nucleo valioso para operadores de redes Cisco: descubrimiento de equipos, 23 planes de configuracion, VLSM, escaneo IPv4 y un ejecutor con dry-run, auditoria, checkpoint y rollback. La separacion entre CLI, validacion, modelos, seguridad y adaptadores Cisco es una buena base para evolucionar el producto.

La principal limitacion no es la cantidad de funciones, sino la confianza operativa y la experiencia de uso. El repositorio no incluye las pruebas que menciona el README, no tiene empaquetado ni automatizacion de calidad, y todo el flujo depende de preguntas interactivas. Antes de ampliar el catalogo conviene asegurar el motor actual y convertirlo en una herramienta repetible: inventario persistente, plantillas, comparacion de cambios y reportes por equipo.

## Estado actual

### Fortalezas

- Arquitectura modular: la CLI no contiene la construccion completa de comandos ni la logica VLSM.
- Seguridad por defecto: secretos con entrada oculta, redaccion en logs, dry-run y doble confirmacion para acciones de riesgo.
- Recuperacion: respaldo local redactado, checkpoint en flash y rollback confirmado.
- Validacion preventiva de IPv4, VLAN, interfaces, ASN y texto Cisco.
- Alcance claro: Cisco IOS/IOS-XE e IPv4, evitando prometer compatibilidad no comprobada.
- Exportacion JSON/CSV y auditoria JSONL, utiles como base para integraciones futuras.

### Riesgos y deuda tecnica

| Prioridad | Hallazgo | Impacto | Accion recomendada |
| --- | --- | --- | --- |
| Critica | No existe el directorio `tests/`, aunque el README declara comandos de pytest. | Un cambio en comandos, redaccion o rollback puede llegar a un equipo sin deteccion previa. | Crear pruebas unitarias y de contrato con conexiones Netmiko simuladas. |
| Alta | Los postchecks solo verifican que IOS no devuelva un error conocido; no comparan el estado observado con el esperado. | Puede declararse aplicado un plan que no produjo el estado deseado. | Incorporar expectativas estructuradas por servicio y validarlas contra datos descubiertos. |
| Alta | El respaldo local esta redactado y el unico artefacto restaurable queda en el mismo dispositivo. | Una falla de flash o del equipo elimina la via automatica de recuperacion. | Permitir respaldo cifrado fuera del dispositivo, con politica explicita de claves y retencion. |
| Alta | La aplicacion es exclusivamente interactiva y no conserva inventario, perfiles ni trabajos. | Se repiten datos, aumenta el error humano y no hay operacion por lotes. | Separar una API de aplicacion de la CLI y persistir inventario no secreto. |
| Media | Falta `pyproject.toml`, declaracion de version de Python y dependencias de desarrollo. | Instalaciones inconsistentes y barrera alta para contribuir o desplegar. | Empaquetar el proyecto y fijar Python 3.11+ por el uso de `StrEnum`. |
| Media | No hay CI, formateo o analisis de seguridad ejecutado automaticamente. | La calidad depende de pasos manuales. | Añadir pipeline con compile, pytest, Ruff y Bandit. |
| Media | El README contiene una ruta absoluta de otra maquina y afirma pruebas no presentes. | La puesta en marcha no es reproducible y la documentacion genera una expectativa incorrecta. | Sustituir por instrucciones relativas y documentar el estado real. |
| Media | Los 23 servicios se resuelven en una funcion condicional extensa. | El crecimiento del catalogo aumenta el costo de prueba y mantenimiento. | Extraer constructores por dominio cuando exista cobertura que proteja el cambio. |
| Baja | No existe una politica de retencion/limpieza para checkpoints en flash. | Los archivos acumulados pueden consumir almacenamiento del equipo. | Registrar, listar y retirar checkpoints vencidos con confirmacion. |

## Arquitectura observada

```text
SarevatApp_V7_0.py
  -> sarevat.cli                 interfaz y orquestacion interactiva
     -> sarevat.cisco.discovery inventario y parsing de comandos show
     -> sarevat.cisco.services  catalogo y construccion de planes
     -> sarevat.cisco.executor  prechecks, apply, postchecks y rollback
     -> sarevat.validators      validacion de entradas
     -> sarevat.security        riesgos, errores IOS y redaccion
     -> sarevat.vlsm            planificacion de subredes
     -> sarevat.scanner         descubrimiento IPv4 y puertos TCP
     -> sarevat.logging_utils   auditoria local
```

Las dependencias apuntan en una sola direccion y no se observa una dependencia circular evidente. El siguiente limite arquitectonico util es crear una capa de casos de uso independiente de `input()`/`print()`. Esto permitira probar flujos completos y, mas adelante, ofrecer otra interfaz sin duplicar logica de red.

## Oportunidades para aumentar utilidad

1. Inventario de dispositivos con etiquetas, sitio, modelo, version y ultimo estado, sin guardar passwords en texto plano.
2. Vista previa con diff entre configuracion actual y propuesta, no solo una lista de comandos.
3. Plantillas reutilizables por sitio o rol: access switch, branch router, edge y laboratorio.
4. Evaluacion de cumplimiento de solo lectura para NTP, syslog, SNMP, AAA, SSH y configuraciones inseguras.
5. Ejecucion por lotes con limites de concurrencia, pausa por fallo y resumen por dispositivo.
6. Historial consultable de cambios, resultados, backups y rollbacks.
7. Importacion/exportacion de inventario y planes en YAML/JSON con esquema versionado.

## Criterio de exito recomendado

La aplicacion deberia considerarse lista para ampliar alcance cuando el motor tenga pruebas para cada constructor de planes, el ejecutor tenga escenarios de exito/fallo/rollback, los postchecks validen estado y exista una prueba de laboratorio para las plataformas Cisco soportadas. Las funciones nuevas deben medir reduccion de pasos manuales, porcentaje de planes validados y tasa de rollback, no solo cantidad de opciones en el menu.
