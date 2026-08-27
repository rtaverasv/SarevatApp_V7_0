# Roadmap de SarevatApp

Este roadmap prioriza confianza operativa antes que expansion de alcance. Las duraciones son orientativas para trabajo incremental y deben ajustarse despues de probar con los modelos Cisco objetivo.

## Fase 0 - Base del repositorio (completada en esta revision)

- [x] Inicializar Git con la rama `main`.
- [x] Excluir entornos, caches, resultados de pruebas, runtime y secretos locales.
- [x] Documentar arquitectura, riesgos y oportunidades de producto.
- [ ] Crear el primer commit cuando se revise el contenido inicial.

## Fase 1 - Confianza y reproducibilidad (1-2 semanas)

Objetivo: poder cambiar el motor sin aumentar el riesgo sobre equipos reales.

- Añadir `pyproject.toml` con Python 3.11+, dependencias de ejecucion y grupos de desarrollo.
- Crear pruebas unitarias para validadores, VLSM, redaccion y los 23 constructores de planes.
- Crear pruebas del ejecutor con dobles de Netmiko: dry-run, precheck fallido, apply, postcheck fallido, checkpoint y rollback.
- Convertir los postchecks en aserciones de estado esperado por servicio.
- Corregir el README con instalacion relativa, entorno virtual y limitaciones reales.
- Añadir CI para compilacion, pytest con cobertura, Ruff y Bandit.

Salida: pipeline verde, cobertura inicial >= 80% en el motor no interactivo y cero secretos en artefactos de prueba.

## Fase 2 - Flujo operativo reutilizable (2-3 semanas)

Objetivo: reducir entradas repetidas y mostrar exactamente que cambiara.

- Extraer casos de uso de `cli.py` para que no dependan de `input()` y `print()`.
- Crear inventario local versionado por esquema, sin credenciales en texto plano.
- Añadir perfiles de conexion y uso opcional del almacen seguro del sistema operativo.
- Implementar diff de configuracion actual contra plan propuesto.
- Guardar planes como borrador, validarlos y volver a ejecutarlos.
- Estandarizar reportes de ejecucion y codigos de salida para automatizacion.

Salida: un operador puede seleccionar un equipo, cargar una plantilla, revisar un diff y ejecutar sin reintroducir todos los datos.

## Fase 3 - Plantillas y cumplimiento (2-4 semanas)

Objetivo: convertir SarevatApp en una herramienta de estandarizacion, no solo de configuracion puntual.

- Plantillas por rol/sitio con variables y esquema validado.
- Perfiles base para NTP, syslog, SSH, SNMPv3, AAA y endurecimiento.
- Modo auditoria de solo lectura con reglas de cumplimiento y evidencia.
- Remediacion generada como `CommandPlan`, siempre separada de la auditoria.
- Respaldo cifrado externo y politica de retencion de backups/checkpoints.
- Reporte HTML/JSON por equipo, sitio y regla.

Salida: informe de cumplimiento reproducible y remediacion revisable mediante diff.

## Fase 4 - Operacion por lotes y experiencia de usuario (3-5 semanas)

Objetivo: operar varios equipos con control de impacto.

- Cola de trabajos con concurrencia limitada y ventana de mantenimiento.
- Estrategias de despliegue: uno primero, lotes pequeños, pausa automatica por fallo.
- Historial filtrable de ejecuciones, cambios y rollbacks.
- Interfaz de terminal mejorada o interfaz web local sobre la misma capa de casos de uso.
- Exportacion/importacion de inventario y resultados.
- Metricas locales: exito, fallo, duracion, dispositivos omitidos y rollbacks.

Salida: despliegue controlado a un grupo de dispositivos con resumen y trazabilidad completa.

## Fase 5 - Certificacion y expansion (continua)

Objetivo: ampliar solo lo que pueda probarse y mantenerse.

- Matriz de compatibilidad por IOS/IOS-XE, modelo y licencia.
- Laboratorio automatizado en CML, EVE-NG o GNS3 para flujos criticos.
- Pruebas de consola serial y fallos de transporte.
- Evaluar IPv6 y otros fabricantes como iniciativas separadas, basadas en demanda.
- Publicacion versionada, changelog, migraciones de esquema y guia de recuperacion.

Salida: releases con plataformas certificadas y limites de soporte explicitos.

## Proximo sprint recomendado

1. Empaquetado reproducible y correccion del README.
2. Pruebas de `validators.py`, `security.py` y `vlsm.py`.
3. Pruebas de todos los planes de `services.py`.
4. Pruebas del ciclo checkpoint/apply/postcheck/rollback.
5. Postchecks con expectativas semanticas para VLAN, trunk, rutas, OSPF y BGP.

No conviene comenzar por una interfaz grafica: sin una capa de casos de uso y pruebas, solo duplicaria el acoplamiento del flujo interactivo actual.
