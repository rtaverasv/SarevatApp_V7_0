# Roadmap unificado de SarevatApp 7.0

## Propósito y alcance

Este es el roadmap principal de SarevatApp. Integra la comparación entre
entornos con la evolución del producto y prioriza la confianza operativa antes
de ampliar alcance. La versión 7.0 administra equipos Cisco IOS/IOS-XE por SSH
o consola serial y permanece exclusivamente en IPv4. IPv6 y otros fabricantes
solo se evaluarán como iniciativas independientes, con aprobación, validadores
y pruebas propias.

La referencia funcional es `SarevatApp_V7_0.py` y el paquete `sarevat/` con
Python 3.11 o posterior. La validación local registrada incluye 118 pruebas,
cobertura de 1,324 de 1,324 líneas ejecutables y 99% de ramas, junto con Ruff,
Bandit y `pip check`. Estos resultados son simulados: no certifican equipos
Cisco reales.

## Línea base y reglas de trabajo

- Antes de modificar otra copia del proyecto, comparar estructura,
  dependencias, hashes, pruebas y capacidades con esta línea base.
- Clasificar diferencias como: Conservada, Mejorada, Regresión, Ausente o Nueva
  sin probar; registrar archivo, evidencia y prioridad P0/P1/P2/P3.
- No declarar compatibilidad real por pruebas unitarias o mocks. Se requiere
  CML, EVE-NG, GNS3 o hardware Cisco autorizado.
- Mantener el flujo seguro: `CommandPlan` validado, dry-run, confirmación,
  respaldo redactado, checkpoint, detección de errores IOS, fail-fast,
  postchecks y rollback confirmado.
- Mantener la auditoría JSONL con secretos redactados, validación estricta de
  entradas, VLSM IPv4 y escaneo autorizado con límites.

## Roadmap por fases

| Fase | Prioridad | Objetivo y resultado esperado |
|---|---:|---|
| 0. Congelar línea base | P0 | Comparar árbol, dependencias, hashes, pruebas y capacidades antes de integrar otra copia. |
| 1. Confianza y regresión automatizada | P0 | Empaquetado reproducible, pruebas de validadores, VLSM, seguridad, escáner, CLI, SSH, serial, 23 planes, rollback y postchecks semánticos; CI con pytest, cobertura, Ruff y Bandit. |
| 2. Laboratorio y compatibilidad | P0/P1 | Validar flujos críticos en CML/EVE-NG/GNS3 y realizar piloto autorizado; crear matriz por IOS/IOS-XE, modelo, licencia y capacidades antes de generar comandos. |
| 3. Inventario y flujo reutilizable | P1 | Inventario versionado por esquema, perfiles de conexión, almacén seguro de credenciales, borradores de planes, diff de configuración y reportes/códigos de salida normalizados. |
| 4. Seguridad, plantillas y cumplimiento | P1/P2 | Plantillas por rol/sitio, NTP, syslog, SSH, SNMPv3, AAA y hardening; auditoría de solo lectura, golden config, drift, evidencia y remediación separada como `CommandPlan`. |
| 5. Operación por lotes y experiencia | P2 | Grupos, concurrencia limitada, ventanas de mantenimiento, despliegue gradual, pausa por fallo, historial filtrable y terminal mejorada o web local sobre la misma capa de casos de uso. |
| 6. Entrega y certificación continua | P2 | Respaldos cifrados y con retención, reportes HTML/JSON/CSV, empaquetado, releases versionados, changelog, migraciones, guía de recuperación y matriz de soporte certificada. |

## Próximo sprint recomendado

1. Ejecutar fases 0 y 1 contra cualquier copia de VS Code antes de añadir
   capacidades nuevas.
2. Mantener y extender la suite de regresión de seguridad, VLSM, escáner, CLI,
   executor y servicios; cubrir cancelaciones, errores IOS y rollback.
3. Corregir primero cualquier diferencia que sea una regresión P0/P1.
4. Preparar laboratorio y matriz de compatibilidad antes de ampliar servicios o
   declarar soporte de plataforma.
5. Implementar después inventario, credenciales seguras y diff; continuar con
   cumplimiento, operaciones masivas y experiencia de usuario.

## Validación mínima local

```powershell
python -m pytest -q --cov=sarevat --cov-branch --cov-report=term-missing
python -m ruff check SarevatApp_V7_0.py sarevat tests
python -m bandit -q -r sarevat SarevatApp_V7_0.py
python -m pip check
```

No conviene empezar por una interfaz gráfica sin conservar la separación entre
la interfaz y los casos de uso: duplicaría el acoplamiento y aumentaría el
riesgo operativo.
