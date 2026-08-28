# Línea base de SarevatApp 7.0

## Identidad congelada

- **Versión funcional:** 7.0.0.
- **Ámbito:** Cisco IOS/IOS-XE por SSH o consola serial; IPv4 únicamente.
- **Commit de referencia:** `94baaeae78c93cbd0f3c6e17e7972cdd4e32923a`.
- **Árbol Git de referencia:** `d70a4a2686c37e6c20faf634905edb739bdacf36`.
- **Python requerido:** 3.11 o superior.

Esta línea base es el punto de comparación obligatorio antes de integrar otra
copia del proyecto o aceptar cambios externos. No equivale a una certificación
en equipos Cisco reales.

## Inventario funcional

| Elemento | Estado congelado |
| --- | --- |
| Punto de entrada | `SarevatApp_V7_0.py` delega en la CLI modular. |
| Núcleo | 12 módulos bajo `sarevat/`, incluidos descubrimiento, servicios y ejecutor Cisco. |
| Pruebas | 12 archivos de prueba y 25 archivos Python en total (código y pruebas). |
| Dependencias de ejecución | Netmiko 4.7.0, Colorama 0.4.6 y PySerial 3.5. |
| Dependencias de calidad | Pytest, pytest-cov, Ruff y Bandit, fijadas en `requirements-dev.txt`. |
| Salvaguardas | Validación, dry-run, confirmación, respaldo redactado, checkpoint, fail-fast, postchecks y rollback confirmado. |

## Procedimiento de comparación

1. Confirmar que no hay cambios locales no revisados con `git status --short`.
2. Comparar el árbol recibido con el commit y el árbol Git indicados arriba.
3. Revisar `pyproject.toml`, ambos archivos de requisitos, los módulos
   `sarevat/`, el punto de entrada y `tests/`.
4. Clasificar cada diferencia como **Conservada**, **Mejorada**,
   **Regresión**, **Ausente** o **Nueva sin probar**, con evidencia y prioridad
   P0/P1/P2/P3.
5. Ejecutar las comprobaciones locales antes de integrar cambios. Una
   regresión P0 o P1 bloquea la integración hasta corregirse o aprobarse de
   forma explícita.

```powershell
python -m pytest -q --cov=sarevat --cov-branch --cov-report=term-missing
python -m ruff check SarevatApp_V7_0.py sarevat tests
python -m bandit -q -r sarevat SarevatApp_V7_0.py
python -m pip check
```

## Límites conocidos

- Los resultados locales y los dobles de Netmiko no certifican IOS, IOS-XE,
  modelos, licencias ni hardware real.
- Para declarar compatibilidad se requiere la matriz y el piloto de la Fase 2
  en CML, EVE-NG, GNS3 o equipos autorizados.
- IPv6 y fabricantes distintos de Cisco no forman parte de esta línea base.
