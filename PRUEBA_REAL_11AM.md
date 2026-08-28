# Piloto Cisco: checklist de las 11:00

Esta guía prepara una prueba controlada; no certifica automáticamente ningún
modelo. La app continúa siendo exclusiva para Cisco IOS/IOS-XE e IPv4.

## Antes de conectar

1. Trabaja con un equipo autorizado, aislado de producción y con una consola
   local funcional. Ten una copia externa de su configuración inicial.
2. Ejecuta desde la carpeta del proyecto:

   ```powershell
   .\scripts\preflight_prueba_real.ps1
   ```

   Si PowerShell impide ejecutar el script, usa el intérprete directamente:

   ```powershell
   .\.venv\Scripts\python.exe -m pytest -q --cov=sarevat --cov-branch --cov-report=term-missing
   .\.venv\Scripts\python.exe -m ruff check sarevat tests
   .\.venv\Scripts\python.exe -m bandit -q -r sarevat
   .\.venv\Scripts\python.exe -m pip check
   ```

3. Confirma dirección IPv4, usuario, contraseña, secreto enable y acceso por
   consola. Las credenciales se piden al conectar y no se guardan en perfiles.
4. Inicia la app con `./.venv/Scripts/python.exe -m sarevat.cli` y guarda un
   perfil sin contraseñas si deseas reutilizar los datos de conexión.

## Orden de prueba recomendado

| Paso | Acción en SarevatApp | Criterio para continuar |
| --- | --- | --- |
| 1 | Conectar y elegir **Ver estado e inventario** | Modelo, versión e interfaces aparecen sin errores. |
| 2 | Usar **Revisión de seguridad** | Se genera el reporte de solo lectura. |
| 3 | Guardar **Referencia segura de configuración** | Se confirma que la referencia local se guardó. |
| 4 | Ejecutar un dry-run de NTP/syslog o endurecimiento básico | Los comandos y avisos son correctos para el equipo. |
| 5 | Aplicar solo un plan de bajo riesgo | Hay respaldo redactado, checkpoint y postcheck satisfactorio. |
| 6 | Ver cambios desde la referencia | Las diferencias coinciden con el único plan aplicado. |

Detente ante cualquier error de IOS, postcheck fallido, pérdida de sesión o
comando inesperado. No pruebes otro plan: conserva la evidencia y, si la app
ofrece rollback, restaura el checkpoint desde la consola.

## AAA y SNMPv3: al final del piloto

- **SNMPv3:** verifica primero el usuario y grupo previstos. La app no borra
  comunidades ni usuarios anteriores; revisa el dry-run y confirma que el NMS
  dispone de los nuevos datos antes de aplicar.
- **AAA:** úsalo únicamente después de validar los pasos anteriores. Debe
  existir el usuario local, la consola debe estar conectada y debes escribir
  `CONSOLA_LISTA`. Luego hay dry-run y dos confirmaciones. No cierres la sesión
  actual hasta abrir y validar una segunda sesión con el usuario local.

## Evidencia a registrar

Actualiza `LABORATORIO_COMPATIBILIDAD.md` con modelo, versión, licencia,
topología, planes probados, resultado de checkpoint/rollback y rutas de los
reportes redactados en `runtime/reports/`. Si algún comando no es aceptado, marca
la plataforma como **No compatible** o **En laboratorio**; no se debe forzar el
plan ni declararla certificada.
