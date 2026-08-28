# SarevatApp 7.0

SarevatApp 7.0 es una reestructuracion segura y modular de la aplicacion de administracion Cisco. La
version original `D:\Downloads\SarevatApp_V6_4.py` se conserva intacta.

## Alcance

- Cisco IOS/IOS-XE mediante SSH o consola serial.
- Planificacion y asignacion VLSM exclusivamente IPv4.
- 23 planes de protocolos y servicios.
- Dry-run obligatorio antes de ofrecer una aplicacion real.
- Deteccion de errores devueltos por IOS.
- Checkpoint en flash, respaldo local redactado, postchecks y rollback confirmado.
- Auditoria JSONL con secretos redactados.
- Ping sweep y escaneo TCP IPv4 con limites, autorizacion y estados diferenciados.
- Sin soporte IPv6 por decision de alcance.

## Ejecucion

```powershell
cd C:\ruta\a\SarevatApp_V7_0
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python .\SarevatApp_V7_0.py
```

La aplicacion crea `runtime\` solamente al ejecutarse. Alli guarda logs, respaldos redactados y reportes.

También puedes instalar el comando `sarevat` con `python -m pip install .` y
ejecutarlo desde la terminal. El menú y las protecciones de seguridad son los
mismos en ambas formas de inicio.

## Inventario y perfiles

La opción **4) Inventario y perfiles** permite guardar el nombre del equipo,
su tipo, IPv4 o puerto serial y el usuario habitual. Al conectar desde un
perfil, SarevatApp actualiza el modelo, versión y último momento en que fue
visto.

Las contraseñas y el enable secret **no se guardan**: la aplicación los pide
solo cuando vas a conectar. El inventario queda en `runtime/inventory.json`,
que se mantiene local y fuera de Git.

Cuando preparas un servicio, VLSM o la configuración inicial, SarevatApp guarda
una vista segura del plan en `runtime/drafts.json`. Puedes verla o eliminarla
desde **Inventario y perfiles > 5) Ver borradores seguros**. Estos borradores
ocultan secretos y sirven para revisar o documentar; no aplican comandos por sí
solos.

## Pruebas

```powershell
python -m pip install -r requirements-dev.txt
.\scripts\validar_calidad.ps1
```

Si tu entorno virtual usa otro intérprete, indícalo sin cambiar el script:
`.\scripts\validar_calidad.ps1 -Python .\.venv\Scripts\python.exe`.

## Flujo seguro de configuracion

1. Descubrir inventario, version y configuracion actual.
2. Validar los datos y generar un `CommandPlan`.
3. Mostrar comandos con secretos ocultos.
4. Ejecutar dry-run sin enviar configuracion.
5. Solicitar confirmacion explicita.
6. Guardar respaldo local redactado.
7. Crear checkpoint `flash:sarevat_<id>.cfg` en el equipo.
8. Enviar comandos con patron de errores IOS.
9. Ejecutar postchecks.
10. Si falla, ofrecer rollback desde el checkpoint y volver a solicitar confirmacion.

## Limites de las pruebas actuales

Las conexiones SSH y serial se probaron con dobles simulados de Netmiko. Para certificar compatibilidad
operativa por modelo y version se necesita un laboratorio Cisco CML, EVE-NG, GNS3 o hardware autorizado.
Algunos comandos y postchecks pueden variar entre IOS, IOS-XE, Catalyst y licencias; el comportamiento
fail-fast los bloqueara en lugar de declarar un exito falso.
