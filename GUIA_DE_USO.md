# Guía de uso de SarevatApp 7.0

SarevatApp administra equipos Cisco IOS/IOS-XE por SSH o consola serial. Esta
versión trabaja solo con IPv4.

## 1. Abrir la app

Desde la carpeta del proyecto:

```powershell
.\.venv\Scripts\python.exe .\SarevatApp_V7_0.py
```

Si aún no existe el entorno virtual:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe .\SarevatApp_V7_0.py
```

Menú principal:

| Número | Acción |
| --- | --- |
| 1 | Conectar a equipo Cisco. |
| 2 | Planificar VLSM IPv4. |
| 3 | Usar el escáner IPv4 autorizado. |
| 4 | Abrir inventario y perfiles. |
| 0 | Salir. |

**Navegación:** escribe el número y presiona Enter. En todos los submenús,
`0` vuelve al nivel anterior. Dentro de un equipo, `0` desconecta y regresa al
menú principal.

## 2. Conectar por primera vez

1. Elige **1) Conectar a equipo Cisco**.
2. Elige **1) SSH** o **2) Consola serial**.
3. Para SSH, escribe tipo de equipo, IPv4, usuario, contraseña y, si aplica,
   secreto enable. Para serial, escribe tipo, puerto, por ejemplo `COM3`, y
   velocidad, normalmente `9600`.
4. Al entrar, usa primero **1) Ver estado e inventario**. Comprueba el modelo,
   versión e interfaces antes de cambiar algo.

Las contraseñas se solicitan al conectar y no se guardan en el inventario.

## 3. Navegación dentro de un equipo

| Número | Para qué sirve |
| --- | --- |
| 1 | Ver estado, modelo, versión e interfaces. Úsala primero. |
| 2 | Preparar protocolos y servicios, como VLAN, rutas, DHCP, OSPF o NTP. |
| 3 | Calcular VLSM IPv4 y preparar interfaces. |
| 4 | Escribir comandos manuales en consola libre. |
| 5 | Preparar configuración inicial segura. |
| 6 | Guardar con `write memory` después de validar. |
| 7 | Comparar la configuración del equipo con un archivo local. |
| 8 | Revisar seguridad en modo solo lectura. |
| 9 | Preparar NTP y syslog juntos. |
| 10 | Añadir SNMPv3 sin borrar usuarios o comunidades existentes. |
| 11 | Preparar AAA local con recuperación por consola. |
| 12 | Guardar una referencia local redactada de la configuración. |
| 13 | Ver cambios frente a esa referencia. |
| 14 | Preparar SSH v2 y cifrado de contraseñas si faltan. |
| 0 | Desconectar. |

## 4. Qué ocurre al configurar

Para servicios, VLSM, NTP/syslog, SNMPv3, AAA y endurecimiento:

1. Escribe los datos solicitados. Las claves se escriben ocultas.
2. Revisa la vista previa; los secretos aparecen ocultos.
3. La app ejecuta un **dry-run**: aún no modifica el equipo.
4. Si el resultado es correcto, responde `si`.
5. Escribe `CONFIRMAR` cuando lo pida.
6. La app crea respaldo local redactado, checkpoint y postchecks.
7. Si falla un comando o una comprobación, detente. Confirma el rollback solo
   si corresponde.

Después de aplicar un plan, usa **13) Ver cambios desde la referencia**. Usa
**6) Guardar configuración** únicamente si el resultado es correcto.

## 5. Orden recomendado en una prueba real

1. Conecta y usa **1) Ver estado e inventario**.
2. Ejecuta **8) Revisión de seguridad**; no cambia nada.
3. Usa **12) Guardar referencia segura**.
4. Haz dry-run de un plan de bajo riesgo, como NTP/syslog o endurecimiento.
5. Aplica un solo plan y revisa su resultado.
6. Usa **13) Ver cambios desde la referencia**.
7. Guarda la configuración con **6)** solo si todo está correcto.
8. Deja SNMPv3 y AAA para el final.

Para el piloto Cisco, sigue también [PRUEBA_REAL_11AM.md](PRUEBA_REAL_11AM.md).

## 6. AAA y SNMPv3 sin perder acceso

### SNMPv3

- Confirma grupo, usuario y datos de tu sistema de monitoreo.
- Revisa el dry-run antes de aplicar.
- La app no elimina comunidades ni usuarios SNMP existentes.
- Prueba el monitoreo nuevo antes de retirar una configuración anterior.

### AAA local

- Verifica que el usuario local exista.
- Mantén una consola local conectada y funcional.
- Escribe `CONSOLA_LISTA` solo si la consola está lista.
- AAA requiere dry-run, confirmación normal y segunda confirmación.
- Antes de desconectarte, abre otra sesión y confirma el acceso.

## 7. Inventario, grupos y borradores

En **4) Inventario y perfiles** puedes ver, crear, conectar o eliminar
perfiles. Al crearlo puedes añadir grupos como `Core, Laboratorio`. La opción
**6) Ver equipos de un grupo** los filtra sin conectarlos.

La opción **5) Ver borradores seguros** muestra o elimina vistas redactadas de
planes preparados. Los perfiles no guardan contraseñas.

## 8. VLSM, escáner y resultados

- En el menú principal, **2) Planificar VLSM IPv4** calcula subredes y permite
  exportar JSON y CSV.
- **3) Escáner IPv4** permite ping sweep o revisar puertos TCP. Úsalo solo en
  redes autorizadas.
- `runtime/reports/` contiene reportes; `runtime/backups/`, respaldos
  redactados; `runtime/logs/`, eventos; `runtime/inventory.json` y
  `runtime/drafts.json`, los datos locales.

Ante un error de IOS, una sesión caída o un cambio inesperado, no continúes con
otro plan. Guarda la evidencia y revisa el equipo desde la consola local.
