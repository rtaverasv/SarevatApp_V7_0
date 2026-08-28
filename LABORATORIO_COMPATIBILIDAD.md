# Laboratorio y matriz de compatibilidad

## Propósito

Este protocolo convierte una prueba de laboratorio en evidencia trazable. La
aplicación puede generar planes para Cisco IOS/IOS-XE, pero no debe presentar un
modelo o una versión como certificados hasta completar una fila de esta matriz.

## Flujo de piloto seguro

1. Utiliza CML, EVE-NG, GNS3 o un equipo Cisco explícitamente autorizado y
   aislado de producción.
2. Registra modelo, imagen/versión, licencia y topología antes de conectar
   SarevatApp.
3. Ejecuta descubrimiento y un dry-run. Revisa los comandos antes de continuar.
4. Aplica **un plan por vez** con checkpoint habilitado y confirma que el
   postcheck aporta la evidencia esperada.
5. Fuerza un fallo controlado en un entorno de laboratorio y confirma el
   rollback. Nunca lo hagas en producción para “probar”.
6. Conserva la salida redactada, el resultado y cualquier variación de sintaxis
   observada; actualiza la fila correspondiente.

## Matriz inicial

| Plataforma | Modelo | Versión | Licencia | Servicios validados | Checkpoint/rollback | Estado | Evidencia |
| --- | --- | --- | --- | --- | --- | --- | --- |
| IOS | Pendiente | Pendiente | Pendiente | Pendiente | Pendiente | No certificado | Pendiente |
| IOS-XE | Pendiente | Pendiente | Pendiente | Pendiente | Pendiente | No certificado | Pendiente |

Estados permitidos:

- **No certificado:** no existe piloto registrado.
- **En laboratorio:** hay ejecución en curso, pero faltan escenarios o revisión.
- **Compatible con límites:** los servicios indicados pasaron en esa combinación
  concreta; documenta las restricciones.
- **No compatible:** se observó una diferencia que impide o vuelve inseguro el
  flujo; no generes el plan hasta corregirla.

## Escenarios mínimos por plataforma

| Área | Caso mínimo y evidencia esperada |
| --- | --- |
| Conexión | SSH y/o serial, descubrimiento de modelo, versión e interfaces. |
| Seguridad | Configuración inicial segura y confirmación de SSH v2/VTY. |
| Switching | VLAN de acceso, trunk y EtherChannel cuando aplique. |
| Routing IPv4 | Ruta estática, OSPF/BGP y DHCP relay cuando aplique. |
| Recuperación | Checkpoint creado, fallo controlado, rollback confirmado. |
| Límites | Comando no soportado o licencia ausente: fallo claro, sin éxito falso. |

## Criterio de salida de fase

La plataforma se marca como **Compatible con límites** solo cuando todas las
pruebas aplicables registran evidencia y no hay regresiones P0/P1. La matriz
no autoriza IPv6 ni fabricantes distintos de Cisco; ambos requieren iniciativas
separadas.
