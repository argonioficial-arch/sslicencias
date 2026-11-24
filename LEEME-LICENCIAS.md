# Sistema de licencias · Radio RP (V1, V2, V3)

## Arquitectura
- Supabase (proyecto `czsxxznvhxkxapxlygyo`): tablas `licenses`, `serial_batches`, `serial_numbers`, `devices`, `license_devices`, `users`, `license_users`, `admins`, `device_sessions`, `license_audit_logs`, `rate_limits`, `license_config`. RLS activo; la lógica está en funciones SQL `lic_*` (solo service_role).
- 10 Edge Functions: device-register, user-register, device-authenticate, activate-serial, license-validate, device-heartbeat, device-deactivate, user-deactivate, generate-serial-batch, admin-manage. Código en `functions/`.
- Cliente (`client/`, ya copiado en `app/` de las 3 radios): identidad Ed25519 del equipo (clave privada cifrada con safeStorage), hash de hardware, clave pública del servidor fijada, detección de reloj manipulado, gracia offline de 24 h con autorización firmada por el servidor, latido cada 15 min y bloqueo inmediato si se revoca.
- Series: formato `RAD-XXXX-XXXX-XXXX`, se guardan con hash HMAC, un solo uso, estados available/reserved/activated/blocked/revoked. Los códigos se muestran UNA vez al generarlos.

## Panel de administración
Abre `panel/index.html` en el navegador. Primer uso: formulario "Bootstrap" con el token de instalación (un solo uso) + tu correo y contraseña (mín. 10). Después: Estadísticas, Licencias, Series (generar lotes ≤200), Radios, Usuarios, Auditoría.

## Pantallas de error del cliente
Licencia no encontrada, serie inválida, serie usada, suspendida, caducada, límite de radios, usuario no autorizado, límite de usuarios, equipo bloqueado, sin conexión.

## Qué se probó (y qué no)
Probado: funciones SQL, las Edge Functions con llamadas reales firmadas, rate limiting, anti-clonado por secuencia, panel con Playwright (rutas simuladas), lógica del gate con Electron simulado, sintaxis de las 3 apps, guías V2/V3 en navegador.
NO probado: ejecución real en Electron/Windows, DPAPI real, instalador, atajos globales, concurrencia real.

## Pendiente por tu parte
1. Dashboard Supabase > Auth > activar "Leaked password protection".
2. Limpiar datos de prueba: licencias LIC-T001/T002 (suspendidas), usuarios u1/u2@test.local, dispositivos de prueba.
3. Los `index.html` de una sola página (vista previa) NO llevan licencia; solo las apps Electron.
