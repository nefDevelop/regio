# Documentación Técnica de ReGiO (Reverse Gateway for Internal Operations)

ReGiO es un proxy inverso blindado diseñado para proteger servicios internos mediante autenticación centralizada, control de acceso por IP y mitigación activa de ataques.

---

## 1. Métodos de Autenticación para APIs

Para conectar aplicaciones o scripts a servicios protegidos por ReGiO, existen dos métodos soportados. Ambos métodos son validados contra los **App Tokens** generados en el panel de control del usuario.

### A. Header X-API-Key (Recomendado)
Es el método más limpio y evita conflictos con la autenticación propia del servicio final (ej. Gitea, Jenkins).
*   **Header:** `X-API-Key`
*   **Valor:** `TU_APP_TOKEN_AQUÍ`
*   **Comportamiento:** ReGiO valida el token y **elimina** este header antes de reenviar la petición al backend para mantener la privacidad.

### B. Autenticación Básica (Basic Auth)
Útil para clientes que no permiten headers personalizados pero sí autenticación estándar.
*   **Usuario:** (Cualquiera, ReGiO lo ignora)
*   **Contraseña:** `TU_APP_TOKEN_AQUÍ`
*   **Comportamiento:** ReGiO intercepta la autenticación básica, valida el token y limpia el header `Authorization` antes de pasar la petición al backend.

---

## 2. Seguridad y Protección de Red

### Fail2Ban Integrado
Monitoriza intentos fallidos de login:
*   **Bloqueo Individual:** 5 intentos fallidos resultan en un bloqueo de 15 minutos.
*   **Bloqueo de Rango (Subnet):** 15 intentos fallidos desde un mismo rango (/24 en IPv4 o /64 en IPv6) resultan en un bloqueo de 1 hora.

### Validación de IPs de Confianza (Antispoofing)
ReGiO no confía ciegamente en cabeceras como `CF-Connecting-IP`. Solo se leen estas cabeceras si la petición proviene de una IP autorizada en la variable `TRUSTED_PROXIES`.

### Protección SSRF Avanzada
La función `isValidTarget` bloquea cualquier intento de apuntar el proxy a:
*   Rangos de IP privados (RFC 1918).
*   Interfaces de loopback y localhost.
*   Direcciones Link-local e IPv6 ULA.
*   *Protección DNS:* El sistema resuelve dominios antes de conectar para verificar que no ocultan IPs restringidas.

### Hardening de Cabeceras
Cada respuesta incluye: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block` y `Strict-Transport-Security`.

---

## 3. Cifrado y Persistencia

### Cifrado en Reposo (AES-256-GCM)
Los secretos TOTP (2FA) se almacenan cifrados en la base de datos utilizando AES-GCM con una clave maestra (`MASTER_KEY`). Esto impide que un robo de la base de datos comprometa los segundos factores de los usuarios.

### Sesiones Blindadas
*   **CSRF Persistente:** Los tokens CSRF se guardan en la base de datos vinculados a la sesión. Esto permite reiniciar el servidor sin invalidar los formularios abiertos de los usuarios.
*   **SameSite Strict:** Las cookies de sesión están configuradas como `SameSite: Strict` para máxima protección.

---

## 4. Gestión de Usuarios e Invitaciones

### Invitaciones Seguras
Al crear un usuario, el administrador obtiene un **Token de Invitación** único. El nuevo usuario debe acceder mediante una URL especial (`?invite=TOKEN`) para establecer su contraseña por primera vez. Esto evita el secuestro de cuentas recién creadas mediante enumeración de nombres.

### Auditoría Inalterable
El registro de eventos es permanente y no puede ser eliminado desde el panel de control, garantizando que todas las acciones administrativas dejen un rastro de auditoría confiable.

---

## 5. Arquitectura de Proxy

ReGiO utiliza un transporte HTTP personalizado para sus operaciones de proxy:
*   **Timeouts Estrictos:** Timeout de 10 segundos para cabeceras de respuesta y 5 segundos para conexión inicial.
*   **Limpieza de Credenciales:** El gateway asegura que ningún dato de autenticación propio de ReGiO llegue al backend, eliminando headers de identificación antes de completar el proxy.

---

## 6. Variables de Entorno

*   **ADMIN_DOMAIN:** Dominio donde reside el panel administrativo.
*   **MASTER_KEY:** Clave de 32 bytes (o cadena hasheada) para el cifrado AES.
*   **TRUSTED_PROXIES:** Lista separada por comas de IPs o rangos CIDR autorizados.
