# Documentación Técnica de ReGiO (Reverse Gateway for Internal Operations)

ReGiO es un proxy inverso diseñado para proteger servicios internos mediante autenticación centralizada, control de acceso por IP y mitigación activa de ataques.

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
La función `SafeDialContext` (utilizada por el proxy) bloquea cualquier intento de conectar a:
*   Rangos de IP privados (RFC 1918), **a menos que estén autorizados**.
*   Interfaces de loopback y localhost.
*   Direcciones Link-local e IPv6 ULA.

**Autorización de IPs Privadas:**
ReGiO permite el acceso a IPs privadas en dos casos:
1.  **Automático:** Cualquier IP configurada como `target` de un servicio se añade automáticamente a la lista blanca al arrancar o al modificar el servicio.
2.  **Manual:** Mediante la variable de entorno `ALLOWED_NETWORKS`.

*   *Protección DNS:* El sistema resuelve dominios antes de conectar para verificar que no ocultan IPs restringidas (DNS Rebinding protection).

### Hardening de Cabeceras
Cada respuesta incluye: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block` y `Strict-Transport-Security`.

---

## 3. Cifrado y Persistencia

### Cifrado en Reposo (AES-256-GCM)
Los secretos TOTP (2FA) se almacenan cifrados en la base de datos utilizando AES-GCM con una clave maestra (`MASTER_KEY`). Esto impide que un robo de la base de datos comprometa los segundos factores de los usuarios.

### Sesiones Blindadas
*   **CSRF Persistente:** Los tokens CSRF se guardan en la base de datos vinculados a la sesión. Esto permite reiniciar el servidor sin invalidar los formularios abiertos de los usuarios.
*   **SameSite Strict:** Las cookies de sesión están configuradas como `SameSite: Strict` para máxima protección.
*   **Tokens Hasheados:** Los tokens de sesión se almacenan hasheados (SHA-256) en la base de datos para proteger contra robo de sesiones en caso de acceso al archivo de la DB.

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
*   **MASTER_KEY:** (**Obligatoria**) Clave para el cifrado AES de secretos TOTP. La aplicación no arrancará sin ella.
*   **TRUSTED_PROXIES:** Lista separada por comas de IPs o rangos CIDR autorizados para enviar cabeceras de IP real.
*   **ALLOWED_NETWORKS:** Lista separada por comas de IPs o rangos CIDR privados que ReGiO tiene permitido contactar (ej: `192.168.30.0/24, 10.0.0.1`).

---

## 7. Gestión por Consola (CLI)

ReGiO permite gestionar la configuración de los servicios directamente desde la terminal. Esto es útil para automatización o administración rápida sin usar la interfaz web.

### Comandos Disponibles

*   **Listar servicios:**
    ```bash
    ./REGIO list
    ```
    Muestra una tabla con todos los hosts configurados, sus destinos internos y si son públicos.

*   **Añadir o Actualizar un servicio:**
    ```bash
    ./REGIO add --host app.tudominio.com --target http://10.0.0.5:8080 [--public] [--bypass "X-My-Header:Value"]
    ```
    *   `--host`: El dominio público que escuchará ReGiO.
    *   `--target`: La dirección interna del servicio.
    *   `--public`: (Opcional) Si se incluye, el servicio no requerirá login para acceder.
    *   `--bypass`: (Opcional) Define un header necesario para saltar la autenticación (para webhooks, etc).

*   **Eliminar un servicio:**
    ```bash
    ./REGIO del --host app.tudominio.com
    ```

### Persistencia y Migración
La configuración ya no depende de un archivo JSON. Se almacena en la tabla `servicios` de la base de datos SQLite. Al arrancar por primera vez con la nueva versión, ReGiO migrará automáticamente cualquier `config.json` existente a la base de datos.
