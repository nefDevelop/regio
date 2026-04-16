# Documentación Técnica de ReGiO (Reverse Gateway for Internal Operations)

ReGiO es un proxy inverso blindado diseñado para proteger servicios internos mediante autenticación centralizada, control de acceso por IP y mitigación de ataques.

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

> **Nota de Seguridad:** Se ha eliminado el soporte de tokens en la URL (`?api_key=...`) para evitar filtraciones en logs y el historial del navegador.

---

## 2. Seguridad y Protección de Red

ReGiO implementa varias capas de defensa activa:

### Fail2Ban Integrado
El sistema monitoriza intentos fallidos de login:
*   **Bloqueo Individual:** 5 intentos fallidos desde una IP resultan en un bloqueo de 15 minutos.
*   **Bloqueo de Rango (Subnet):** 15 intentos fallidos desde un mismo rango ( /24 en IPv4 o /64 en IPv6) resultan en un bloqueo de 1 hora para todo el rango.
*   **Persistencia:** Las IPs bloqueadas se guardan en la base de datos SQLite para mantener el bloqueo incluso tras un reinicio.

### Rate Limiting
Protección contra ataques de denegación de servicio (DoS) y fuerza bruta:
*   **Límite Global:** 100 peticiones por minuto por IP.
*   **Respuesta:** HTTP 429 (Too Many Requests).

### Hardening de Cabeceras
Cada respuesta servida por ReGiO incluye:
*   `X-Content-Type-Options: nosniff`
*   `X-Frame-Options: DENY` (Evita Clickjacking)
*   `X-XSS-Protection: 1; mode=block`
*   `Strict-Transport-Security (HSTS)`: 1 año.

---

## 3. Arquitectura y Almacenamiento

### Estructura de Datos
*   **Base de Datos:** SQLite (`data/regio.db`). Almacena usuarios, hashes de tokens (SHA-256), sesiones activas persistentes e historial de bloqueos.
*   **Configuración de Servicios:** `data/config.json`. Mapea dominios a URLs internas de backend.

### Flujo de Petición
1.  **Recepción:** Se obtiene la IP real (soporta Cloudflare via `CF-Connecting-IP`).
2.  **Validación de Red:** Chequeo de Rate Limit e IP Blacklist.
3.  **Auth Check:**
    *   Si existe Cookie de sesión: Valida contra `ActiveSessions` (memoria).
    *   Si no hay cookie: Busca `X-API-Key` o `Basic Auth`.
4.  **Routing:** Si es el dominio de administración, sirve el panel interno. Si es un dominio configurado, actúa como proxy.
5.  **Proxy:** Reescribe headers (`X-Forwarded-Host`) y limpia credenciales de ReGiO para no confundir al backend.

---

## 4. Gestión de App Tokens

Los App Tokens son la forma segura de dar acceso a servicios externos sin compartir la contraseña maestra del usuario.
*   **Un solo uso visual:** El token original solo se muestra una vez al crearlo.
*   **Almacenamiento Seguro:** ReGiO solo guarda el hash SHA-256 del token.
*   **Auditoría:** Cada token registra su fecha de último uso.

---

## 5. Requisitos del Entorno

*   **ADMIN_DOMAIN:** Variable de entorno obligatoria que define el dominio donde reside el panel de control.
*   **Puertos:** ReGiO escucha internamente en el puerto `80`. Se recomienda su despliegue tras un terminador SSL (como Caddy, Nginx o Cloudflare) para habilitar HTTPS.
