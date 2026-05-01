<p align="center">
  <img src="docs/assets/logo.svg" alt="reGIO Logo" width="120">
</p>

# reGIO: Reverse Proxy Seguro con Panel de Administración

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/nef734/regio)](https://golang.org/)

**reGIO** es un proxy inverso y ligero escrito en Go, diseñado para proteger servicios internos mediante autenticación centralizada, control de acceso por IP y mitigación activa de ataques. Ideal para usuarios de Cloudflare Tunnels, Tailscale Funnel o entornos de red privada.

---

## Características Principales

- **Autenticación Blindada:** Sistema de sesiones persistentes con protección CSRF global.
- **Soporte para 2FA (TOTP):** Autenticación en dos pasos con secretos cifrados en reposo (AES-256-GCM).
- **Anti-Botnets (Rate-Limit por Usuario):** Bloqueo de cuentas tras múltiples intentos fallidos, incluso si el atacante usa múltiples IPs distribuidas.
- **Fail2Ban de Red:** Bloqueo automático de IPs y rangos (/24 o /64) para mitigar ataques coordinados.
- **Protección contra DNS Rebinding (TOCTOU):** Validación DNS en tiempo real en el `DialContext` del proxy para evitar el bypass de IPs privadas.
- **Configuración en DB & CLI:** La configuración de servicios reside en SQLite y se puede gestionar mediante una potente interfaz de línea de comandos.
- **Seguridad en Repositorio:** Ejecución como usuario no-root (`regio:1000`) y configuración con permisos restringidos.
- **Tests de Seguridad Integrados:** Suite de tests que valida protecciones contra SSRF, CSRF y Bypass.

---

## Gestión por Consola (CLI)

Puedes gestionar tus servicios sin entrar a la web:
```bash
./REGIO list                           # Ver servicios y sus CSPs
./REGIO add --host app.io --target http://10.0.0.1:80 --csp "default-src 'self'..." # Añadir/Actualizar
./REGIO del --host app.io              # Eliminar
```

---

## Gestión de Seguridad Avanzada (CSP)

reGIO incluye un sistema de **Content Security Policy (CSP)** dinámico:
- **Reportes en tiempo real**: Los bloqueos de recursos externos se muestran en el panel de administración.
- **Configuración por puente**: Cada servicio puede tener su propia política de seguridad.
- **Flujo Discover & Allow**: Copia las URLs bloqueadas desde la sección de reportes y añádelas a la CSP del puente correspondiente para permitir solo lo que el servicio necesita para funcionar.

---

## Ejecución de Tests de Seguridad

Para validar las protecciones en tu entorno:
```bash
make test
```
---

## Instalación y Despliegue

```bash
git clone https://github.com/nef734/regio.git
cd regio

# Configura tu entorno
cp .env.example .env
# Define ADMIN_DOMAIN, MASTER_KEY y TRUSTED_PROXIES
nano .env

# Despliega con Docker
docker compose up -d --build
```

---

### 1. Uso con Git (Recomendado)
Configura Git para enviar el token en la cabecera estándar de reGIO:

```bash
git config http.extraHeader "X-API-Key: TU_TOKEN_DE_REGIO"
```
Esto permite que `git push/pull` funcione sin interferir con las credenciales de tu servidor Git.

### 2. Uso con APIs y Scripts
El método recomendado es mediante cabeceras HTTP:

```bash
# Método Recomendado
curl -H "X-API-Key: TU_TOKEN" http://api.tudominio.com/data

# Fallback: Basic Auth (el token se usa como contraseña)
curl -u "usuario:TU_TOKEN" http://api.tudominio.com/data
```

### 3. Bypass Tokens (Para Robots y Webhooks)
Si necesitas que un servicio automático (GitHub, UptimeRobot, etc.) acceda sin autenticación, utiliza un **Bypass Token**:
1.  En el panel, pulsa el botón **Generar** junto al nuevo puente.
2.  reGIO creará un token seguro (ej: `rgbp_abcd...`).
3.  Configura tu servicio para que envíe la siguiente cabecera exacta:
    *   **Header:** `X-REGIO-Bypass`
    *   **Valor:** `TU_TOKEN_GENERADO`
4.  Cualquier petición con esta combinación saltará la pantalla de login. Puedes **revocar** el acceso en cualquier momento eliminando el puente o actualizándolo sin el token.

---

## Gestión de Usuarios

reGIO utiliza un sistema de **Invitaciones Seguras** para evitar el uso de contraseñas por defecto.

### 1. Primer Usuario (Setup)
Al instalar reGIO por primera vez, si la base de datos está vacía, al acceder a tu dominio administrativo serás redirigido a `/setup`. Aquí crearás la cuenta del administrador principal.

### 2. Añadir nuevos usuarios
1.  Entra al panel de administración.
2.  En la sección **"Gestión de Usuarios"**, escribe el nombre del nuevo usuario y pulsa "Añadir".
3.  reGIO generará un **Token de Invitación** único.
4.  Copia la URL de invitación que aparecerá en el **Registro de Eventos** (ej: `https://tu-admin.com/REGIO-login?invite=abc...`).
5.  Envía esa URL al usuario; él podrá establecer su contraseña y configurar su 2FA (TOTP) al acceder.

---

## Variables de Entorno Críticas

| Variable | Descripción | Ejemplo |
| :--- | :--- | :--- |
| `ADMIN_DOMAIN` | Dominio para el panel de control | `admin.regio.io` |
| `MASTER_KEY` | Clave para cifrar secretos TOTP | `clave_larga_y_secreta` |
| `TRUSTED_PROXIES` | IPs/Rangos en los que confiar cabeceras | `127.0.0.1,172.18.0.0/16` |

---

## Seguridad y Limpieza
Una vez validada la autenticación, reGIO **elimina automáticamente** las cabeceras `X-API-Key` y los datos de `Authorization` antes de pasar la petición al servicio final, garantizando que tus credenciales de acceso nunca se filtren al backend.

---

## Licencia
MIT License. Hecho para la comunidad Self-Hosted con un ojo en la seguridad.
