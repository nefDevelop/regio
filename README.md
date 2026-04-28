# reGIO: Reverse Proxy Seguro con Panel de Administración

**reGIO** es un proxy inverso blindado y ligero escrito en Go, diseñado para proteger servicios internos mediante autenticación centralizada, control de acceso por IP y mitigación activa de ataques. Ideal para usuarios de Cloudflare Tunnels (probado en el) en Tailscale Funnel o entornos de red privada tambien deberia funcionar.

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
./REGIO list                           # Ver servicios
./REGIO add --host app.io --target http://10.0.0.1:80 # Añadir
./REGIO del --host app.io              # Eliminar
```

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

## Guía de Autenticación para Aplicaciones

reGIO utiliza el header **`X-API-Key`** como método estándar para evitar conflictos con los sistemas de autenticación de los servicios finales (como Gitea o Jenkins).

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
MIT License. Hecho para la comunidad Self-Hosted con foco en la seguridad.
