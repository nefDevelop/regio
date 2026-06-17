<p align="center">
  <img src="docs/assets/logo.svg" alt="reGIO Logo" width="120">
</p>

<h1 align="center">reGIO</h1>
<p align="center"><strong>Reverse proxie in GO</strong></p>
<p align="center">Proxy inverso seguro escrito en Go — Autenticación centralizada, WAF, Fail2Ban y panel de administración.</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://golang.org/"><img src="https://img.shields.io/github/go-mod/go-version/nefDevelop/regio" alt="Go Version"></a>
  <a href="https://github.com/nefDevelop/regio/actions"><img src="https://img.shields.io/github/actions/workflow/status/nefDevelop/regio/go.yml?branch=main" alt="CI"></a>
</p>

---

## Índice

- [Características](#características)
- [Quick Start](#quick-start)
- [Variables de Entorno](#variables-de-entorno)
- [Gestión CLI](#gestión-cli)
- [Métodos de Autenticación](#métodos-de-autenticación)
- [Gestión de Usuarios](#gestión-de-usuarios)
- [Seguridad](#seguridad)
- [Desarrollo](#desarrollo)
- [Licencia](#licencia)

---

## Características

| Capa | Característica | Descripción |
|------|---------------|-------------|
| **Proxy** | Reverse Proxy | Enruta tráfico HTTP/HTTPS a servicios internos |
| **Proxy** | WebSockets | Soporte nativo para conexiones WebSocket |
| **Proxy** | SSRF Protection | `SafeDialContext` con validación DNS anti-rebinding |
| **Proxy** | Headers sanitizados | Limpieza automática de credenciales antes de proxy |
| **Auth** | Sesiones con CSRF | Tokens CSRF persistentes en DB (sobreviven reinicios) |
| **Auth** | 2FA (TOTP) | Autenticación en dos pasos con secretos cifrados AES-256-GCM |
| **Auth** | App Tokens | Múltiples métodos: header, query param, Basic Auth, path token |
| **Auth** | Bypass Tokens | Acceso sin autenticación para webhooks/bots via `X-REGIO-Bypass` |
| **Auth** | SSO | Inyección de `X-Forwarded-User` al backend |
| **Seguridad** | WAF Integrado | Detección de SQLi, XSS, path traversal y scanner User-Agents |
| **Seguridad** | Fail2Ban | Bloqueo por IP (5 fallos/15min) y por subred (15 fallos/1h) |
| **Seguridad** | Rate Limiting | 100 req/min por IP con persistencia en SQLite |
| **Seguridad** | Anti-Botnet | Rate limiting por username (10 fallos → 30min bloqueo) |
| **Seguridad** | CSP Dinámico | Políticas por servicio con panel de reportes |
| **Seguridad** | HTTPS/TLS | TLS nativo con redirección automática HTTP→HTTPS |
| **Admin** | Panel Web | Dashboard completo: puentes, usuarios, IPs, sesiones, CSP |
| **Admin** | CLI | `list`, `add`, `del`, `rotate-key` |
| **Admin** | Invitaciones | Onboarding seguro con tokens de invitación de un solo uso |
| **Admin** | Auditoría | Log inmutable de eventos con anti-flood |

---

## Quick Start

```bash
git clone https://github.com/nefDevelop/regio.git
cd regio

cp .env.example .env
# Edita .env: ADMIN_DOMAIN, MASTER_KEY (mín. 32 caracteres)
nano .env

docker compose up -d --build
```

Accede a `http://tudominio:9999/setup` para crear el administrador inicial.

> ⚠️ **MASTER_KEY**: Genera una clave segura con `openssl rand -base64 32`.  
> La clave del `Makefile` es **solo para tests**. Nunca la uses en producción.

### Sin Docker

```bash
make build
ADMIN_DOMAIN=admin.tudominio.com MASTER_KEY="$(openssl rand -base64 32)" ./REGIO
```

---

## Variables de Entorno

| Variable | Obligatoria | Defecto | Descripción |
|----------|-------------|---------|-------------|
| `ADMIN_DOMAIN` | **Sí** | — | Dominio del panel de administración |
| `MASTER_KEY` | **Sí** | — | Clave AES-256 para cifrar secretos TOTP (≥32 caracteres) |
| `TRUSTED_PROXIES` | No | — | IPs/CIDR separadas por coma que pueden enviar cabeceras de IP real |
| `ALLOWED_NETWORKS` | No | — | Rangos privados permitidos (ej: `10.0.0.0/8`) |
| `PORT` | No | `80` | Puerto HTTP |
| `PORT_TLS` | No | `443` | Puerto HTTPS |
| `TLS_CERT` | No | — | Ruta al certificado TLS |
| `TLS_KEY` | No | — | Ruta a la clave TLS |
| `FORCE_HTTPS` | No | `false` | Redirección forzosa a HTTPS |
| `REGIO_DB_PATH` | No | `./data/REGIO.db` | Ruta a la base de datos SQLite |

---

## Gestión CLI

```bash
# Listar servicios configurados
./REGIO list

# Añadir o actualizar un servicio
./REGIO add --host app.io --target http://10.0.0.1:80 [--public] [--bypass "X-Header:Value"] [--csp "default-src 'self'"]

# Eliminar un servicio
./REGIO del --host app.io

# Rotar la clave maestra (re-cifra todos los secretos TOTP)
./REGIO rotate-key --old "key_actual" --new "nueva_key"
```

---

## Métodos de Autenticación

### App Tokens (para APIs y scripts)

Genera tokens desde el panel de perfil de usuario. Cuatro formas de usarlos:

```bash
# Header (recomendado)
curl -H "X-API-Key: tu_token" https://api.tudominio.com/data

# Query param
curl "https://api.tudominio.com/data?api_key=tu_token"

# Path token
curl "https://api.tudominio.com/r-auth/tu_token/data"

# Basic Auth (el token como contraseña)
curl -u "cualquier:tu_token" https://api.tudominio.com/data
```

> reGIO elimina automáticamente las cabeceras de autenticación antes de reenviar al backend.

### Git con reGIO

```bash
git config http.extraHeader "X-API-Key: TU_TOKEN_DE_REGIO"
```

### Bypass Tokens (para webhooks/robots)

Ideal para GitHub Webhooks, UptimeRobot, etc.:

1. En el panel admin, pulsa **Generar** junto al puente.
2. Recibirás un token `rgbp_...`.
3. El servicio remoto envía: `X-REGIO-Bypass: rgbp_...`
4. La petición salta la autenticación. Revocable en cualquier momento.

---

## Gestión de Usuarios

### Primer usuario (Setup)

Al acceder al dominio admin con la DB vacía, reGIO redirige a `/setup` para crear la cuenta de administrador.

### Invitaciones

1. En el panel, sección **Gestión de Usuarios**, añade un nombre.
2. reGIO genera un token de invitación único.
3. Envía al usuario la URL: `https://tu-admin.com/REGIO-login?invite=TOKEN`
4. El usuario establece su contraseña y puede configurar 2FA TOTP.

---

## Seguridad

### Pipeline de Protección (por petición)

```
Cliente → SecurityEngine → Auth → Proxy → Backend
               │              │
         ┌─────┴──────┐  ┌────┴────┐
         │ IP Block?  │  │ Cookie? │
         │ Rate Limit?│  │ Token?  │
         │ WAF?       │  │ Bypass? │
         └────────────┘  │ Public? │
                         └─────────┘
```

- **IP/Subnet blocking**: 5 fallos → 15 min bloqueo individual; 15 fallos → 1h bloqueo de /24
- **Rate limiting**: 100 peticiones/minuto por IP (persistido en SQLite)
- **User rate limiting**: 10 fallos de login por username → 30 min bloqueo (anti-botnet distribuido)
- **WAF**: Detecta path traversal (`../`, `..\\`), SQL injection (`' OR 1=1--`, `UNION SELECT`), XSS (`<script>`, `onerror=`) y User-Agent de scanners
- **SSRF Protection**: Validación DNS en tiempo real en `DialContext` — bloquea loopback, link-local, RFC 1918 (salvo autorización explícita)
- **Fail2Ban**: Persistente en SQLite, sobrevive reinicios del servidor
- **CSRF**: Tokens por sesión almacenados en DB, sobreviven reinicios
- **Cabeceras de seguridad**: HSTS, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Permissions-Policy, Referrer-Policy

### CSP (Content Security Policy)

Cada servicio puede tener su propia política CSP. Las violaciones se reportan al panel de administración, permitiendo un flujo **Discover & Allow**:

1. El servicio opera con una CSP restrictiva.
2. Los recursos bloqueados aparecen en el panel de reportes.
3. El admin copia las URLs bloqueadas y las añade a la CSP del puente.

---

## Desarrollo

```bash
make build          # Compilar el binario
make test           # Ejecutar tests
make test-race      # Tests con detector de race conditions
make audit          # go vet + gosec
make seed           # Generar DB de prueba en /tmp
make run-dbtest     # Ejecutar con datos de prueba (puerto 9090)
make docker-build   # Construir imagen Docker
```

### Tests

El proyecto incluye **8 suites de tests** que cubren:

- Cifrado/descifrado AES-GCM y Argon2id
- CRUD de configuración en SQLite
- Fail2Ban (individual y por subred)
- WAF (path traversal, SQLi, XSS)
- SSRF / `SafeDialContext`
- Bypass tokens
- CSRF en handlers HTTP
- Autenticación por token (path, query, header, Basic Auth)

```bash
make test           # go test -v ./...
make test-race      # go test -race -v ./...
```

---

## Licencia

MIT License. Hecho para la comunidad Self-Hosted con un ojo en la seguridad.

---

<p align="center">
  <a href="DOCUMENTATION.md">Documentación Técnica</a> ·
  <a href="CONTRIBUTING.md">Contribuir</a> ·
  <a href="SECURITY.md">Reportar Vulnerabilidad</a> ·
  <a href="roadmap.md">Roadmap</a>
</p>
