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
| **Seguridad** | Geobloqueo GeoIP | Filtrado por país (allow/deny) con BD local `.mmdb`, global o por servicio |
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
| `GEO_MODE` | No | `off` | Geobloqueo global: `off`, `allow` (solo países listados) o `deny` (bloquea los listados) |
| `GEO_COUNTRIES` | No | — | Países ISO alpha-2 separados por coma (ej: `ES, FR`) |
| `GEO_FAIL_MODE` | No | `open` | Si no se determina el país: `open` (permitir) o `closed` (bloquear) |
| `GEOIP_DB_PATH` | No | `./data/GeoLite2-Country.mmdb` | BD GeoIP de países (GeoLite2 de MaxMind o DB-IP Lite, formato `.mmdb`) |

> 🌍 **Geobloqueo**: descarga `GeoLite2-Country.mmdb` ([MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data), requiere cuenta) o
> [`dbip-country-lite.mmdb.gz`](https://db-ip.com/db/ip/ip-dbip-country-lite.mmdb.gz) (sin registro), descomprímela en `./data/` y configura
> `GEO_MODE=allow` + `GEO_COUNTRIES=ES` (solo España) o `GEO_MODE=deny` + `GEO_COUNTRIES=IN` (todo salvo India).
> La política también se gestiona desde el panel admin → «Filtrado por País (GeoIP)», que sobrescribe estas variables.

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
         │ GeoIP?     │  │ Cookie? │
         │ IP Block?  │  │ Token?  │
         │ Rate Limit?│  │ Bypass? │
         │ WAF?       │  │ Public? │
         └────────────┘  └─────────┘
```

- **Geobloqueo por país**: lista blanca (`allow`, ej: solo España) o lista negra (`deny`, ej: todo menos India) sobre una BD GeoIP local; configurable como política global y por servicio, con fail-open/fail-closed elegible en el panel
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
make seed           # Generar DB de prueba en /tmp
make run-dbtest     # Ejecutar con datos de prueba (puerto 9090)
make docker-build   # Construir imagen Docker
make audit          # go vet + gosec (falla ante hallazgos fuera del baseline)
make help           # Lista completa de targets
```

### Tests

Todo se orquesta vía `make` (punto de entrada único):

| Comando | Qué hace |
|---------|----------|
| `make test` | **Puerta principal**: unitarios rápidos (`-short`) + suite completa con **gate de cobertura** por umbrales |
| `make test-unit` | Suite en modo `-short` (sin integración pesada: backends/Argon2) |
| `make test-integration` | Suite completa in-process (DB, proxy, auth) |
| `make test-contract` | Solo matrices de contrato y caracterización (red de seguridad de refactorizaciones) |
| `make test-cover` | Suite completa + perfil de cobertura + gate (`scripts/cover_gate.sh`) |
| `make test-race` | Detector de race conditions |
| `make test-e2e` | E2E contra el **binario real** (`-tags e2e`): setup→login→admin→proxy, geobloqueo, CLI, graceful shutdown |
| `make test-smoke` | Subconjunto E2E rápido (smoke + CLI) |
| `make test-fuzz` | Fuzzing nativo de Go (WAF, parsers) con budget de tiempo |
| `make bench` | Benchmarks de los caminos calientes |
| `make ci` | Exactamente lo que ejecuta CI: test + race + e2e + audit |

**Gate de cobertura**: global ≥70% y por paquete (auth/db/handlers/security ≥83–85%,
`cmd/` excluido porque lo cubre el e2e) — umbrales en `scripts/cover_gate.sh`;
si un porcentaje baja, `make test` falla.

**Áreas cubiertas**: cifrado AES-GCM y Argon2id (incl. compatibilidad de hashes
legacy), SQLite y migraciones de esquema, Fail2Ban, WAF, SSRF, bypass tokens,
CSRF, app tokens, **geobloqueo GeoIP**, matriz de routing/autorización (23
casos), contrato de las **12 acciones del panel**, contrato dual del proxy
(saneo de credenciales, cookies y mensajes 404), login/2FA/invitaciones con
**anti-replay TOTP**, ciclo de sesiones, y E2E del binario real (incl.
apagado ordenado con SIGTERM).

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
