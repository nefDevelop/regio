# Documentación Técnica de reGIO

**reGIO**  es un proxy inverso seguro escrito en Go que protege servicios internos mediante autenticación centralizada, control de acceso por IP, WAF y mitigación activa de ataques.

---

## Índice

1. [Arquitectura del Sistema](#1-arquitectura-del-sistema)
2. [Estructura del Proyecto](#2-estructura-del-proyecto)
3. [Modelo de Datos](#3-modelo-de-datos)
4. [Flujo de Autenticación](#4-flujo-de-autenticación)
5. [Seguridad en Capas](#5-seguridad-en-capas)
6. [API de Administración](#6-api-de-administración)
7. [CLI: Referencia Completa](#7-cli-referencia-completa)
8. [Variables de Entorno](#8-variables-de-entorno)
9. [Content Security Policy (CSP)](#9-content-security-policy-csp)
10. [Seguridad del Contenedor Docker](#10-seguridad-del-contenedor-docker)
11. [CI/CD](#11-cicd)
12. [Constantes de Seguridad](#12-constantes-de-seguridad)

---

## 1. Arquitectura del Sistema

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │                         INTERNET / RED PÚBLICA                      │
 └──────────────────────────┬──────────────────────────────────────────┘
                            │
                    ┌───────┴────────┐
                    │  Cloudflare /  │
                    │  Tailscale /   │  (opcional)
                    │  Nginx         │
                    └───────┬────────┘
                            │
 ┌──────────────────────────┴──────────────────────────────────────────┐
 │                         reGIO SERVER                                │
 │                                                                     │
 │  ┌──────────────────────────────────────────────────────────────┐   │
 │  │                    MainHandler (routing)                     │   │
 │  │                                                              │   │
 │  │  1. ¿Es CSP Report?         → HandleCSPReport()              │   │
 │  │  2. SecurityEngine()        → IP Block? Rate Limit? WAF?     │   │
 │  │  3. ¿Es static?             → ServeStatic()                  │   │
 │  │  4. ¿NeedsSetup?            → redirect /setup                │   │
 │  │  5. ¿Es /REGIO-login?       → HandleLogin()                  │   │
 │  │  6. ¿Tiene cookie válida?   → next                           │   │
 │  │  7. ¿Tiene API token?       → VerifyAppToken()               │   │
 │  │     (path/query/header/auth)                                 │   │
 │  │  8. ¿Tiene bypass token?    → CheckBypass()                  │   │
 │  │  9. ¿Es servicio público?   → allow                          │   │
 │  │  10. ProxyHandler()         → reverse proxy al backend       │   │
 │  └──────────────────────────────────────────────────────────────┘   │
 │                           │                                         │
 │  ┌────────────────────────┴──────────────────────────────────────┐  │
 │  │                   SecurityEngine                              │  │
 │  │                                                               │  │
 │  │   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    │  │
 │  │   │  IP Filter   │──▶│ Rate Limiter │──▶│     WAF      │    │  │
 │  │   │ (Fail2Ban)   │    │  100 req/min │    │ SQLi/XSS/PT  │    │  │
 │  │   └──────────────┘    └──────────────┘    └──────────────┘    │  │
 │  └───────────────────────────────────────────────────────────────┘  │
 │                           │                                         │
 │  ┌────────────────────────┴──────────────────────────────────────┐  │
 │  │                    ProxyHandler                               │  │
 │  │  ┌─────────────────────────────────────────────────────────┐  │  │
 │  │  │  proxyTransport (SafeDialContext)                       │  │  │
 │  │  │  • Valida DNS en tiempo real (anti-rebinding)           │  │  │
 │  │  │  • Bloquea IPs privadas (salvo whitelist)               │  │  │
 │  │  │  • Limpia headers de autenticación                      │  │  │
 │  │  │  • Timeouts: 10s headers, 5s handshake                  │  │  │
 │  │  └─────────────────────────────────────────────────────────┘  │  │
 │  └───────────────────────────────────────────────────────────────┘  │
 │                                                                     │
 │  ┌──────────────────────────────────────────────────────────────┐   │
 │  │  Background Goroutine (cada 10 min)                          │   │
 │  │  • LimpiarBloqueosExpirados()                                │   │
 │  │  • LimpiarRateLimiter()                                      │   │
 │  │  • LimpiarIntentosUsuario()                                  │   │
 │  │  • CleanupSessions() (sesiones > 7 días)                     │   │
 │  └──────────────────────────────────────────────────────────────┘   │
 │                                                                     │
 └──────────────────────────┬──────────────────────────────────────────┘
                            │
 ┌──────────────────────────┴──────────────────────────────────────────┐
 │                     SERVIDORES INTERNOS                             │
 │                                                                     │
 │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐     │
 │  │  Gitea   │  │  Grafana │  │  Jenkins │  │  Otros servicios │     │
 │  │ :3000    │  │ :3001    │  │ :8080    │  │  :XXXX           │     │
 │  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘     │
 │                                                                     │
 └─────────────────────────────────────────────────────────────────────┘
```

### Capas del Sistema

| Capa | Directorio | Responsabilidad |
|------|-----------|-----------------|
| **Entry Point** | `cmd/regio/` | Arranque, parsing de flags, servidor HTTP/TLS |
| **Routing** | `internal/handlers/` | `MainHandler`, lógica de negocio, templates HTML |
| **Seguridad** | `internal/security/` | WAF, Fail2Ban, rate limiting, SSRF, bypass tokens |
| **Autenticación** | `internal/auth/` | Argon2id, TOTP, AES-GCM, sesiones, app tokens |
| **Datos** | `internal/db/` | SQLite, migraciones, CRUD, logging de eventos |
| **Modelos** | `internal/models/` | Estructuras de datos compartidas |

---

## 2. Estructura del Proyecto

```
regio/
├── cmd/
│   ├── regio/
│   │   └── main.go              # Punto de entrada del servidor
│   └── seed/
│       └── main.go              # Generador de datos de prueba
├── internal/
│   ├── auth/
│   │   ├── auth.go              # Criptografía: Argon2id, TOTP, AES-GCM
│   │   └── auth_test.go         # Tests de autenticación
│   ├── db/
│   │   ├── db.go                # SQLite: init, CRUD, migraciones, eventos
│   │   ├── db_test.go           # Tests de base de datos
│   │   └── data/                # Directorio runtime (montado como volumen)
│   ├── handlers/
│   │   ├── handlers.go          # 1558 líneas — núcleo HTTP, routing, login,
│   │   │                          admin, profile, setup, proxy, CSP
│   │   ├── setup_test.go        # Helpers de test
│   │   ├── security_integration_test.go  # Tests integración CSRF
│   │   ├── tokens_test.go       # Tests autenticación por token
│   │   ├── static/              # Assets embedidos
│   │   │   ├── style.css        # CSS tema oscuro
│   │   │   ├── reGIO.svg        # Logo
│   │   │   └── qrcode.min.js    # QR para 2FA
│   │   └── templates/           # Templates HTML embedidos
│   │       ├── admin.html       # Panel de administración
│   │       ├── login.html       # Página de login
│   │       ├── profile.html     # Perfil de usuario y 2FA
│   │       ├── setup.html       # Wizard de instalación
│   │       └── setpassword.html # Establecer contraseña por invitación
│   ├── models/
│   │   └── models.go            # Config, User, AppToken, BannedIP, Event,
│   │                              BypassKey, CSPReport
│   └── security/
│       ├── engine.go            # SecurityEngine: orquestación de protecciones
│       ├── bypass.go            # Gestión de bypass tokens
│       ├── bypass_test.go       # Tests de bypass
│       ├── ip_filter.go         # Fail2Ban por IP y subred
│       ├── network.go           # SafeDialContext, validación IP
│       ├── network_test.go      # Tests de red/SSRF
│       ├── ratelimit.go         # Rate limiting por IP
│       ├── security_test.go     # Tests de seguridad integrados
│       ├── setup_test.go        # Helpers de test
│       ├── user_filter.go       # Rate limiting por username
│       └── waf.go               # Web Application Firewall
├── docs/
│   └── assets/
│       └── logo.svg             # Logo para README
├── .env.example                 # Plantilla de variables de entorno
├── .github/workflows/go.yml     # CI: build, vet, test, gosec
├── .gitleaks.toml               # Configuración Gitleaks
├── CONTRIBUTING.md              # Guía de contribución
├── Dockerfile                   # Build multi-etapa (Alpine, no-root)
├── LICENSE                      # MIT
├── Makefile                     # Build, test, seed, docker
├── README.md                    # Documentación principal
├── SECURITY.md                  # Política de vulnerabilidades
├── docker-compose.yml           # Despliegue Docker
├── go.mod / go.sum              # Dependencias Go
└── roadmap.md                   # Plan de desarrollo
```

---

## 3. Modelo de Datos

reGIO utiliza **SQLite** (mediante `modernc.org/sqlite`, sin CGO) como motor de base de datos. La base de datos se almacena en `REGIO_DB_PATH` (defecto: `./data/REGIO.db`) y se abre en modo WAL para mejor concurrencia de lectura.

### Diagrama Entidad-Relación

```
┌─────────────┐       ┌─────────────┐       ┌──────────────┐
│   users     │       │  sessions   │       │  app_tokens  │
├─────────────┤       ├─────────────┤       ├──────────────┤
│ id (PK)     │──┐    │ token (PK)  │       │ id (PK)      │
│ username    │  │    │ user_id(FK) │──┐    │ user_id(FK)  │──┐
│ password_   │  │    │ csrf_token  │  │    │ name         │  │
│ hash        │  │    │ remote_ip   │  │    │ token_hash   │  │
│ totp_secret │  │    │ user_agent  │  │    │ last_used    │  │
│ totp_active │  │    │ created_at  │  │    │ created_at   │  │
│ is_admin    │  │    │ expires_at  │  │    └──────────────┘  │
│ invite_token│  │    └─────────────┘  │                      │
│ created_at  │  │                     │                      │
└─────────────┘  │                     │                      │
                 │                     │                      │
┌──────────────┐ │                     │                      │
│ servicios    │ │                     │                      │
├──────────────┤ │                     │                      │
│ host (PK)    │ │                     │                      │
│ target_url   │ │                     │                      │
│ is_public    │ │                     │                      │
│ bypass_header│ │                     │                      │
│ csp          │ │                     │                      │
└──────────────┘ │                     │                      │
                 │                     │                      │
┌──────────────┐ │                     │                      │
│ banned_ips   │ │                     │                      │
├──────────────┤ │                     │                      │
│ ip (PK)      │ │                     │                      │
│ hasta        │ │                     │                      │
│ reason       │ │                     │                      │
└──────────────┘ │                     │                      │
                 │                     │                      │
┌──────────────┐ │                     │                      │
│ bypass_keys  │ │                     │                      │
├──────────────┤ │                     │                      │
│ token (PK)   │ │                     │                      │
│ name         │ │                     │                      │
│ host         │ │                     │                      │
│ created_at   │ │                     │                      │
└──────────────┘ │                     │                      │
                 │                     │                      │
┌──────────────┐ │                     │                      │
│ csp_reports  │ │                     │                      │
├──────────────┤ │                     │                      │
│ id (PK)      │ │                     │                      │
│ host         │ │                     │                      │
│ blocked_uri  │ │                     │                      │
│ violated_    │ │                     │                      │
│ directive    │ │                     │                      │
│ original_    │ │                     │                      │
│ policy       │ │                     │                      │
│ created_at   │ │                     │                      │
└──────────────┘ │                     │                      │
                 │                     │                      │
┌──────────────┐ │                     │                      │
│ events       │ │                     │                      │
├──────────────┤ │                     │                      │
│ id (PK)      │ │                     │                      │
│ timestamp    │ │                     │                      │
│ message      │ │                     │                      │
│ performer    │ │                     │                      │
└──────────────┘ │                     │                      │
                 │                     │                      │
┌──────────────┐ │                     │                      │
│ rate_limits  │ │                     │                      │
├──────────────┤ │                     │                      │
│ ip           │ │                     │                      │
│ timestamp    │ │                     │                      │
└──────────────┘ │                     │                      │
```

### Esquema SQL Detallado

#### `users`

| Columna | Tipo | Descripción |
|---------|------|-------------|
| `id` | INTEGER PK | ID autoincremental |
| `username` | TEXT UNIQUE | Nombre de usuario |
| `password_hash` | TEXT | Hash Argon2id de la contraseña |
| `totp_secret` | TEXT | Secreto TOTP cifrado con AES-256-GCM |
| `totp_active` | INTEGER | 0/1 — indica si 2FA está activo |
| `is_admin` | INTEGER | 0/1 — permisos de administrador |
| `invite_token` | TEXT | Token de invitación (SHA-256) para primer login |
| `created_at` | TEXT | Timestamp ISO 8601 |

#### `sessions`

| Columna | Tipo | Descripción |
|---------|------|-------------|
| `token` | TEXT PK | SHA-256 del token de sesión |
| `user_id` | INTEGER FK | Referencia a `users.id` |
| `csrf_token` | TEXT | Token CSRF persistente para formularios |
| `remote_ip` | TEXT | IP desde la que se inició sesión |
| `user_agent` | TEXT | User-Agent del cliente |
| `created_at` | TEXT | Timestamp de creación |
| `expires_at` | TEXT | Timestamp de expiración (+7 días) |

#### `app_tokens`

| Columna | Tipo | Descripción |
|---------|------|-------------|
| `id` | INTEGER PK | ID autoincremental |
| `user_id` | INTEGER FK | Referencia a `users.id` |
| `name` | TEXT | Nombre descriptivo del token |
| `token_hash` | TEXT | SHA-256 del token (nunca se almacena en plano) |
| `last_used` | TEXT NULL | Timestamp del último uso |
| `created_at` | TEXT | Timestamp de creación |

#### `servicios`

| Columna | Tipo | Descripción |
|---------|------|-------------|
| `host` | TEXT PK | Dominio público del servicio |
| `target_url` | TEXT | URL interna del servicio (ej: `http://10.0.0.5:8080`) |
| `is_public` | INTEGER | 0/1 — acceso sin autenticación |
| `bypass_header` | TEXT | Header y valor para bypass (ej: `X-Webhook-Key:abc`) |
| `csp` | TEXT | Content Security Policy para este servicio |

#### `banned_ips`

| Columna | Tipo | Descripción |
|---------|------|-------------|
| `ip` | TEXT PK | IP o subred bloqueada |
| `hasta` | TEXT | Timestamp de expiración del bloqueo |
| `reason` | TEXT | Motivo del bloqueo |

#### `bypass_keys`

| Columna | Tipo | Descripción |
|---------|------|-------------|
| `token` | TEXT PK | SHA-256 del bypass token (nunca se almacena en plano) |
| `name` | TEXT | Nombre descriptivo |
| `host` | TEXT | Host asociado |
| `created_at` | TEXT | Timestamp ISO 8601 |

#### `csp_reports`

| Columna | Tipo | Descripción |
|---------|------|-------------|
| `id` | INTEGER PK | ID autoincremental |
| `host` | TEXT | Host donde ocurrió la violación |
| `blocked_uri` | TEXT | URI del recurso bloqueado |
| `violated_directive` | TEXT | Directiva CSP violada |
| `original_policy` | TEXT | Política CSP original |
| `created_at` | TEXT | Timestamp ISO 8601 |

#### `events`

| Columna | Tipo | Descripción |
|---------|------|-------------|
| `id` | INTEGER PK | ID autoincremental |
| `timestamp` | TEXT | Timestamp ISO 8601 |
| `message` | TEXT | Descripción del evento |
| `performer` | TEXT | Usuario que realizó la acción |

#### `rate_limits`

| Columna | Tipo | Descripción |
|---------|------|-------------|
| `ip` | TEXT | Dirección IP |
| `timestamp` | TEXT | Timestamp de la petición |

---

## 4. Flujo de Autenticación

```
Petición entrante
       │
       ▼
┌─────────────────────────────┐
│ ¿Es /api/csp-report?        │──SÍ──▶ HandleCSPReport()
└─────────────────────────────┘
       NO
       ▼
┌─────────────────────────────┐
│ ¿IP bloqueada?              │──SÍ──▶ 403 Forbidden
│ (Fail2Ban individual/subred)│
└─────────────────────────────┘
       NO
       ▼
┌─────────────────────────────┐
│ ¿Rate limit excedido?       │──SÍ──▶ 429 Too Many Requests
│ (100 req/min por IP)        │
└─────────────────────────────┘
       NO
       ▼
┌─────────────────────────────┐
│ ¿Match WAF?                 │──SÍ──▶ 403 Forbidden
│ (SQLi, XSS, path traversal) │       + Evento de seguridad
└─────────────────────────────┘
       NO
       ▼
┌─────────────────────────────┐
│ ¿Es /static/*?              │──SÍ──▶ ServeStatic()
└─────────────────────────────┘
       NO
       ▼
┌─────────────────────────────┐
│ ¿NeedsSetup?                │──SÍ──▶ redirect /setup
└─────────────────────────────┘
       NO
       ▼
┌─────────────────────────────┐
│ ¿Es /REGIO-login?           │──SÍ──▶ HandleLogin()
└─────────────────────────────┘                             ┌─────────────────┐
       NO                                                   │ ¿Login exitoso? │──NO──▶ 401 + evento fallo
       ▼                                                    └────────┬────────┘
┌─────────────────────────────┐                                     SÍ
│ ¿Cookie de sesión?          │──SÍ──▶ Validar en DB                │
│ (REGIO_session)             │        │                             ▼
└─────────────────────────────┘        │                      Crear sesión + cookie
       NO                              VÁLIDA                  + CSRF token
       ▼                               │
┌─────────────────────────────┐        │
│ ¿API Token?                 │        │
│ ┌─ Path: /r-auth/TOKEN/...  │        │
│ ├─ Query: ?api_key=TOKEN    │        │
│ ├─ Header: X-API-Key        │        │
│ └─ Basic Auth               │        │
└─────────────────────────────┘        │
       NO                              │
       ▼                               │
┌─────────────────────────────┐        │
│ ¿Bypass Token?              │        │
│ (X-REGIO-Bypass)            │        │
└─────────────────────────────┘        │
       NO                              │
       ▼                               │
┌─────────────────────────────┐        │
│ ¿Servicio público?          │        │
└─────────────────────────────┘        │
       NO                              │
       ▼                               ▼
┌─────────────────────────────┐  ┌──────────────────┐
│ redirect /REGIO-login       │  │ ProxyHandler()   │
│ (o 401 si es API)           │  │ → Backend        │
└─────────────────────────────┘  └──────────────────┘
```

---

## 5. Seguridad en Capas

### 5.1 Web Application Firewall (WAF) — `internal/security/waf.go`

El WAF analiza cada petición y detecta:

| Ataque | Patrón detectado | Ejemplo |
|--------|-----------------|---------|
| **Path Traversal** | `../`, `..\\`, `%2e%2e/` | `GET /../../../etc/passwd` |
| **SQL Injection** | `' OR 1=1`, `UNION SELECT`, `'; DROP` | `GET /?id=1' OR '1'='1` |
| **XSS** | `<script>`, `onerror=`, `javascript:` | `GET /?q=<script>alert(1)</script>` |
| **Scanners** | User-Agent de herramientas de ataque | `nikto`, `sqlmap`, `acunetix` |

### 5.2 Fail2Ban — `internal/security/ip_filter.go`

| Tipo | Umbral | Duración | Persistencia |
|------|--------|----------|-------------|
| **IP individual** | 5 fallos | 15 minutos | SQLite |
| **Subred /24 o /64** | 15 fallos | 1 hora | SQLite |

### 5.3 Rate Limiting — `internal/security/ratelimit.go`

- **100 peticiones por minuto por IP**
- Datos persistidos en la tabla `rate_limits` de SQLite
- Sobrevive a reinicios del servidor
- Limpieza periódica de datos expirados (cada 10 min)

### 5.4 Anti-Botnet Distribuido — `internal/security/user_filter.go`

- **10 intentos fallidos de login por username** → bloqueo de 30 minutos
- Funciona independientemente de la IP de origen
- Previene ataques de fuerza bruta distribuidos (múltiples IPs, un usuario)

### 5.5 Protección SSRF — `internal/security/network.go`

La función `SafeDialContext` se usa como `DialContext` personalizado en el transporte HTTP del proxy:

```
Petición a backend
       │
       ▼
┌─────────────────────────────┐
│ Resolver DNS del target     │
│ (si es nombre de host)      │
└─────────────────────────────┘
       │
       ▼
┌─────────────────────────────┐
│ ¿IP en rango privado?       │──SÍ──▶ ¿Está en ALLOWED_NETWORKS
│ (127.0.0.0/8, 10.0.0.0/8,   │       o es target configurado?
│  172.16.0.0/12,             │           │
│  192.168.0.0/16,            │       SÍ ─┴─ NO
│  ::1, fe80::/10, fc00::/7)  │       ▼      ▼
└─────────────────────────────┘    Permitir  Bloquear
       │
       NO
       ▼
    Conectar
```

### 5.6 CSRF Protection

- Cada sesión tiene un token CSRF único almacenado en SQLite
- Los tokens sobreviven a reinicios del servidor (a diferencia de CSRFs en memoria)
- Verificación en todos los formularios POST del panel admin
- Se inyecta en los templates HTML via `{{.CSRFToken}}`

### 5.7 Cabeceras de Seguridad

Todas las respuestas HTTP incluyen:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Permissions-Policy: geolocation=(), microphone=(), camera=()
Referrer-Policy: no-referrer
```

---

## 6. API de Administración

### Endpoints Internos

| Ruta | Método | Descripción |
|------|--------|-------------|
| `/REGIO-login` | GET/POST | Login de usuario |
| `/setup` | GET/POST | Wizard de instalación inicial |
| `/admin` | GET | Dashboard de administración |
| `/admin?action=get_service_details&host=HOST` | GET | Detalles de un servicio (eventos, CSP reports, bypass keys) |
| `/profile` | GET/POST | Perfil de usuario, cambio de contraseña, 2FA, app tokens |
| `/logout` | POST | Cerrar sesión |
| `/api/csp-report` | POST | Endpoint CSP report-only |
| `/static/*` | GET | Archivos estáticos embebidos |
| `/*` (admin domain) | — | 404 |
| `/*` (otros hosts) | — | Proxy al backend configurado |

### Formularios del Panel Admin

| Acción | Método | Parámetros | Descripción |
|--------|--------|------------|-------------|
| Añadir/editar servicio | POST | `action=save`, `host`, `target`, `is_public`, `bypass_header`, `bypass_value`, `csp` | Guarda configuración de puente |
| Eliminar servicio | POST | `action=delete`, `host` | Elimina puente |
| Añadir usuario | POST | `action=add_user`, `username` | Crea usuario con invitación |
| Eliminar usuario | POST | `action=delete_user`, `user_id` | Elimina usuario |
| Bloquear IP | POST | `action=block_ip`, `ip` | Bloquea IP manualmente |
| Desbloquear IP | POST | `action=unblock_ip`, `ip` | Desbloquea IP |
| Generar bypass key | POST | `action=generate_bypass`, `host`, `name` | Crea bypass token |
| Revocar bypass key | POST | `action=revoke_bypass`, `token` | Elimina bypass token |
| Limpiar CSP reports | POST | `action=clear_reports` | Vacía tabla de reportes CSP |

---

## 7. CLI: Referencia Completa

### `list`

```bash
./REGIO list
```

Muestra todos los servicios configurados en formato tabla:

```
HOST                 TARGET                     PUBLIC   BYPASS           CSP
─────                ──────                     ──────   ──────           ───
app.io               http://10.0.0.5:8080       No                       default-src 'self'...
```

### `add`

```bash
./REGIO add --host HOST --target TARGET [flags]
```

| Flag | Obligatorio | Descripción |
|------|-------------|-------------|
| `--host` | **Sí** | Dominio público |
| `--target` | **Sí** | URL del backend interno |
| `--public` | No | Marca el servicio como público (sin autenticación) |
| `--bypass` | No | Header y valor para bypass (ej: `X-Key:Valor`) |
| `--csp` | No | Content Security Policy personalizada |

### `del`

```bash
./REGIO del --host HOST
```

### `rotate-key`

```bash
./REGIO rotate-key --old "CLAVE_ACTUAL" --new "CLAVE_NUEVA"
```

Re-cifra todos los secretos TOTP almacenados con la nueva clave maestra. Requiere la clave actual para descifrar y la nueva para cifrar.

---

## 8. Variables de Entorno

| Variable | Obligatoria | Defecto | Descripción |
|----------|:-----------:|---------|-------------|
| `ADMIN_DOMAIN` | **SÍ** | — | Dominio donde sirve el panel de administración |
| `MASTER_KEY` | **SÍ** | — | Clave AES-256-GCM para cifrar TOTP secrets (≥32 caracteres) |
| `TRUSTED_PROXIES` | No | — | IPs/CIDR separadas por coma autorizadas a enviar cabeceras de IP real |
| `ALLOWED_NETWORKS` | No | — | Rangos privados que el proxy puede contactar (ej: `10.0.0.0/8`) |
| `PORT` | No | `80` | Puerto de escucha HTTP |
| `PORT_TLS` | No | `443` | Puerto de escucha HTTPS |
| `TLS_CERT` | No | — | Ruta al archivo de certificado TLS |
| `TLS_KEY` | No | — | Ruta al archivo de clave TLS |
| `FORCE_HTTPS` | No | `false` | Redirigir todo el tráfico HTTP a HTTPS |
| `REGIO_DB_PATH` | No | `./data/REGIO.db` | Ruta al archivo de base de datos SQLite |

---

## 9. Content Security Policy (CSP)

### Política por Defecto

```
default-src 'self';
script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com;
style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com;
img-src 'self' data: https://cdn.simpleicons.org;
connect-src 'self' https://wttr.in;
font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com;
report-uri /api/csp-report
```

### Flujo Discover & Allow

1. El admin configura una CSP restrictiva para un servicio.
2. Cuando el servicio intenta cargar un recurso externo no permitido, el navegador bloquea el recurso y envía un reporte CSP a `/api/csp-report`.
3. Los reportes aparecen en el panel de administración con la URL bloqueada y la directiva violada.
4. El admin añade las URLs necesarias a la CSP del servicio correspondiente.

---

## 10. Seguridad del Contenedor Docker

El `Dockerfile` y `docker-compose.yml` implementan las siguientes medidas de hardening:

| Medida | Implementación |
|--------|---------------|
| **Multi-stage build** | Compilación en `golang:alpine`, ejecución en `alpine:latest` |
| **Usuario no-root** | `adduser -D -u 1000 regio` + `USER regio` |
| **Capabilities mínimas** | `cap_drop: ALL` + `cap_add: [CAP_NET_BIND_SERVICE]` |
| **No new privileges** | `security_opt: no-new-privileges:true` |
| **Read-only filesystem** | `read_only: true` + `tmpfs: /tmp` |
| **Binario sin simbolos** | `-ldflags="-s -w"` (stripped) |
| **Bind de puertos privilegiados** | `setcap 'cap_net_bind_service=+ep'` |
| **Healthcheck** | Cada 30s vía `wget` a `/REGIO-login` |
| **Límites de recursos** | CPU: 0.5 cores, RAM: 128MB |

---

## 11. CI/CD

### GitHub Actions — `.github/workflows/go.yml`

| Job | Acción |
|-----|--------|
| **Code Quality** | `go build ./...` + `go vet ./...` |
| **Tests + Race** | `go test -race -v ./...` con `MASTER_KEY` de test |
| **Security Scan** | `gosec -no-fail -fmt text ./...` |

### Workflow

```
Push / PR a main
       │
       ▼
┌─────────────────┐
│ Code Quality    │── Build + Vet
├─────────────────┤
│ Tests + Race    │── go test -race
├─────────────────┤
│ Security Scan   │── gosec
└─────────────────┘
       │
       ▼
     ✅ Todos pasan → merge seguro
```

---

## 12. Constantes de Seguridad

| Constante | Valor | Localización |
|-----------|-------|-------------|
| Rate limit | 100 req/min por IP | `ratelimit.go:11-12` |
| Fail2Ban individual | 5 fallos → 15 min bloqueo | `ip_filter.go:68-72` |
| Fail2Ban subred | 15 fallos → 1 h bloqueo | `ip_filter.go:82-89` |
| User rate limit | 10 fallos → 30 min bloqueo | `user_filter.go:14-15` |
| Duración de sesión | 7 días | `handlers.go:1551` |
| Máximo body de petición | 10 MB | `handlers.go:1223-1224` |
| CSP report body limit | 10 KB | `handlers.go:1152` |
| Máximo de eventos DB | 5000 (purga 500) | `db.go:373-376` |
| Intervalo de limpieza | 10 minutos | `main.go:173-181` |
| Response header timeout | 10 segundos | `handlers.go:59` |
| TLS handshake timeout | 5 segundos | `handlers.go:57` |

---

*Documentación generada a partir del análisis del código fuente. Última actualización: Junio 2026.*
