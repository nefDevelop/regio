# reGiO: Reverse Proxy Seguro con Panel de Administración

**reGiO** es un proxy inverso blindado y ligero escrito en Go, diseñado para proteger servicios internos mediante autenticación centralizada, control de acceso por IP y mitigación activa de ataques. Ideal para usuarios de Cloudflare Tunnels, Tailscale Funnel o entornos de red privada.

---

## Características Principales

- **Autenticación Blindada:** Sistema de sesiones persistentes con protección CSRF global.
- **Soporte para 2FA (TOTP):** Autenticación en dos pasos con secretos cifrados en reposo (AES-256-GCM).
- **Anti-Fuerza Bruta (Fail2Ban):** Bloqueo automático de IPs y rangos de red (/24 o /64) tras intentos fallidos.
- **Validación de Proxies de Confianza:** Prevención de suplantación de identidad (Spoofing) mediante la validación de IPs de confianza (vía `TRUSTED_PROXIES`).
- **Protección SSRF Avanzada:** Bloqueo estricto de accesos a IPs privadas (RFC 1918) y loopback desde el proxy.
- **App Tokens Seguros:** Gestión de tokens para APIs con haseo SHA-256 y auditoría de uso.
- **Invitaciones Seguras:** Los nuevos usuarios requieren un token único de un solo uso para establecer su contraseña.
- **DoS Mitigation:** Timeouts estrictos en la comunicación con backends para garantizar la estabilidad.
- **Docker Ready:** Imagen ultra-ligera (< 15MB) basada en Alpine Linux.

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

reGiO utiliza el header **`X-API-Key`** como método estándar para evitar conflictos con los sistemas de autenticación de los servicios finales (como Gitea o Jenkins).

### 1. Uso con Git (Recomendado)
Configura Git para enviar el token en la cabecera estándar de reGiO:

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
Una vez validada la autenticación, reGiO **elimina automáticamente** las cabeceras `X-API-Key` y los datos de `Authorization` antes de pasar la petición al servicio final, garantizando que tus credenciales de acceso nunca se filtren al backend.

---

## Licencia
MIT License. Hecho para la comunidad Self-Hosted con foco en la seguridad.
