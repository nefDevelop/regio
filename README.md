# 🛡️ reGiO: Secure Reverse Proxy & Admin Panel

**reGiO** es un portero (reverse proxy) ligero y ultra-seguro escrito en Go, diseñado para proteger tus servicios locales expuestos a internet (ideal para usuarios de Cloudflare Tunnels, Tailscale Funnel o Ngrok).

Ofrece una capa de **autenticación centralizada**, **bloqueo automático de ataques por fuerza bruta** y un **panel de administración web** para gestionar tus redirecciones de forma visual.

---

## ✨ Características Principales

- **Autenticación Centralizada:** Protege todos tus servicios (NAS, Plex, Home Assistant, etc.) con una sola cuenta de usuario/contraseña vía Basic Auth.
- **Anti-Brute Force (Fail2Ban):** Bloqueo automático de IPs tras 5 intentos fallidos durante 15 minutos. Detecta la IP real del atacante incluso detrás de Cloudflare (`CF-Connecting-IP`).
- **Panel de Administración Web:** Gestiona tus puentes (Mappings) de `Dominio -> Puerto` directamente desde el navegador sin tocar archivos JSON ni reiniciar el servidor.
- **Docker Ready:** Despliegue en segundos con Docker y Docker Compose. Imagen ultra-ligera basada en Alpine Linux (< 15MB).
- **Configuración Dinámica:** Los cambios realizados en el panel persisten en un archivo `config.json` local.

---

## Instalación Rápida

### 1. Requisitos

- Docker y Docker Compose instalados.
- Un dominio o subdominio apuntando a tu servidor (ej: vía Cloudflare Tunnel).

### 2. Clonar y Configurar

```bash
git clone https://github.com/tu-usuario/REGIO.git
cd REGIO

# Configura tus credenciales y dominio de administración
cp .env.example .env
nano .env
```

### 3. Preparar archivos

```bash
# Crea un archivo de configuración vacío
echo '{"servicios": {}}' > config.json
```

### 4. Desplegar

```bash
docker-compose up -d --build
```

---

## 🛠️ Configuración de Cloudflare Tunnel

Para que el REGIO funcione correctamente, debes configurar tus **Public Hostnames** en el panel de Cloudflare Zero Trust apuntando todos al mismo puerto del REGIO (por defecto `9999`):

- `auth.tudominio.com` -> `http://localhost:9999` (Panel Admin)
- `nas.tudominio.com` -> `http://localhost:9999` (Tu NAS)
- `app.tudominio.com` -> `http://localhost:9999` (Otra App)

---

## 🖥️ Uso del Panel de Administración

1.  Accede a la URL definida en tu `.env` bajo `ADMIN_DOMAIN` seguido de `/admin`.
    - Ejemplo: `https://auth.tudominio.com/admin`
2.  Introduce el usuario y contraseña configurados en tu archivo `.env`.
3.  **Añadir Servicio:** Introduce el dominio público (ej: `nas.tudominio.com`) y el destino interno (ej: `http://localhost:4545`).
4.  **Eliminar Servicio:** Haz clic en "Eliminar" para desactivar un puente al instante.

---

## 🔐 Seguridad y Privacidad

- **Variables de Entorno:** Las credenciales nunca se guardan en el código fuente.
- **No-Root:** El contenedor está diseñado para ser ejecutado con privilegios mínimos (opcional según configuración).
- **Aislamiento:** Tus aplicaciones reales no necesitan estar expuestas al exterior; el REGIO actúa como el único punto de entrada.

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Siéntete libre de usarlo, modificarlo y compartirlo.

---

_Hecho con ❤️ para la comunidad Self-Hosted._
