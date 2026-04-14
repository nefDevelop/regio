# reGiO: Reverse Proxy Seguro con Panel de Administración

**reGiO** es un proxy inverso ligero y seguro escrito en Go, diseñado para proteger tus servicios locales expuestos a internet (ideal para usuarios de Cloudflare Tunnels, Tailscale Funnel o Ngrok).

Ofrece una capa de **autenticación centralizada**, **bloqueo automático de ataques por fuerza bruta** y un **panel de administración web** para gestionar tus redirecciones de forma visual.

---

## Características

- **Autenticación Multi-Usuario:** Sistema de inicio de sesión seguro basado en sesiones. Permite crear múltiples usuarios y gestionar sus accesos desde el panel de administrador.
- **Soporte para 2FA (TOTP):** Los usuarios pueden activar la autenticación en dos pasos (compatible con Google Authenticator, Authy, etc.) para una capa extra de seguridad.
- **Anti-Fuerza Bruta (Fail2Ban):** Bloqueo automático de IPs y rangos de red tras repetidos intentos de inicio de sesión fallidos. Detecta la IP real del atacante incluso detrás de Cloudflare.
- **Panel de Administración Web:** Interfaz gráfica para gestionar puentes (redirecciones), usuarios, bloqueos de IP y visualizar un registro de eventos.
- **Docker Ready:** Despliegue rápido y sencillo con Docker. Imagen ultra-ligera (< 15MB).
- **Configuración Dinámica:** Los cambios en los puentes se guardan en `config.json` y se aplican al instante sin reinicios.

---

## Instalación

### Requisitos

- Docker y Docker Compose instalados.
- Un dominio o subdominio apuntando a tu servidor (ej: vía Cloudflare Tunnel).

### Pasos

```bash
git clone https://github.com/nef734/regio.git
cd regio

# Configura el dominio que usarás para acceder al panel de administración
cp .env.example .env
nano .env

# Crea un archivo de configuración vacío
echo '{"servicios": {}}' > config.json

# Despliega el contenedor
docker-compose up -d --build
```

---

## Ejemplo de Configuración (Cloudflare Tunnel)

Para que reGiO funcione correctamente, debes configurar tus **Public Hostnames** en el panel de Cloudflare Zero Trust apuntando todos al mismo servicio local donde se ejecuta reGiO (por defecto, el puerto `80` del contenedor):

- `admin.tudominio.com` -> `http://localhost:80` (Panel Admin, según tu `ADMIN_DOMAIN`)
- `nas.tudominio.com` -> `http://localhost:80` (Tu NAS)
- `app.tudominio.com` -> `http://localhost:80` (Otra App)

---

## Uso y Primeros Pasos

1.  **Primer Inicio (Instalación):** Al acceder por primera vez a cualquier dominio gestionado por reGiO, serás redirigido a una página de instalación para crear tu cuenta de administrador principal.
2.  **Inicio de Sesión:** Una vez configurado, accede al panel de administración en la URL definida en tu variable `ADMIN_DOMAIN` (ej: `https://admin.tudominio.com/admin`).
3.  **Gestión de Puentes:** En el panel, puedes añadir un dominio público (ej: `nas.tudominio.com`) y su destino local correspondiente.
    - **Importante sobre el "Destino Local":** Como reGiO se ejecuta en Docker, `localhost` significa "el interior del propio contenedor". En su lugar, usa:
      - **Si el servicio es otro contenedor (misma red Docker):** Usa el nombre del contenedor (ej: `http://nextcloud:80` o `http://plex:32400`).
      - **Si el servicio está en tu servidor (host) u otro equipo local:** Usa la IP local de tu red (ej: `http://192.168.1.50:8080`).
4.  **Gestión de Usuarios:** El administrador puede crear nuevos usuarios. Los usuarios nuevos sin contraseña asignada podrán crearla en su primer inicio de sesión.
5.  **Perfil de Usuario:** Cada usuario puede acceder a su perfil para cambiar su nombre/contraseña y activar/desactivar el 2FA.

---

## Seguridad y Privacidad

- **Variables de Entorno:** La configuración sensible (como el dominio de administración) se gestiona fuera del código.
- **No-Root:** El contenedor está diseñado para ser ejecutado con privilegios mínimos (opcional según configuración).
- **Aislamiento:** Tus aplicaciones reales no necesitan estar expuestas al exterior; reGiO actúa como el único punto de entrada.

---

## Licencia

Este proyecto está bajo la Licencia MIT. Siéntete libre de usarlo, modificarlo y compartirlo.

---

_Hecho para la comunidad Self-Hosted._
