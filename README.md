# reGiO: Reverse Proxy Seguro con Panel de Administración

**reGiO** es un proxy inverso ligero y seguro escrito en Go, diseñado para proteger tus servicios locales expuestos a internet (ideal para usuarios de Cloudflare Tunnels, Tailscale Funnel o Ngrok).

Ofrece una capa de **autenticación centralizada**, **bloqueo automático de ataques por fuerza bruta** y un **panel de administración web** para gestionar tus redirecciones de forma visual.

---

## Características Principales

- **Autenticación Multi-Usuario:** Sistema de inicio de sesión seguro basado en sesiones con soporte para múltiples usuarios y roles.
- **Soporte para 2FA (TOTP):** Los usuarios pueden activar la autenticación en dos pasos para una capa extra de seguridad.
- **Anti-Fuerza Bruta (Fail2Ban):** Bloqueo automático de IPs tras repetidos intentos fallidos. Detecta la IP real incluso detrás de proxies como Cloudflare.
- **App Tokens Avanzados:** Genera tokens de acceso para aplicaciones, scripts o clientes Git.
- **Soporte de Cabeceras Estándar:**
  - `Authorization: Bearer <TOKEN>`
  - `X-Regio-Token: <TOKEN>`
  - `X-API-Key: <TOKEN>`
- **Bypass Seguro por Cabecera:** Permite el acceso automático a un servicio si se presenta una cabecera secreta preconfigurada (ideal para webhooks o integraciones CI/CD).
- **Panel de Administración Web:** Interfaz gráfica para gestionar servicios, usuarios, bloqueos de IP y registro de eventos en tiempo real.
- **Docker Ready:** Imagen ultra-ligera (< 15MB) basada en Alpine Linux.

---

## Instalación y Despliegue

```bash
git clone https://github.com/nef734/regio.git
cd regio

# Configura tu dominio de administración en el .env
cp .env.example .env
nano .env

# Despliega con Docker
docker compose up -d --build
```

---

## Guía de Autenticación para Aplicaciones

reGiO ofrece flexibilidad total para que tus aplicaciones se conecten de forma segura sin pasar por el login visual.

### 1. Uso con Git (Recomendado)
Para evitar tokens en la URL y mantener la compatibilidad con las credenciales de tu servidor Git (Gogs/Gitea), configura Git para enviar el token de reGiO en una cabecera:

```bash
git config http.extraHeader "X-Regio-Token: TU_TOKEN_DE_REGIO"
```
Esto permite que `git push/pull` funcione con la URL limpia: `http://vit.734038.xyz/user/repo.git`.

### 2. Uso con APIs y Scripts
Puedes usar el estándar Bearer o cabeceras personalizadas:

```bash
# Usando Bearer (Estándar API)
curl -H "Authorization: Bearer TU_TOKEN" http://api.tudominio.com/data

# Usando X-Regio-Token
curl -H "X-Regio-Token: TU_TOKEN" http://api.tudominio.com/data
```

### 3. Acceso vía Path (Rápido)
Si no puedes configurar cabeceras, usa el token directamente en la dirección:
`http://app.tudominio.com/r-auth/TU_TOKEN/ruta/destino`

---

## Configuración de Bypass Seguro (Avanzado)

En lugar de hacer un servicio totalmente "público", puedes definir una "llave de paso" en `config.json`. Solo las peticiones que incluyan esa cabecera exacta podrán saltar la autenticación de reGiO:

```json
{
  "servicios": {
    "webhook.tudominio.com": "http://192.168.1.50:9000"
  },
  "bypass_headers": {
    "webhook.tudominio.com": "X-My-Secret:SuperClave123"
  }
}
```

---

## Seguridad y Limpieza
reGiO es inteligente: una vez que valida tu token (ya sea por Path, Query o Header), **elimina esas cabeceras y parámetros** antes de pasar la petición al servicio final. Esto evita que tus tokens se filtren a los backends y previene conflictos con sus propios sistemas de autenticación.

---

## Licencia
MIT License. Hecho para la comunidad Self-Hosted.
