# Política de Seguridad

## Reporte de Vulnerabilidades

La seguridad de reGIO es nuestra máxima prioridad. Si crees haber encontrado una vulnerabilidad, te pedimos que nos la reportes de manera responsable.

**No abras un issue público.** En su lugar, abre un [advisory de seguridad en GitHub](https://github.com/nefDevelop/regio/security/advisories/new) o contacta directamente a los mantenedores a través de los canales privados del repositorio.

## Proceso de Respuesta

1.  Confirmaremos la recepción de tu reporte en un plazo de 48 horas.
2.  Trabajaremos en una solución y te mantendremos informado sobre el progreso.
3.  Una vez corregida, publicaremos una nueva versión y te daremos crédito por el hallazgo (si así lo deseas).

## Alcance

Esta política cubre el código fuente en este repositorio y las imágenes Docker oficiales. No cubre servicios de terceros o configuraciones de red externas (como la seguridad de tu instancia de Cloudflare o Tailscale).

## Limitaciones del geobloqueo (GeoIP)

El filtrado por país (`GEO_MODE` / panel admin → «Filtrado por País») es una **capa defensiva más, no un control de acceso fuerte**:

- Las **VPNs, proxies y salidas de datacenter** se geolocalizan por la IP del proveedor, no por la ubicación real del usuario.
- La base de datos se actualiza **mensualmente**; entre actualizaciones puede haber rangos de IP recién asignados mal clasificados.
- Si la BD no está cargada o la IP es indeterminable, el comportamiento lo decide `GEO_FAIL_MODE` (`open` por defecto para no cortar el servicio).
- Las IPs privadas/locales nunca se geolocalizan y quedan siempre fuera del filtrado.
- No sustituye a la autenticación, al WAF ni al rate limiting: úsalo como defensa en profundidad.

## Hardening de despliegue

Recomendaciones de infraestructura para que las protecciones de reGIO
(rate limiting, Fail2Ban, geobloqueo) sean efectivas:

- **El origin solo debe ser accesible a través del proxy** (Cloudflare,
  Nginx, Tailscale, etc.). El rate limiting y el geobloqueo confían en la IP
  real extraída de `X-Forwarded-For`: si alguien puede alcanzar el puerto de
  reGIO directamente y `TRUSTED_PROXIES` incluye esa ruta, podría falsificar
  la cabecera para bypassear límites. Cierra el puerto con firewall/grupo de
  seguridad salvo para el proxy.
- **`TRUSTED_PROXIES` con precisión quirúrgica**: solo las IPs/CIDR exactos
  del proxy (nunca `0.0.0.0/0` ni rangos amplios). Cada entrada autoriza a
  quien la posee a elegir la IP cliente que ve reGIO.
- **Rotación de la base GeoIP**: descárgala mensualmente (MaxMind/DB-IP); el
  proceso la recarga sola cada 10 minutos si detecta el fichero cambiado.
- **Backends de terceros**: reGIO elimina antes de proxyar `X-API-Key`, la
  cookie `REGIO_session`, las cookies `REGIO_*` de respuesta y cualquier
  `Authorization` Basic que corresponda a un token de reGIO. El resto de
  cabeceras llegan al backend tal cual: trata los backends como código de
  confianza y revoca `bypass` keys con el panel si dejas de confiar en uno.
- **`MASTER_KEY` y `.env`**: nunca en el repositorio (gitleaks/`.gitignore`);
  rota con `./REGIO rotate-key` si hay sospecha de exposición.
