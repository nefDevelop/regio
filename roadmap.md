# Roadmap de reGIO

Este documento detalla las funcionalidades planeadas y el estado actual del desarrollo.

## Próximamente (Q2 2026)

- [ ] **Autodescubrimiento (Docker Provider):** Integración con Docker socket para añadir servicios dinámicamente mediante _Labels_.
- [ ] **Soporte para OAuth2/OIDC:** Permitir login con Google, GitHub, Authentik, etc.
- [ ] **Dashboard de Analíticas:** Visualización en tiempo real de peticiones bloqueadas y tráfico.
- [ ] **Exportación de Logs:** Integración con sistemas como Loki o Syslog.

## Ideas en Evaluación

- [ ] **WAF Integrado:** Reglas básicas de filtrado para ataques comunes (SQLi, XSS).
- [ ] **Gestión Automática de Certificados:** Integración nativa con Let's Encrypt / ACME.
- [ ] **Multi-Admin:** Soporte para diferentes niveles de permisos administrativos.

## Completado ✅

- [x] **Guard de memoria del rate limiter sin DoS:** el guard de "memory exhaustion" rechazaba tráfico (`return false`) y llamaba a `LimpiarRateLimiter()` por cada IP nueva al superar 10.000 entradas. Como la limpieza solo borra IPs con 10 min de inactividad, rotar IPs de origen mantenía todas las entradas como activas y cada petición pagaba un volcado completo a SQLite: medido **165 ms/petición** frente a 2–18 µs antes del umbral, sin recuperación posible. Ahora expulsa las entradas menos recientemente usadas (LRU por `seq`) y sigue atendiendo la petición: **19,7 µs/petición** en el mismo punto (~5.000×). El guard acota la memoria, no el tráfico. Cubierto por `TestRateLimiterAcotaMemoriaSinDegradar` y `TestRateLimiterExpulsaLoMaisViejo`.
- [x] **Geobloqueo por país (GeoIP):** Filtrado allow/deny con BD local `.mmdb` (MaxMind/DB-IP), política global + override por servicio, fail-open/fail-closed configurable desde el panel admin.
- [x] **SSO / Proxy Auth:** Inyección de identidad (`X-Forwarded-User`) al backend para inicio de sesión automático (Single Sign-On).
- [x] Proxy Inverso core con soporte HTTP/1.1 y WebSockets.
- [x] Autenticación de sesiones y App Tokens.
- [x] Soporte 2FA (TOTP).
- [x] Sistema Fail2Ban por IP y Subred.
- [x] CLI de gestión avanzada.
- [x] Persistencia en SQLite.
