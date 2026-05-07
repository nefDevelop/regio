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

- [x] **SSO / Proxy Auth:** Inyección de identidad (`X-Forwarded-User`) al backend para inicio de sesión automático (Single Sign-On).
- [x] Proxy Inverso core con soporte HTTP/1.1 y WebSockets.
- [x] Autenticación de sesiones y App Tokens.
- [x] Soporte 2FA (TOTP).
- [x] Sistema Fail2Ban por IP y Subred.
- [x] CLI de gestión avanzada.
- [x] Persistencia en SQLite.
