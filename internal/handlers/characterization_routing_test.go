package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"regio/internal/models"
	"regio/internal/security"
)

// TestMainHandlerRoutingCharacterization congela el comportamiento actual de
// enrutado/autorización de MainHandler. Es la red de seguridad previa a los
// refactor R1-R3: cualquier cambio de status/Location/body que rompa estos
// casos es una regresión de comportamiento no aprobada.
//
// quirks y decisiones congelados:
//   - Errores del WAF -> 403 "Solicitud bloqueada por las reglas de
//     seguridad." (fix deuda #1; antes respondían 429 "Demasiadas peticiones").
//     El 429 del default corresponde SOLO al rate limiter.
//   - Mensajes 404 unificados a "Dominio no configurado en ReGiO: <host>"
//     (antes la ruta bypass decía "Dominio no configurado" — fix deuda #2).
//   - /health salta el SecurityEngine (nunca geo-bloquea); /api/csp-report
//     SÍ pasa por él desde el fix S2 (antes era un endpoint sin limitar).
//   - Redirects mixtos: NeedsSetup usa 307; login/profile/admin usan 303.
//   - La ruta bypass ahora pasa el statusWriter: el log de cierre refleja el
//     status real (antes registraba [200] en un 404 — fix deuda #6).
func TestMainHandlerRoutingCharacterization(t *testing.T) {
	type routingCase struct {
		name       string
		method     string
		path       string
		host       string
		headers    map[string]string
		form       url.Values // si != nil, se envía como cuerpo urlencoded en POST
		rawBody    string     // si != "", se envía como cuerpo crudo (POST)
		acceptHTML bool
		needsSetup bool
		session    *models.User // si != nil: sesión válida con cookie "routing-raw"
		servicio   map[string]string
		bypassRaw  string // si != "", registra clave de bypass para el host (ruta ProxyHandler)
		geo        *security.GeoPolicy
		bannedIP   bool

		wantStatus  int
		wantLoc     string // subcadena esperada en Location (opcional)
		wantBody    string // subcadena esperada en el body (opcional)
		wantBodyNot string // subcadena que NO debe aparecer (opcional)
		wantCT      string // prefijo de Content-Type esperado (opcional)
	}

	cases := []routingCase{
		{
			name: "health responde 200 aunque NeedsSetup sea true",
			path: "/health", host: "admin.test", needsSetup: true,
			wantStatus: 200, wantBody: "ok", wantCT: "text/plain",
		},
		{
			name: "health NO pasa por el SecurityEngine (no geo-bloquea)",
			path: "/health", host: "service.test",
			geo:        &security.GeoPolicy{Mode: security.GeoModeAllow, Countries: []string{"ES"}, FailMode: security.GeoFailClosed},
			wantStatus: 200, wantBody: "ok",
		},
		{
			// Fix S2: los reportes CSP AHORA pasan por el SecurityEngine
			// (antes estaban antes de todo: sin rate limit/geo/WAF).
			name:   "csp-report SÍ pasa por el engine: geo lo bloquea",
			method: "POST", path: "/api/csp-report", host: "admin.test",
			headers:    map[string]string{"Content-Type": "application/json"},
			rawBody:    `{"csp-report":{"blocked-uri":"https://ejemplo.test/x.js"}}`,
			geo:        &security.GeoPolicy{Mode: security.GeoModeAllow, Countries: []string{"ES"}, FailMode: security.GeoFailClosed},
			wantStatus: 403, wantBody: "Acceso denegado desde tu región",
		},
		{
			// ...y con política geográfica inactiva se procesa con normalidad.
			name:   "csp-report con geo off -> 204",
			method: "POST", path: "/api/csp-report", host: "admin.test",
			headers:    map[string]string{"Content-Type": "application/json"},
			rawBody:    `{"csp-report":{"blocked-uri":"https://ejemplo.test/ok.js"}}`,
			wantStatus: 204,
		},
		{
			name: "static se sirve con Content-Type correcto",
			path: "/static/style.css", host: "admin.test",
			wantStatus: 200, wantCT: "text/css",
		},
		{
			name: "static SÍ está sujeto al geobloqueo (pasa por el engine)",
			path: "/static/style.css", host: "admin.test",
			geo:        &security.GeoPolicy{Mode: security.GeoModeAllow, Countries: []string{"ES"}, FailMode: security.GeoFailClosed},
			wantStatus: 403, wantBody: "Acceso denegado desde tu región",
		},
		{
			name: "favicon.ico sirve el SVG del logo",
			path: "/favicon.ico", host: "admin.test",
			wantStatus: 200,
		},
		{
			name: "NeedsSetup redirige cualquier ruta a /setup",
			path: "/cualquier-cosa", host: "admin.test", needsSetup: true,
			wantStatus: 307, wantLoc: "/setup",
		},
		{
			name: "NeedsSetup permite entrar en /setup",
			path: "/setup", host: "admin.test", needsSetup: true,
			wantStatus: 200,
		},
		{
			name: "GET /REGIO-login sirve el formulario",
			path: "/REGIO-login", host: "admin.test",
			wantStatus: 200,
		},
		{
			// QUIRK congelado: este redirect usa 303 SeeOther (no 307).
			name: "Sin sesión + Accept html -> 303 a login",
			path: "/perfil-cualquiera", host: "service.test", acceptHTML: true,
			wantStatus: 303, wantLoc: "/REGIO-login",
		},
		{
			name: "Sin sesión + Accept no-html (AJAX) -> 401 con mensaje",
			path: "/api/cualquiera", host: "service.test",
			wantStatus: 401, wantBody: "Sesión expirada o no autorizada",
		},
		{
			name: "Sesión no-admin en /admin -> 303 a /profile",
			path: "/admin", host: "admin.test",
			session:    &models.User{ID: 10, Username: "pepe", IsAdmin: false, CSRFToken: "csrf-routing"},
			wantStatus: 303, wantLoc: "/profile",
		},
		{
			name: "Sesión admin en /admin -> panel 200",
			path: "/admin", host: "admin.test",
			session:    &models.User{ID: 1, Username: "admin", IsAdmin: true, CSRFToken: "csrf-routing"},
			wantStatus: 200,
		},
		{
			name: "Sesión admin en / -> 303 a /admin",
			path: "/", host: "admin.test",
			session:    &models.User{ID: 1, Username: "admin", IsAdmin: true, CSRFToken: "csrf-routing"},
			wantStatus: 303, wantLoc: "/admin",
		},
		{
			name: "Host no configurado con sesión -> 404 con mensaje INLINE (R1)",
			path: "/x", host: "ghost.test",
			session:    &models.User{ID: 1, Username: "admin", IsAdmin: true, CSRFToken: "csrf-routing"},
			wantStatus: 404, wantBody: "Dominio no configurado en ReGiO: ghost.test",
		},
		{
			// FIX deuda #2: mensaje unificado (antes decía solo "Dominio no
			// configurado" sin host en la ruta bypass).
			name: "Bypass token en host no configurado -> 404 con mensaje unificado",
			path: "/x", host: "ghost.test",
			bypassRaw:  "routing-bypass-token",
			wantStatus: 404, wantBody: "Dominio no configurado en ReGiO: ghost.test",
		},
		{
			// FIX deuda #1: antes respondía 429 "Demasiadas peticiones"
			// (código y mensaje falsos). Ahora 403 con mensaje propio del WAF.
			name: "WAF por User-Agent scanner -> 403 con mensaje propio",
			path: "/x", host: "service.test",
			headers:    map[string]string{"User-Agent": "sqlmap/1.7.2#stable"},
			wantStatus: 403, wantBody: "Solicitud bloqueada por las reglas de seguridad",
		},
		{
			name: "WAF por SQLi en query -> 403 con mensaje propio",
			path: "/x?q=%27%20OR%201%3D1--", host: "service.test",
			wantStatus: 403, wantBody: "Solicitud bloqueada por las reglas de seguridad",
		},
		{
			name: "IP bloqueada (Fail2Ban) -> 403 con detalle del motivo",
			path: "/x", host: "service.test", bannedIP: true,
			wantStatus: 403, wantBody: "IP bloqueada",
		},
		{
			name: "GET /logout con sesión -> 405",
			path: "/logout", host: "admin.test",
			session:    &models.User{ID: 1, Username: "admin", IsAdmin: true, CSRFToken: "csrf-routing"},
			wantStatus: 405,
		},
		{
			name:   "POST /logout sin CSRF -> 403",
			method: "POST", path: "/logout", host: "admin.test",
			form:       url.Values{"otro": {"campo"}},
			headers:    map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			session:    &models.User{ID: 1, Username: "admin", IsAdmin: true, CSRFToken: "csrf-routing"},
			wantStatus: 403, wantBody: "CSRF",
		},
		{
			name:   "POST /logout con CSRF -> 303 a login",
			method: "POST", path: "/logout", host: "admin.test",
			form:       url.Values{"csrf_token": {"csrf-routing"}},
			headers:    map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			session:    &models.User{ID: 1, Username: "admin", IsAdmin: true, CSRFToken: "csrf-routing"},
			wantStatus: 303, wantLoc: "/REGIO-login",
		},
	}

	const rawToken = "routing-raw-token"

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateState(t)

			// --- estado específico del caso ---
			Mu.Lock()
			NeedsSetup = tc.needsSetup
			if tc.servicio != nil {
				for h, tgt := range tc.servicio {
					Config.Servicios[h] = tgt
				}
			}
			Mu.Unlock()

			if tc.session != nil {
				seedSession(t, rawToken, tc.session)
			}
			if tc.bypassRaw != "" {
				security.AddBypassKey(tc.bypassRaw, "routing-bypass", tc.host)
				t.Cleanup(func() {
					// DeleteBypassKey trabaja sobre el hash; recalcularlo igual que bypassHash
					security.DeleteBypassKey(testBypassHash(tc.bypassRaw))
				})
			}
			if tc.geo != nil {
				prev := security.GetGlobalGeoPolicy()
				if err := security.SetGlobalGeoPolicy(*tc.geo); err != nil {
					t.Fatalf("policy: %v", err)
				}
				t.Cleanup(func() { _ = security.SetGlobalGeoPolicy(prev) })
			}
			if tc.bannedIP {
				// httptest.NewRequest usa RemoteAddr 192.0.2.1 por defecto
				security.BanIP("192.0.2.1", "caracterización", time.Hour)
			}

			// --- request ---
			method := tc.method
			if method == "" {
				method = http.MethodGet
			}
			var bodyReader io.Reader
			if method == http.MethodPost {
				switch {
				case tc.form != nil:
					bodyReader = strings.NewReader(tc.form.Encode())
				case tc.rawBody != "":
					bodyReader = strings.NewReader(tc.rawBody)
				default:
					bodyReader = strings.NewReader("")
				}
			}
			req := httptest.NewRequest(method, tc.path, bodyReader)
			req.Host = tc.host
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if tc.acceptHTML {
				req.Header.Set("Accept", "text/html")
			}
			if tc.session != nil {
				req.AddCookie(&http.Cookie{Name: SessionKey, Value: rawToken})
			}
			if tc.bypassRaw != "" {
				req.Header.Set("X-REGIO-Bypass", tc.bypassRaw)
			}

			rr := httptest.NewRecorder()
			MainHandler(rr, req)

			// --- aserciones ---
			if rr.Code != tc.wantStatus {
				t.Errorf("status = %d; want %d (body: %s)", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.wantLoc != "" {
				if loc := rr.Header().Get("Location"); !strings.Contains(loc, tc.wantLoc) {
					t.Errorf("Location = %q; want que contenga %q", loc, tc.wantLoc)
				}
			}
			if tc.wantBody != "" && !strings.Contains(rr.Body.String(), tc.wantBody) {
				t.Errorf("body = %q; want que contenga %q", rr.Body.String(), tc.wantBody)
			}
			if tc.wantBodyNot != "" && strings.Contains(rr.Body.String(), tc.wantBodyNot) {
				t.Errorf("body = %q; NO debe contener %q", rr.Body.String(), tc.wantBodyNot)
			}
			if tc.wantCT != "" {
				ct := rr.Header().Get("Content-Type")
				if !strings.HasPrefix(ct, tc.wantCT) {
					t.Errorf("Content-Type = %q; want prefijo %q", ct, tc.wantCT)
				}
			}
		})
	}
}

// TestIsKnownHost cubre el guardián anti open-redirect (fix deuda #3):
// solo el dominio admin y los servicios configurados son "conocidos".
func TestIsKnownHost(t *testing.T) {
	isolateState(t) // AdminDomain = "admin.test", Config vacío

	if !IsKnownHost("admin.test") {
		t.Error("el dominio admin debe ser conocido")
	}
	if !IsKnownHost("admin.test:9999") {
		t.Error("el puerto debe ignorarse al normalizar")
	}
	if IsKnownHost("evil.test") {
		t.Error("un host desconocido no debe ser conocido")
	}

	Mu.Lock()
	Config.Servicios["app.test"] = "http://192.168.1.2:80"
	Mu.Unlock()
	if !IsKnownHost("app.test") {
		t.Error("un servicio configurado debe ser conocido")
	}
	if IsKnownHost("app.test.evil.com") {
		t.Error("un host que solo termina por el nombre del servicio no debe ser conocido")
	}
}
