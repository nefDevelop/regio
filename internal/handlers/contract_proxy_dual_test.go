package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"regio/internal/db"
	"regio/internal/models"
	"regio/internal/security"
)

// backendCapture registra lo que el backend mock recibe, y permite definir
// la respuesta (status, headers, body).
type backendCapture struct {
	mu       sync.Mutex
	path     string
	rawQuery string
	headers  http.Header
}

func (c *backendCapture) record(r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.path = r.URL.Path
	c.rawQuery = r.URL.RawQuery
	c.headers = r.Header.Clone()
}

func (c *backendCapture) get() (string, string, http.Header) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.path, c.rawQuery, c.headers
}

// newBackend lanza un backend capturador. respond personaliza la respuesta;
// si es nil responde 200 con body {"ok":true} y headers de seguridad de
// backend que reGIO debería sobrescribir.
func newBackend(t *testing.T, respond func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *backendCapture) {
	t.Helper()
	cap := &backendCapture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.record(r)
		if respond != nil {
			respond(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Strict-Transport-Security", "max-age=99")
		w.Header().Set("X-Custom-Keep", "siempre")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

// setupProxy registra el servicio "app.test" apuntando al backend y permite
// dializar a su IP (loopback) vía AllowedNetworks.
func setupProxy(t *testing.T, backendURL string) {
	t.Helper()
	u, err := url.Parse(backendURL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		security.AddAllowedIP(ip)
	}
	Mu.Lock()
	Config.Servicios["app.test"] = backendURL
	Mu.Unlock()
}

// seedAppToken crea un usuario + app token válido para VerifyAppToken.
func seedAppToken(t *testing.T, rawToken string) {
	t.Helper()
	cleanUsers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id, username, is_admin) VALUES (1, 'tokenuser', 1)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	h := sha256.Sum256([]byte(rawToken))
	tokenHash := base64.StdEncoding.EncodeToString(h[:])
	if _, err := db.DB.Exec("INSERT INTO app_tokens (user_id, name, token_hash) VALUES (1, 'proxy-token', ?)", tokenHash); err != nil {
		t.Fatalf("insert app_token: %v", err)
	}
}

// TestProxyContractCharacterization congela el contrato de las DOS rutas de
// proxy (inline en MainHandler vs ProxyHandler por bypass). Origen: red de
// seguridad del refactor R1; después se aplicó el fix de deuda #2 (mensaje
// 404 unificado y X-API-Key borrado en ambas rutas) — las aserciones reflejan
// la regla unificada actual.
func TestProxyContractCharacterization(t *testing.T) {
	if testing.Short() {
		t.Skip("modo -short: test de integración (backend/Argon2)")
	}
	const appHost = "app.test"

	t.Run("inline con sesión: X-Forwarded + X-API-Key borrado + Authorization conservada", func(t *testing.T) {
		isolateState(t)
		backend, cap := newBackend(t, nil)
		setupProxy(t, backend.URL)
		seedSession(t, "proxy-raw-1", &models.User{ID: 1, Username: "admin", IsAdmin: true, CSRFToken: "csrf-proxy"})

		req := httptest.NewRequest("GET", "/datos?x=1", nil)
		req.Host = appHost
		req.Header.Set("Authorization", "Bearer segreto-cliente")
		req.Header.Set("X-API-Key", "clave-cliente")
		req.AddCookie(&http.Cookie{Name: SessionKey, Value: "proxy-raw-1"})
		req.AddCookie(&http.Cookie{Name: "carrito", Value: "42"}) // cookie del backend

		rr := httptest.NewRecorder()
		MainHandler(rr, req)

		if rr.Code != 200 {
			t.Fatalf("status = %d; want 200 (body: %s)", rr.Code, rr.Body.String())
		}
		path, query, got := cap.get()
		if path != "/datos" || query != "x=1" {
			t.Errorf("backend recibió path=%q query=%q; want /datos con x=1", path, query)
		}
		if got.Get("X-Forwarded-Host") != appHost {
			t.Errorf("X-Forwarded-Host = %q; want %q", got.Get("X-Forwarded-Host"), appHost)
		}
		if got.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("X-Forwarded-Proto = %q; want https (siempre, QUIRK)", got.Get("X-Forwarded-Proto"))
		}
		// tokenUsed == "" (sesión cookie): Authorization NO se borra...
		if got.Get("Authorization") != "Bearer segreto-cliente" {
			t.Errorf("Authorization = %q; want conservada con sesión de cookie", got.Get("Authorization"))
		}
		// ...pero X-API-Key SIEMPRE se borra en la ruta inline.
		if got.Get("X-API-Key") != "" {
			t.Errorf("X-API-Key = %q; want borrada en ruta inline", got.Get("X-API-Key"))
		}
		// Mejora A1: la cookie de sesión de reGIO NUNCA llega al backend;
		// las cookies del backend sí se conservan.
		cookieBackend := got.Get("Cookie")
		if strings.Contains(cookieBackend, SessionKey) {
			t.Errorf("Cookie = %q; la cookie de sesión de reGIO no debe filtrarse al backend", cookieBackend)
		}
		if !strings.Contains(cookieBackend, "carrito=42") {
			t.Errorf("Cookie = %q; want conservar la cookie del backend carrito=42", cookieBackend)
		}
		// Cuerpo y headers de respuesta
		if rr.Body.String() != `{"ok":true}` {
			t.Errorf("body = %q; want {\"ok\":true}", rr.Body.String())
		}
		if rr.Header().Get("X-Custom-Keep") != "siempre" {
			t.Errorf("X-Custom-Keep del backend perdido")
		}
		// Los headers de seguridad del backend NO deben sobrevivir: manda reGIO.
		if strings.Contains(rr.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Errorf("CSP del backend no fue eliminado: %q", rr.Header().Get("Content-Security-Policy"))
		}
		if !strings.Contains(rr.Header().Get("Content-Security-Policy"), "report-uri /api/csp-report") {
			t.Errorf("CSP de reGIO no presente: %q", rr.Header().Get("Content-Security-Policy"))
		}
		if rr.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("X-Frame-Options = %q; want DENY (reGIO, no SAMEORIGIN del backend)", rr.Header().Get("X-Frame-Options"))
		}
		if rr.Header().Get("Strict-Transport-Security") != "max-age=31536000; includeSubDomains" {
			t.Errorf("HSTS = %q; want el de reGIO", rr.Header().Get("Strict-Transport-Security"))
		}
	})

	t.Run("inline con token: Authorization borrada y api_key fuera de la query", func(t *testing.T) {
		isolateState(t)
		backend, cap := newBackend(t, nil)
		setupProxy(t, backend.URL)
		seedAppToken(t, "proxy-token-query")

		req := httptest.NewRequest("GET", "/datos?api_key=proxy-token-query&y=2", nil)
		req.Host = appHost

		rr := httptest.NewRecorder()
		MainHandler(rr, req)

		if rr.Code != 200 {
			t.Fatalf("status = %d; want 200 (body: %s)", rr.Code, rr.Body.String())
		}
		_, query, got := cap.get()
		if strings.Contains(query, "api_key") {
			t.Errorf("query = %q; api_key debe eliminarse antes del proxy", query)
		}
		if !strings.Contains(query, "y=2") {
			t.Errorf("query = %q; want conserva y=2", query)
		}
		if got.Get("Authorization") != "" {
			t.Errorf("Authorization = %q; want borrada cuando tokenUsed != \"\"", got.Get("Authorization"))
		}
	})

	t.Run("bypass X-REGIO-Bypass (ProxyHandler): conserva Authorization, borra X-API-Key", func(t *testing.T) {
		isolateState(t)
		backend, cap := newBackend(t, nil)
		setupProxy(t, backend.URL)
		const rawBypass = "contract-bypass-token"
		security.AddBypassKey(rawBypass, "contrato", appHost)
		t.Cleanup(func() { security.DeleteBypassKey(testBypassHash(rawBypass)) })

		req := httptest.NewRequest("GET", "/datos", nil)
		req.Host = appHost
		req.Header.Set("X-REGIO-Bypass", rawBypass)
		req.Header.Set("Authorization", "Bearer segreto")
		req.Header.Set("X-API-Key", "clave")
		req.AddCookie(&http.Cookie{Name: SessionKey, Value: "cookie-sesion-ajena"})
		req.AddCookie(&http.Cookie{Name: "backend", Value: "xyz"}) // cookie del backend

		rr := httptest.NewRecorder()
		MainHandler(rr, req)

		if rr.Code != 200 {
			t.Fatalf("status = %d; want 200 (body: %s)", rr.Code, rr.Body.String())
		}
		_, _, got := cap.get()
		// Regla unificada (fix deuda #2):
		//  - Authorization NO consumida por reGIO (la auth fue el bypass) ->
		//    se conserva: pertenece al backend, igual que con sesión de cookie.
		if got.Get("Authorization") != "Bearer segreto" {
			t.Errorf("Authorization = %q; want conservada (no fue consumida por reGIO)", got.Get("Authorization"))
		}
		//  - X-API-Key es cabecera de reGIO -> NUNCA se reenvía (antes la
		//    ruta bypass la filtraba al backend: era la divergencia peligrosa).
		if got.Get("X-API-Key") != "" {
			t.Errorf("X-API-Key = %q; want borrada en ambas rutas (cabecera de reGIO)", got.Get("X-API-Key"))
		}
		if got.Get("X-Forwarded-Host") != appHost {
			t.Errorf("X-Forwarded-Host = %q; want %q", got.Get("X-Forwarded-Host"), appHost)
		}
		// Mejora A1: también en la ruta bypass la sesión de reGIO no sale.
		cookieBackend := got.Get("Cookie")
		if strings.Contains(cookieBackend, SessionKey) {
			t.Errorf("Cookie = %q; la sesión de reGIO no debe filtrarse (ni en bypass)", cookieBackend)
		}
		if !strings.Contains(cookieBackend, "backend=xyz") {
			t.Errorf("Cookie = %q; want conservar backend=xyz", cookieBackend)
		}
	})

	t.Run("S4: Set-Cookie interno REGIO_ del backend se filtra", func(t *testing.T) {
		isolateState(t)
		backend, _ := newBackend(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Set-Cookie", "REGIO_session=hijacked; Path=/; Domain=.example.com")
			w.Header().Add("Set-Cookie", "REGIO_otra=1; Path=/")
			w.Header().Add("Set-Cookie", "JSESSIONID=backend123; Path=/")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		})
		setupProxy(t, backend.URL)
		seedSession(t, "s4-raw", &models.User{ID: 1, Username: "admin", IsAdmin: true, CSRFToken: "csrf-s4"})

		req := httptest.NewRequest("GET", "/x", nil)
		req.Host = appHost
		req.AddCookie(&http.Cookie{Name: SessionKey, Value: "s4-raw"})
		rr := httptest.NewRecorder()
		MainHandler(rr, req)

		if rr.Code != 200 {
			t.Fatalf("status = %d; want 200", rr.Code)
		}
		vistas := map[string]bool{}
		for _, c := range rr.Result().Cookies() {
			vistas[c.Name] = true
		}
		if vistas[SessionKey] || vistas["REGIO_otra"] {
			t.Errorf("cookies internas de reGIO llegaron al cliente: %v", vistas)
		}
		if !vistas["JSESSIONID"] {
			t.Error("la cookie del backend JSESSIONID debe conservarse")
		}
	})

	t.Run("S7a: Basic con token de app de reGIO NO llega al backend", func(t *testing.T) {
		isolateState(t)
		backend, cap := newBackend(t, nil)
		setupProxy(t, backend.URL)
		seedAppToken(t, "regio-token-abc123")
		seedSession(t, "s7a-raw", &models.User{ID: 1, Username: "admin", IsAdmin: true, CSRFToken: "csrf-s7a"})

		req := httptest.NewRequest("GET", "/x", nil)
		req.Host = appHost
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("cualquiera:regio-token-abc123")))
		req.AddCookie(&http.Cookie{Name: SessionKey, Value: "s7a-raw"})
		rr := httptest.NewRecorder()
		MainHandler(rr, req)

		if rr.Code != 200 {
			t.Fatalf("status = %d; want 200", rr.Code)
		}
		_, _, got := cap.get()
		if got.Get("Authorization") != "" {
			t.Errorf("Authorization = %q; un token de app de reGIO no debe filtrarse (S7)", got.Get("Authorization"))
		}
	})

	t.Run("S7b: Basic de la app (no es token reGIO) se conserva", func(t *testing.T) {
		isolateState(t)
		backend, cap := newBackend(t, nil)
		setupProxy(t, backend.URL)
		seedSession(t, "s7b-raw", &models.User{ID: 1, Username: "admin", IsAdmin: true, CSRFToken: "csrf-s7b"})

		basico := "Basic " + base64.StdEncoding.EncodeToString([]byte("appuser:contrasena-de-la-app"))
		req := httptest.NewRequest("GET", "/x", nil)
		req.Host = appHost
		req.Header.Set("Authorization", basico)
		req.AddCookie(&http.Cookie{Name: SessionKey, Value: "s7b-raw"})
		rr := httptest.NewRecorder()
		MainHandler(rr, req)

		if rr.Code != 200 {
			t.Fatalf("status = %d; want 200", rr.Code)
		}
		_, _, got := cap.get()
		if got.Get("Authorization") != basico {
			t.Errorf("Authorization = %q; el Basic de la app debe reenviarse intacto (S7)", got.Get("Authorization"))
		}
	})

	t.Run("rewrite de redirects: backend host -> host original + fuerza https", func(t *testing.T) {
		isolateState(t)
		backend, _ := newBackend(t, func(w http.ResponseWriter, r *http.Request) {
			// r.Host es ya el host del backend (remote.Host) tras la reescritura del proxy
			http.Redirect(w, r, "http://"+r.Host+"/nuevo", http.StatusFound)
		})
		setupProxy(t, backend.URL)
		seedSession(t, "proxy-raw-2", &models.User{ID: 1, Username: "admin", IsAdmin: true, CSRFToken: "csrf-proxy"})

		req := httptest.NewRequest("GET", "/redir", nil)
		req.Host = appHost
		req.AddCookie(&http.Cookie{Name: SessionKey, Value: "proxy-raw-2"})

		rr := httptest.NewRecorder()
		MainHandler(rr, req)

		if rr.Code != http.StatusFound {
			t.Fatalf("status = %d; want 302", rr.Code)
		}
		loc := rr.Header().Get("Location")
		if loc != "https://app.test/nuevo" {
			t.Errorf("Location = %q; want https://app.test/nuevo (host reescrito + https forzado)", loc)
		}
	})
}
