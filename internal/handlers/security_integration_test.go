package handlers

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"regio/internal/db"
	"regio/internal/models"
	"regio/internal/security"
)

// TestCSRFValidation verifica que las acciones POST requieren token CSRF válido.
func TestCSRFValidation(t *testing.T) {
	// Simular una sesión activa
	testToken := "test-session-hash"
	Mu.Lock()
	ActiveSessions[testToken] = &models.User{
		ID:        1,
		Username:  "admin",
		IsAdmin:   true,
		CSRFToken: "valid-csrf-token-123",
	}
	Mu.Unlock()
	defer func() {
		Mu.Lock()
		delete(ActiveSessions, testToken)
		Mu.Unlock()
	}()

	tests := []struct {
		name           string
		csrfToken      string
		expectedStatus int
	}{
		{"Sin CSRF token", "", http.StatusForbidden},
		{"CSRF token incorrecto", "wrong-token", http.StatusForbidden},
		{"CSRF token válido", "valid-csrf-token-123", http.StatusSeeOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Set("accion", "delete_service")
			form.Set("host", "nonexistent.test")
			if tt.csrfToken != "" {
				form.Set("csrf_token", tt.csrfToken)
			}

			req := httptest.NewRequest("POST", "/admin", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Host = "admin.test"
			req.AddCookie(&http.Cookie{Name: SessionKey, Value: "raw-token-for-test"})

			// Mock: hacer que sessionHash("raw-token-for-test") == testToken
			// Como no podemos controlar el hash, usamos directamente el token hasheado
			// Reconfigurar la sesión con el hash real
			realHash := sessionHash("raw-token-for-test")
			Mu.Lock()
			ActiveSessions[realHash] = ActiveSessions[testToken]
			Mu.Unlock()
			defer func() {
				Mu.Lock()
				delete(ActiveSessions, realHash)
				Mu.Unlock()
			}()

			rr := httptest.NewRecorder()
			HandleAdmin(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("%s: got status %d, want %d", tt.name, rr.Code, tt.expectedStatus)
			}
		})
	}
}

// TestSSRFProtection verifica que isValidTarget bloquea IPs privadas y loopback.
func TestSSRFProtection(t *testing.T) {
	tests := []struct {
		target   string
		blocked  bool
		scenario string
	}{
		// Debe bloquear
		{"http://localhost:8080", true, "Loopback localhost"},
		{"http://127.0.0.1:8080", true, "Loopback IPv4"},
		{"http://[::1]:8080", true, "Loopback IPv6"},
		{"http://169.254.1.1:80", true, "Link-local IPv4"},

		// Debe permitir (RFC 1918 para servicios internos)
		{"http://10.0.0.1:80", false, "RFC1918 clase A"},
		{"http://172.16.0.1:80", false, "RFC1918 clase B"},
		{"http://172.31.255.255:80", false, "RFC1918 clase B límite"},
		{"http://192.168.1.1:80", false, "RFC1918 clase C"},

		// Debe permitir
		{"http://8.8.8.8:80", false, "IP pública Google DNS"},
		{"http://1.1.1.1:80", false, "IP pública Cloudflare"},
		{"https://example.com", false, "Dominio público HTTPS"},

		// Esquemas inválidos
		{"ftp://example.com", true, "Esquema FTP"},
		{"file:///etc/passwd", true, "Esquema file://"},
		{"javascript:alert(1)", true, "Esquema javascript"},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			err := security.IsValidTarget(tt.target)
			if tt.blocked && err == nil {
				t.Errorf("isValidTarget(%s) debería estar BLOQUEADO pero fue permitido", tt.target)
			}
			if !tt.blocked && err != nil {
				t.Errorf("isValidTarget(%s) debería estar PERMITIDO pero fue bloqueado: %v", tt.target, err)
			}
		})
	}
}

// TestIsPrivateIPv6 verifica la corrección del bug de precedencia en isPrivateIP.
func TestIsPrivateIPv6(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
		desc     string
	}{
		{"fc00::1", true, "IPv6 ULA fc00::1"},
		{"fd12:3456::1", true, "IPv6 ULA fd12"},
		{"2001:db8::1", false, "IPv6 documentation prefix"},
		{"::1", true, "IPv6 loopback"},
		{"fe80::1", true, "IPv6 link-local"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("No se pudo parsear IP: %s", tt.ip)
			}
			result := security.IsPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

// TestRateLimitPerUser verifica el bloqueo de cuentas por fuerza bruta distribuida.
func TestRateLimitPerUser(t *testing.T) {
	username := "victima"

	// 9 fallos no deben bloquear
	for i := 0; i < 9; i++ {
		security.RegistrarFalloUsuario(username)
		if security.IsUserBlocked(username) {
			t.Errorf("Usuario bloqueado prematuramente en intento %d", i+1)
		}
	}

	// El 10º fallo debe bloquear
	security.RegistrarFalloUsuario(username)
	if !security.IsUserBlocked(username) {
		t.Error("Usuario NO bloqueado tras 10 intentos")
	}

	// Resetear intentos (simula login exitoso)
	security.ResetearIntentosUsuario(username)
	if security.IsUserBlocked(username) {
		t.Error("Usuario sigue bloqueado después de resetear")
	}
}

// TestSessionHashConsistency verifica que sessionHash es determinista.
func TestSessionHashConsistency(t *testing.T) {
	token := "test-token-consistency"
	hash1 := sessionHash(token)
	hash2 := sessionHash(token)

	if hash1 != hash2 {
		t.Errorf("sessionHash no es determinista: %s != %s", hash1, hash2)
	}

	// Tokens diferentes deben producir hashes diferentes
	hash3 := sessionHash("different-token")
	if hash1 == hash3 {
		t.Error("Tokens diferentes producen el mismo hash")
	}
}

// TestNoCookiePanic verifica que HandleAdmin y HandleProfile no paniquean sin cookie (C01).
func TestNoCookiePanic(t *testing.T) {
	AdminDomain = "admin.test"
	NeedsSetup = false

	t.Run("HandleAdmin sin cookie retorna 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin", nil)
		req.Host = "admin.test"
		rr := httptest.NewRecorder()
		HandleAdmin(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("HandleAdmin sin cookie: got %d, want %d", rr.Code, http.StatusUnauthorized)
		}
	})

	t.Run("HandleProfile sin cookie redirige a login", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/profile", nil)
		req.Host = "admin.test"
		rr := httptest.NewRecorder()
		HandleProfile(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Errorf("HandleProfile sin cookie: got %d, want %d", rr.Code, http.StatusSeeOther)
		}
	})
}

// TestGetRealIP verifica la extracción correcta de IP con X-Forwarded-For (A04).
func TestGetRealIP(t *testing.T) {
	savedProxies := TrustedProxies
	TrustedProxies = []string{"10.0.0.1"}
	defer func() { TrustedProxies = savedProxies }()

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		cf         string
		expected   string
	}{
		{
			name:       "X-Forwarded-For toma primera IP",
			remoteAddr: "10.0.0.1:1234",
			xff:        "1.2.3.4, 10.0.0.1",
			expected:   "1.2.3.4",
		},
		{
			name:       "CF-Connecting-IP tiene prioridad",
			remoteAddr: "10.0.0.1:1234",
			xff:        "1.2.3.4, 10.0.0.1",
			cf:         "5.6.7.8",
			expected:   "5.6.7.8",
		},
		{
			name:       "Sin proxy de confianza usa RemoteAddr",
			remoteAddr: "9.9.9.9:1234",
			expected:   "9.9.9.9",
		},
		{
			name:       "Sin X-Forwarded-For usa RemoteAddr",
			remoteAddr: "10.0.0.1:1234",
			expected:   "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.cf != "" {
				req.Header.Set("CF-Connecting-IP", tt.cf)
			}
			result := getRealIP(req)
			if result != tt.expected {
				t.Errorf("getRealIP() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestPasswordMinimumLength verifica que el mínimo de contraseña es 12 caracteres (B05).
func TestPasswordMinimumLength(t *testing.T) {
	t.Run("HandleLogin set_password rechaza <12 chars", func(t *testing.T) {
		// Crear un usuario sin contraseña (invitación) para llegar al check de longitud
		inviteToken := "test-invite-token-123"
		db.DB.Exec("DELETE FROM users")
		db.DB.Exec("INSERT INTO users (id, username, password_hash, invite_token, is_admin) VALUES (99, 'newuser', '', ?, 0)", inviteToken)

		form := url.Values{}
		form.Set("user", "newuser")
		form.Set("new_pass", "short")
		form.Set("confirm_pass", "short")
		form.Set("step", "set_password")

		req := httptest.NewRequest("POST", "/REGIO-login?"+url.Values{"invite_token": {inviteToken}}.Encode(), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = "admin.test"
		rr := httptest.NewRecorder()
		HandleLogin(rr, req, "1.2.3.4")

		// En caso de error renderiza el template (status 200), no redirige (StatusSeeOther)
		if rr.Code == http.StatusSeeOther {
			t.Error("HandleLogin aceptó contraseña de menos de 12 caracteres")
		}
	})
}

// TestPasswordMinimumLengthSetup verifica que setup rechaza <12 chars (B05).
func TestPasswordMinimumLengthSetup(t *testing.T) {
	Mu.Lock()
	NeedsSetup = true
	Mu.Unlock()
	defer func() {
		Mu.Lock()
		NeedsSetup = false
		Mu.Unlock()
	}()

	t.Run("HandleSetup rechaza <12 chars", func(t *testing.T) {
		db.DB.Exec("DELETE FROM users")
		form := url.Values{}
		form.Set("user", "admin")
		form.Set("pass", "short")

		req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = "admin.test"
		rr := httptest.NewRecorder()
		HandleSetup(rr, req)

		if rr.Code == http.StatusSeeOther {
			t.Error("HandleSetup aceptó contraseña de menos de 12 caracteres")
		}
	})

	t.Run("HandleSetup acepta >=12 chars", func(t *testing.T) {
		db.DB.Exec("DELETE FROM users")
		form := url.Values{}
		form.Set("user", "admin2")
		form.Set("pass", "this-is-a-long-password")

		req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = "admin.test"
		rr := httptest.NewRecorder()
		HandleSetup(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Errorf("HandleSetup debería aceptar contraseña larga, got %d", rr.Code)
		}
	})
}

// TestLastAdminProtection verifica que no se pueda eliminar el último admin (B03).
func TestLastAdminProtection(t *testing.T) {
	// Asegurar que hay un solo admin diferente de ID 1 en DB
	db.DB.Exec("DELETE FROM users")
	db.DB.Exec("INSERT OR REPLACE INTO users (id, username, is_admin) VALUES (2, 'onlyadmin', 1)")

	realHash := sessionHash("admin-session-token")
	Mu.Lock()
	ActiveSessions[realHash] = &models.User{
		ID:        2,
		Username:  "onlyadmin",
		IsAdmin:   true,
		CSRFToken: "csrf-admin-123",
	}
	Mu.Unlock()
	defer func() {
		Mu.Lock()
		delete(ActiveSessions, realHash)
		Mu.Unlock()
	}()

	form := url.Values{}
	form.Set("accion", "delete_user")
	form.Set("del_user", "onlyadmin")
	form.Set("csrf_token", "csrf-admin-123")

	req := httptest.NewRequest("POST", "/admin", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "admin.test"
	req.AddCookie(&http.Cookie{Name: SessionKey, Value: "admin-session-token"})

	rr := httptest.NewRecorder()
	HandleAdmin(rr, req)

	// No redirige (303) — significa que rechazó la operación
	if rr.Code == http.StatusSeeOther {
		t.Errorf("Debería rechazar eliminar último admin, got 303. Cuerpo: %s", rr.Body.String())
	}
}

// TestCSRFRotation verifica que el token CSRF se rota tras uso exitoso (M06).
func TestCSRFRotation(t *testing.T) {
	realHash := sessionHash("rotation-test-token")
	Mu.Lock()
	ActiveSessions[realHash] = &models.User{
		ID:        1,
		Username:  "admin2",
		IsAdmin:   true,
		CSRFToken: "original-csrf-token",
	}
	Mu.Unlock()
	defer func() {
		Mu.Lock()
		delete(ActiveSessions, realHash)
		Mu.Unlock()
	}()

	// Primera petición: token CSRF válido, debe funcionar
	form := url.Values{}
	form.Set("accion", "add_service")
	form.Set("host", "test-csrf-rotation.local")
	form.Set("target", "http://192.168.1.100:8080")
	form.Set("csrf_token", "original-csrf-token")

	req := httptest.NewRequest("POST", "/admin", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "admin.test"
	req.AddCookie(&http.Cookie{Name: SessionKey, Value: "rotation-test-token"})

	rr := httptest.NewRecorder()
	HandleAdmin(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Primera petición CSRF debería funcionar, got %d", rr.Code)
	}

	// Verificar que el token CSRF cambió en la sesión
	Mu.Lock()
	user := ActiveSessions[realHash]
	Mu.Unlock()
	if user.CSRFToken == "original-csrf-token" {
		t.Error("El token CSRF no fue rotado después del uso exitoso")
	}

	// Segunda petición: con el token original (ahora viejo), debe fallar
	form2 := url.Values{}
	form2.Set("accion", "add_service")
	form2.Set("host", "test-csrf-rotation2.local")
	form2.Set("target", "http://192.168.1.101:8080")
	form2.Set("csrf_token", "original-csrf-token")

	req2 := httptest.NewRequest("POST", "/admin", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Host = "admin.test"
	req2.AddCookie(&http.Cookie{Name: SessionKey, Value: "rotation-test-token"})

	rr2 := httptest.NewRecorder()
	HandleAdmin(rr2, req2)

	if rr2.Code != http.StatusForbidden {
		t.Errorf("Token CSRF viejo debería ser rechazado, got %d", rr2.Code)
	}
}

// TestUnauthenticatedAccess verifica que las rutas protegidas requieren autenticación.
func TestUnauthenticatedAccess(t *testing.T) {
	AdminDomain = "admin.test"
	NeedsSetup = false

	protectedPaths := []struct {
		path string
		host string
	}{
		{"/admin", "admin.test"},
		{"/profile", "admin.test"},
		{"/", "admin.test"},
		{"/some-service", "service.test"},
	}

	for _, pp := range protectedPaths {
		t.Run(pp.path+"@"+pp.host, func(t *testing.T) {
			req := httptest.NewRequest("GET", pp.path, nil)
			req.Host = pp.host
			req.Header.Set("Accept", "text/html")
			rr := httptest.NewRecorder()

			MainHandler(rr, req)

			// Debe redirigir a login o devolver 401
			if rr.Code != http.StatusSeeOther && rr.Code != http.StatusUnauthorized {
				t.Errorf("Ruta %s@%s accesible sin auth: status %d", pp.path, pp.host, rr.Code)
			}
		})
	}
}

// TestSecurityHeaders verifica que todos los headers de seguridad están presentes.
func TestSecurityHeaders(t *testing.T) {
	AdminDomain = "admin.test"
	NeedsSetup = false

	req := httptest.NewRequest("GET", "/REGIO-login", nil)
	req.Host = "admin.test"
	rr := httptest.NewRecorder()

	MainHandler(rr, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-Xss-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
	}

	for header, expected := range expectedHeaders {
		got := rr.Header().Get(header)
		if got != expected {
			t.Errorf("Header %s = %q, want %q", header, got, expected)
		}
	}

	// CSP debe existir
	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header faltante")
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP no contiene default-src 'self': %s", csp)
	}
}
