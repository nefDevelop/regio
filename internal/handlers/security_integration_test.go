package handlers

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"regio/internal/models"
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
			err := isValidTarget(tt.target)
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
			result := isPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

// TestRateLimitPerUser verifica el bloqueo de cuentas por fuerza bruta distribuida.
func TestRateLimitPerUser(t *testing.T) {
	// Limpiar estado
	Mu.Lock()
	intentosUsuario = make(map[string]*models.Intento)
	Mu.Unlock()

	username := "victima"

	// 9 fallos no deben bloquear
	for i := 0; i < 9; i++ {
		RegistrarFalloUsuario(username)
		if IsUserBlocked(username) {
			t.Errorf("Usuario bloqueado prematuramente en intento %d", i+1)
		}
	}

	// El 10º fallo debe bloquear
	RegistrarFalloUsuario(username)
	if !IsUserBlocked(username) {
		t.Error("Usuario NO bloqueado tras 10 intentos")
	}

	// Resetear intentos (simula login exitoso)
	ResetearIntentosUsuario(username)
	if IsUserBlocked(username) {
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
