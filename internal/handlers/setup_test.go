package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"regio/internal/db"
)

func init() {
	if db.DB == nil {
		db.InitDB()
	}
	if Tmpls == nil {
		Init()
	}
}

// TestSetupFlow_FullInstall verifica el ciclo completo de instalación:
// GET formulario → POST válidos → redirect a login → NeedsSetup=false.
func TestSetupFlow_FullInstall(t *testing.T) {
	isolateState(t)
	cleanUsers(t)

	Mu.Lock()
	NeedsSetup = true
	Mu.Unlock()
	defer func() {
		Mu.Lock()
		NeedsSetup = false
		Mu.Unlock()
	}()

	t.Run("GET /setup muestra formulario", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/setup", nil)
		req.Host = "admin.test"
		rr := httptest.NewRecorder()
		HandleSetup(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("GET /setup status = %d; want 200", rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "Crea tu cuenta de administrador") {
			t.Error("GET /setup no contiene el formulario de instalación")
		}
		if !strings.Contains(body, "Finalizar Instalación") {
			t.Error("GET /setup no contiene el botón de submit")
		}
	})

	t.Run("POST con credenciales válidas → 303 a login", func(t *testing.T) {
		form := url.Values{}
		form.Set("user", "admin-inst")
		form.Set("pass", "segura-para-test-123")

		req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = "admin.test"
		rr := httptest.NewRecorder()
		HandleSetup(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Errorf("POST /setup válido status = %d; want 303", rr.Code)
		}
		loc := rr.Header().Get("Location")
		if loc != "/REGIO-login" {
			t.Errorf("POST /setup válido redirect = %q; want /REGIO-login", loc)
		}

		Mu.Lock()
		ns := NeedsSetup
		Mu.Unlock()
		if ns {
			t.Error("NeedsSetup debe ser false tras instalación exitosa")
		}

		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'admin-inst'").Scan(&count)
		if count != 1 {
			t.Errorf("usuario admin no creado, COUNT = %d; want 1", count)
		}
	})

	t.Run("GET /setup tras instalación → redirect a login", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/setup", nil)
		req.Host = "admin.test"
		rr := httptest.NewRecorder()
		HandleSetup(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Errorf("GET /setup post-install status = %d; want 303", rr.Code)
		}
		if loc := rr.Header().Get("Location"); loc != "/REGIO-login" {
			t.Errorf("redirect = %q; want /REGIO-login", loc)
		}
	})
}

// TestSetupFlow_ShortPassword verifica que contraseñas <12 chars rechazan
// con mensaje de error visible.
func TestSetupFlow_ShortPassword(t *testing.T) {
	isolateState(t)
	cleanUsers(t)

	Mu.Lock()
	NeedsSetup = true
	Mu.Unlock()
	defer func() {
		Mu.Lock()
		NeedsSetup = false
		Mu.Unlock()
	}()

	form := url.Values{}
	form.Set("user", "admin")
	form.Set("pass", "corta")

	req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "admin.test"
	rr := httptest.NewRecorder()
	HandleSetup(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("POST /setup pass corta status = %d; want 200 (re-render con error)", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "al menos 8 caracteres") {
		t.Error("respuesta no contiene mensaje de error de contraseña")
	}

	var count int
	db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count != 0 {
		t.Errorf("no debe crearse usuario con pass corta, COUNT = %d", count)
	}
}

// TestSetupFlow_EmptyUser verifica que usuario vacío rechaza con error.
func TestSetupFlow_EmptyUser(t *testing.T) {
	isolateState(t)
	cleanUsers(t)

	Mu.Lock()
	NeedsSetup = true
	Mu.Unlock()
	defer func() {
		Mu.Lock()
		NeedsSetup = false
		Mu.Unlock()
	}()

	form := url.Values{}
	form.Set("user", "")
	form.Set("pass", "contraseña-larga-123")

	req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "admin.test"
	rr := httptest.NewRecorder()
	HandleSetup(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("POST /setup user vacío status = %d; want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "usuario") {
		t.Error("respuesta no contiene mensaje de error de usuario")
	}
}

// TestSetupFlow_CSRFBlock verifica que POST con Origin externo es rechazado.
func TestSetupFlow_CSRFBlock(t *testing.T) {
	isolateState(t)
	cleanUsers(t)

	Mu.Lock()
	NeedsSetup = true
	Mu.Unlock()
	defer func() {
		Mu.Lock()
		NeedsSetup = false
		Mu.Unlock()
	}()

	form := url.Values{}
	form.Set("user", "admin")
	form.Set("pass", "contraseña-larga-123")

	req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.com")
	req.Host = "admin.test"
	rr := httptest.NewRecorder()
	HandleSetup(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("POST /setup CSRF status = %d; want 403", rr.Code)
	}

	var count int
	db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count != 0 {
		t.Error("no debe crearse usuario con Origin externo")
	}
}

// TestSetupFlow_NoOriginAllowed verifica que POST sin Origin/Referer se acepta
// (clientes nativos/curl no los envían).
func TestSetupFlow_NoOriginAllowed(t *testing.T) {
	isolateState(t)
	cleanUsers(t)

	Mu.Lock()
	NeedsSetup = true
	Mu.Unlock()
	defer func() {
		Mu.Lock()
		NeedsSetup = false
		Mu.Unlock()
	}()

	form := url.Values{}
	form.Set("user", "admin-curl")
	form.Set("pass", "contraseña-larga-123")

	req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "admin.test"
	rr := httptest.NewRecorder()
	HandleSetup(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("POST /setup sin Origin status = %d; want 303", rr.Code)
	}
}

// TestSetupFlow_AlreadyCompleted verifica que si NeedsSetup=false, POST/GET
// redirigen a /REGIO-login.
func TestSetupFlow_AlreadyCompleted(t *testing.T) {
	isolateState(t)
	cleanUsers(t)

	Mu.Lock()
	NeedsSetup = false
	Mu.Unlock()

	req := httptest.NewRequest("POST", "/setup", nil)
	req.Host = "admin.test"
	rr := httptest.NewRecorder()
	HandleSetup(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("POST /setup ya instalado status = %d; want 303", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/REGIO-login" {
		t.Errorf("redirect = %q; want /REGIO-login", loc)
	}
}

// TestSetupFlow_MinPasswordBoundary verifica la frontera exacta de 12 caracteres.
func TestSetupFlow_MinPasswordBoundary(t *testing.T) {
	isolateState(t)
	cleanUsers(t)

	Mu.Lock()
	NeedsSetup = true
	Mu.Unlock()
	defer func() {
		Mu.Lock()
		NeedsSetup = false
		Mu.Unlock()
	}()

	tests := []struct {
		name     string
		pass     string
		wantCode int
	}{
		{"7 chars rechaza", "1234567", http.StatusOK},
		{"8 chars acepta", "12345678", http.StatusSeeOther},
		{"9 chars acepta", "123456789", http.StatusSeeOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db.DB.Exec("DELETE FROM users")
			Mu.Lock()
			NeedsSetup = true
			Mu.Unlock()

			form := url.Values{}
			form.Set("user", "admin-boundary")
			form.Set("pass", tt.pass)

			req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Host = "admin.test"
			rr := httptest.NewRecorder()
			HandleSetup(rr, req)

			if rr.Code != tt.wantCode {
				t.Errorf("pass %d chars → status = %d; want %d", len(tt.pass), rr.Code, tt.wantCode)
			}
		})
	}
}

// TestSetupCSP verifica que la página de instalación usa SetupCSP
// (más permisivo) en lugar del DefaultCSP.
func TestSetupCSP(t *testing.T) {
	isolateState(t)

	Mu.Lock()
	NeedsSetup = true
	Mu.Unlock()
	defer func() {
		Mu.Lock()
		NeedsSetup = false
		Mu.Unlock()
	}()

	req := httptest.NewRequest("GET", "/setup", nil)
	req.Host = "admin.test"
	rr := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rr, status: http.StatusOK}
	MainHandler(sw, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action") {
		t.Errorf("CSP de setup no contiene form-action: %s", csp)
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP de setup no contiene default-src: %s", csp)
	}
}
