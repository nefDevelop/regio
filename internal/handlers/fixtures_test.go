package handlers

import (
	"crypto/sha256"
	"encoding/base64"
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

// testBypassHash replica el algoritmo de security.bypassHash (SHA-256 +
// base64 RawURL) para poder calcular el hash y limpiar claves de bypass
// registradas por los tests.
func testBypassHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// isolateState congela las globales del paquete handlers y el estado de
// seguridad compartido (rate limiter, bans, AllowedNetworks), las deja en un
// baseline determinista y las restaura automáticamente al terminar el test.
//
// Regla: debe ser la PRIMERA llamada de todo test que toque estado global;
// la configuración concreta del test se aplica DESPUÉS de invocarla.
func isolateState(t *testing.T) {
	t.Helper()

	// --- snapshot del estado previo ---
	Mu.Lock()
	savedConfig := Config
	savedNeedsSetup := NeedsSetup
	savedAdminDomain := AdminDomain
	savedSessions := make(map[string]*models.User, len(ActiveSessions))
	for k, v := range ActiveSessions {
		savedSessions[k] = v
	}
	Mu.Unlock()

	savedTrustedProxies := TrustedProxies
	savedAllowedNetworks := append([]net.IPNet(nil), security.AllowedNetworks...)
	savedIntentos := make(map[string]*models.Intento, len(security.IntentosDB))
	for k, v := range security.IntentosDB {
		copia := *v
		savedIntentos[k] = &copia
	}

	// --- baseline determinista durante el test ---
	Mu.Lock()
	Config = models.Config{
		Servicios:     make(map[string]string),
		Publicos:      make(map[string]bool),
		BypassHeaders: make(map[string]string),
		CSPs:          make(map[string]string),
		GeoModes:      make(map[string]string),
		GeoCountries:  make(map[string]string),
	}
	NeedsSetup = false
	AdminDomain = "admin.test"
	ActiveSessions = make(map[string]*models.User)
	Mu.Unlock()

	TrustedProxies = nil
	security.AllowedNetworks = nil
	security.IntentosDB = make(map[string]*models.Intento)
	security.ResetRateLimiter()

	t.Cleanup(func() {
		security.ResetRateLimiter()
		security.IntentosDB = savedIntentos
		security.AllowedNetworks = savedAllowedNetworks
		TrustedProxies = savedTrustedProxies

		Mu.Lock()
		Config = savedConfig
		NeedsSetup = savedNeedsSetup
		AdminDomain = savedAdminDomain
		ActiveSessions = savedSessions
		Mu.Unlock()
	})
}

// cleanUsers vacía la tabla users (y sus tablas hijas con FK: app_tokens,
// sessions) antes y después del test. Con `PRAGMA foreign_keys=ON`, borrar
// users sin limpiar antes los hijos falla con FOREIGN KEY constraint — de
// ahí que los deletes se hagan en orden hijos→padre y con error verificado.
func cleanUsers(t *testing.T) {
	t.Helper()
	if db.DB == nil {
		db.InitDB()
	}
	wipe := func() {
		// Orden: hijos primero (FK REFERENCES users(id))
		for _, tabla := range []string{"app_tokens", "sessions", "users"} {
			if _, err := db.DB.Exec("DELETE FROM " + tabla); err != nil {
				t.Errorf("limpiando tabla %s: %v", tabla, err)
			}
		}
	}
	wipe()
	t.Cleanup(wipe)
}

// seedSession registra una sesión activa cuyo hash coincide con sessionHash(rawToken)
// y la elimina al terminar el test.
func seedSession(t *testing.T, rawToken string, user *models.User) string {
	t.Helper()
	h := sessionHash(rawToken)
	Mu.Lock()
	ActiveSessions[h] = user
	Mu.Unlock()
	t.Cleanup(func() {
		Mu.Lock()
		delete(ActiveSessions, h)
		Mu.Unlock()
	})
	return h
}

// postAdmin envía un formulario POST al panel admin con la cookie de sesión
// indicada (rawToken) y devuelve el recorder.
func postAdmin(t *testing.T, rawToken string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/admin", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "admin.test"
	req.AddCookie(&http.Cookie{Name: SessionKey, Value: rawToken})
	rr := httptest.NewRecorder()
	HandleAdmin(rr, req)
	return rr
}

// getAdmin envía una petición GET al panel admin con la cookie indicada.
func getAdmin(t *testing.T, rawToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/admin", nil)
	req.Host = "admin.test"
	req.AddCookie(&http.Cookie{Name: SessionKey, Value: rawToken})
	rr := httptest.NewRecorder()
	HandleAdmin(rr, req)
	return rr
}

// seedAdminUser crea un usuario administrador en la DB (para acciones que
// consultan la tabla users). El vaciado lo garantiza cleanUsers.
func seedAdminUser(t *testing.T, id int, username string) {
	t.Helper()
	if _, err := db.DB.Exec("INSERT OR REPLACE INTO users (id, username, is_admin) VALUES (?, ?, 1)", id, username); err != nil {
		t.Fatalf("creando admin %s: %v", username, err)
	}
}
