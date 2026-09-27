package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"regio/internal/db"
	"regio/internal/models"
	"regio/internal/security"
)

// TestGeoBlockedReturns403 verifica que una IP de país bloqueado recibe 403
// con un mensaje genérico (sin revelar la política).
func TestGeoBlockedReturns403(t *testing.T) {
	isolateState(t)

	if db.DB == nil {
		db.InitDB()
	}

	original := security.GetGlobalGeoPolicy()
	// Lista blanca ES + fail-closed: sin BD GeoIP cargada, todo se bloquea
	if err := security.SetGlobalGeoPolicy(security.GeoPolicy{
		Mode:      security.GeoModeAllow,
		Countries: []string{"ES"},
		FailMode:  security.GeoFailClosed,
	}); err != nil {
		t.Fatalf("configurando política de test: %v", err)
	}
	defer func() {
		_ = security.SetGlobalGeoPolicy(original)
		security.ResetRateLimiter()
	}()

	req := httptest.NewRequest("GET", "/some-service", nil)
	req.Host = "service.test"
	rr := httptest.NewRecorder()

	MainHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want %d", rr.Code, http.StatusForbidden)
	}
	if !strings.Contains(rr.Body.String(), "Acceso denegado desde tu región") {
		t.Errorf("body = %q; want mensaje genérico de región", rr.Body.String())
	}
	// No debe filtrar detalles de la política
	if strings.Contains(rr.Body.String(), "ES") || strings.Contains(rr.Body.String(), "fail") {
		t.Errorf("la respuesta no debe revelar la política: %q", rr.Body.String())
	}
}

// TestGeoFailOpenPasses verifica que con fail-open (sin BD GeoIP) el tráfico
// no se corta: la petición avanza hasta la lógica normal (401/redirect).
func TestGeoFailOpenPasses(t *testing.T) {
	isolateState(t)

	if db.DB == nil {
		db.InitDB()
	}

	original := security.GetGlobalGeoPolicy()
	if err := security.SetGlobalGeoPolicy(security.GeoPolicy{
		Mode:      security.GeoModeAllow,
		Countries: []string{"ES"},
		FailMode:  security.GeoFailOpen,
	}); err != nil {
		t.Fatalf("configurando política de test: %v", err)
	}
	defer func() {
		_ = security.SetGlobalGeoPolicy(original)
		security.ResetRateLimiter()
	}()

	req := httptest.NewRequest("GET", "/some-service", nil)
	req.Host = "service.test"
	rr := httptest.NewRecorder()

	MainHandler(rr, req)

	if rr.Code == http.StatusForbidden && strings.Contains(rr.Body.String(), "región") {
		t.Errorf("fail-open no debería bloquear por geografía, status=%d body=%q", rr.Code, rr.Body.String())
	}
}

// TestAdminRendersGeoSection verifica que el panel admin renderiza la sección
// de geobloqueo con los datos de la política y del lector GeoIP.
func TestAdminRendersGeoSection(t *testing.T) {
	isolateState(t)

	if db.DB == nil {
		db.InitDB()
	}

	token := "geo-admin-raw-token"
	seedSession(t, token, &models.User{
		ID:        1,
		Username:  "admin",
		IsAdmin:   true,
		CSRFToken: "csrf-geo-token",
	})

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(&http.Cookie{Name: SessionKey, Value: token})
	rr := httptest.NewRecorder()

	HandleAdmin(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"Filtrado por País (GeoIP)",
		"set_geo_policy",
		"geo_fail_mode",
		"Estado de la Base de Datos GeoIP",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("panel admin no contiene %q", want)
		}
	}
}
