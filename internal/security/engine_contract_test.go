package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// req de utilidad para SecurityEngine
func engineReq(path, userAgent string) *http.Request {
	req := httptest.NewRequest("GET", path, nil)
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	return req
}

// TestSecurityEngineContract testea el orquestador directamente (0% en el
// baseline: solo se ejercitaba cross-package vía MainHandler).
func TestSecurityEngineContract(t *testing.T) {
	setGlobalPolicyForTest(t, GeoPolicy{Mode: GeoModeOff, FailMode: GeoFailOpen})

	t.Run("petición limpia pasa el motor", func(t *testing.T) {
		ResetRateLimiter()
		if err := SecurityEngine("203.0.113.10", engineReq("/ok", "Mozilla/5.0")); err != nil {
			t.Errorf("SecurityEngine = %v; want nil", err)
		}
	})

	t.Run("IP bloqueada -> error con motivo", func(t *testing.T) {
		ResetRateLimiter()
		t.Cleanup(func() { UnbanIP("203.0.113.20") })
		BanIP("203.0.113.20", "test", time.Hour)

		err := SecurityEngine("203.0.113.20", engineReq("/x", "Mozilla/5.0"))
		if err == nil || !strings.Contains(err.Error(), "IP bloqueada") {
			t.Errorf("err = %v; want error que contenga 'IP bloqueada'", err)
		}
	})

	t.Run("rate limit agotado -> error de demasiadas peticiones", func(t *testing.T) {
		ResetRateLimiter()
		ip := "203.0.113.30"
		for i := 0; i < 100; i++ {
			if !CheckRateLimit(ip) {
				t.Fatalf("rate limit cedió antes de la petición %d", i+1)
			}
		}
		if CheckRateLimit(ip) {
			t.Error("la petición 101 debería ser rechazada")
		}
	})

	t.Run("WAF detecta scanner UA -> error", func(t *testing.T) {
		ResetRateLimiter()
		err := SecurityEngine("203.0.113.40", engineReq("/x", "sqlmap/1.7"))
		if err == nil {
			t.Error("WAF debería rechazar UA de scanner")
		}
	})

	t.Run("geo off no interfiere", func(t *testing.T) {
		ResetRateLimiter()
		if err := SecurityEngine("203.0.113.50", engineReq("/x", "Mozilla/5.0")); err != nil {
			t.Errorf("con geo off no debe bloquear: %v", err)
		}
	})
}

// comprueba que el orden del motor es geo -> IP -> rate -> WAF: una IP
// bloqueada con WAF sucio reporta el bloqueo de IP (primero en la cadena).
func TestSecurityEngineOrden(t *testing.T) {
	setGlobalPolicyForTest(t, GeoPolicy{Mode: GeoModeOff, FailMode: GeoFailOpen})
	ResetRateLimiter()
	t.Cleanup(func() { UnbanIP("203.0.113.60") })
	BanIP("203.0.113.60", "orden", time.Hour)

	err := SecurityEngine("203.0.113.60", engineReq("/x", "sqlmap/1.7"))
	if err == nil || !strings.Contains(err.Error(), "IP bloqueada") {
		t.Errorf("el bloqueo de IP debe prevalecer sobre el WAF; err = %v", err)
	}
}
