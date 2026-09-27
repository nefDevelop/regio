package handlers

import (
	"net/http/httptest"
	"testing"
)

// Benchmarks de los caminos calientes de handlers.

func BenchmarkSessionHash(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sessionHash("token-de-ejemplo-1234567890")
	}
}

func BenchmarkSanitizeLogURI(b *testing.B) {
	req := httptest.NewRequest("GET", "/r-auth/mi-token-largo/ruta/sensible?query=secreta", nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sanitizeLogURI(req.URL)
	}
}

// BenchmarkMainHandler_Health mide el overhead de entrada completo del
// MainHandler en su camino más barato (health sale antes del SecurityEngine).
func BenchmarkMainHandler_Health(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/health", nil)
		MainHandler(rr, req)
	}
}
