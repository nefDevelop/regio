package security

import (
	"net"
	"net/http/httptest"
	"testing"
)

// Benchmarks de los caminos calientes del SecurityEngine.
// Excluye a propósito Argon2 (auth): su coste es intencionado.

func BenchmarkCheckWAF_PeticiónLimpia(b *testing.B) {
	req := httptest.NewRequest("GET", "/api/v1/users/42?fields=name,email", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = CheckWAF(req)
	}
}

func BenchmarkCheckWAF_AtaqueSQLi(b *testing.B) {
	req := httptest.NewRequest("GET", "/x?q=%27%20OR%201%3D1--", nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = CheckWAF(req)
	}
}

func BenchmarkCheckRateLimit(b *testing.B) {
	ResetRateLimiter()
	ip := "198.18.0.1"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if i%100 == 0 {
			b.StopTimer()
			ResetRateLimiter()
			b.StartTimer()
		}
		CheckRateLimit(ip)
	}
}

func BenchmarkIsIPBlocked(b *testing.B) {
	UnbanIP("198.18.0.2") // estado limpio
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		IsIPBlocked("198.18.0.2")
	}
}

// benchGeoPolicy fija la política global para el benchmark y devuelve la
// función de restauración (los benchmarks comparten proceso con los tests).
func benchGeoPolicy(b *testing.B, p GeoPolicy) func() {
	b.Helper()
	prev := GetGlobalGeoPolicy()
	if err := SetGlobalGeoPolicy(p); err != nil {
		b.Fatalf("policy: %v", err)
	}
	origLookup := lookupCountryFunc
	return func() {
		_ = SetGlobalGeoPolicy(prev)
		lookupCountryFunc = origLookup
	}
}

func BenchmarkCheckGeoPolicy_Off(b *testing.B) {
	defer benchGeoPolicy(b, GeoPolicy{Mode: GeoModeOff, FailMode: GeoFailOpen})()
	lookupCountryFunc = func(ip net.IP) (string, error) { return "ES", nil }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = CheckGeoPolicy("198.18.0.3", "app.test")
	}
}

func BenchmarkCheckGeoPolicy_AllowConLookup(b *testing.B) {
	defer benchGeoPolicy(b, GeoPolicy{Mode: GeoModeAllow, Countries: []string{"ES"}, FailMode: GeoFailOpen})()
	lookupCountryFunc = func(ip net.IP) (string, error) { return "ES", nil }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = CheckGeoPolicy("198.18.0.4", "app.test")
	}
}

func BenchmarkParseCountries(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseCountries("ES, FR, DE, IT, PT")
	}
}
