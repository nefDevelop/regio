package handlers

import (
	"net/url"
	"strings"
	"testing"
)

// FuzzSanitizeLogURI garantiza que la redacción de logs nunca paniquea y que
// la query nunca se filtra al log (propiedad de seguridad).
func FuzzSanitizeLogURI(f *testing.F) {
	f.Add("/admin")
	f.Add("/r-auth/secreto/ruta?password=x")
	f.Add("/x?" + strings.Repeat("y", 3000))
	f.Add("//../../etc?token=abc")

	f.Fuzz(func(t *testing.T, raw string) {
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		got := sanitizeLogURI(u)
		if u.RawQuery != "" {
			if strings.Contains(got, u.RawQuery) {
				t.Errorf("sanitizeLogURI(%q) = %q filtra la query", raw, got)
			}
			if !strings.HasSuffix(got, "?[redacted]") {
				t.Errorf("sanitizeLogURI(%q) = %q; want sufijo ?[redacted]", raw, got)
			}
		}
	})
}
