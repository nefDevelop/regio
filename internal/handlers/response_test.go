package handlers

import (
	"net/url"
	"testing"
)

// TestSanitizeLogURI congela el comportamiento de redacción de logs (R3).
func TestSanitizeLogURI(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"ruta normal sin query", "/admin", "/admin"},
		{"query se redacta entera", "/buscar?q=secreto", "/buscar?[redacted]"},
		{"token de path redactado conservando la ruta final", "/r-auth/MITOKEN/dashboard", "/r-auth/[redacted]/dashboard"},
		{"token sin ruta posterior", "/r-auth/MITOKEN", "/r-auth/[redacted]"},
		{"token con doble barra final", "/r-auth/MITOKEN/", "/r-auth/[redacted]/"},
		{"query vacía no añade marcador", "/r-auth/TOK?x=1", "/r-auth/[redacted]?" + "[redacted]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.raw)
			if err != nil {
				t.Fatalf("parse %q: %v", tt.raw, err)
			}
			got := sanitizeLogURI(u)
			if got != tt.want {
				t.Errorf("sanitizeLogURI(%q) = %q; want %q", tt.raw, got, tt.want)
			}
		})
	}
}
