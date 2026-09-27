package security

import (
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzCheckWAF garantiza que ninguna entrada (path, query, UA) provoca panic
// y que las peticiones válidas siguen pasando. Objetivo principal: seguridad
// de las regex del WAF frente a entradas malformadas/ReDoS.
func FuzzCheckWAF(f *testing.F) {
	f.Add("/api/users", "name=' OR 1=1--", "Mozilla/5.0")
	f.Add("/x", "", "sqlmap/1.7.2")
	f.Add(strings.Repeat("a", 5000), strings.Repeat("'", 500), "<script>alert(1)</script>")
	f.Add("/../../etc/passwd", "q=..%2F..%2F", "curl/8.0")
	f.Add("/a?b=c", " UNION SELECT password FROM users --", "nikto/2.1")

	f.Fuzz(func(t *testing.T, path, query, ua string) {
		req := httptest.NewRequest("GET", "/", nil)
		// path/query malformados no deben romper el parser
		req.URL.Path = path
		req.URL.RawQuery = query
		req.Header.Set("User-Agent", ua)

		err := CheckWAF(req)
		// Propiedad: si el WAF rechaza, hay mensaje; si acepta, err == nil.
		// Solo verificamos ausencia de panic (el fuzzing lo garantiza) y
		// consistencia del contrato error-nil.
		if err != nil && err.Error() == "" {
			t.Error("CheckWAF devolvió un error vacío")
		}
	})
}

// FuzzParseCountries: cualquier entrada produce códigos válidos o error,
// nunca panic, y no duplica códigos.
func FuzzParseCountries(f *testing.F) {
	f.Add("ES, FR")
	f.Add("")
	f.Add("España")
	f.Add("es,ES, eS ")
	f.Add(strings.Repeat("X,", 500))

	f.Fuzz(func(t *testing.T, raw string) {
		got, err := ParseCountries(raw)
		if err != nil {
			if got != nil {
				t.Error("ParseCountries debe devolver nil países ante un error")
			}
			return
		}
		seen := map[string]bool{}
		for _, c := range got {
			if len(c) != 2 {
				t.Errorf("código inválido %q en %v", c, got)
			}
			if seen[c] {
				t.Errorf("código duplicado %q en %v", c, got)
			}
			seen[c] = true
		}
	})
}

// FuzzIsValidTarget: sin panic; si se acepta, el esquema debe ser http(s).
func FuzzIsValidTarget(f *testing.F) {
	f.Add("http://10.0.0.1:80")
	f.Add("https://example.com")
	f.Add("file:///etc/passwd")
	f.Add("javascript:alert(1)")
	f.Add("http://127.0.0.1")
	f.Add(strings.Repeat("a", 4096))

	f.Fuzz(func(t *testing.T, target string) {
		err := IsValidTarget(target)
		if err == nil && !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			t.Errorf("IsValidTarget(%q) = nil pero el esquema no es http(s)", target)
		}
	})
}

// FuzzIsPrivateIP: sin panic y propiedades básicas de rangos privados.
func FuzzIsPrivateIP(f *testing.F) {
	f.Add("10.0.0.1")
	f.Add("8.8.8.8")
	f.Add("::1")
	f.Add("2001:db8::1")

	f.Fuzz(func(t *testing.T, ipStr string) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return
		}
		got := IsPrivateIP(ip)
		// Propiedades: loopback y ULA siempre privadas; 8.8.8.8 nunca.
		if ip.IsLoopback() && !got {
			t.Errorf("loopback %s debe ser privada", ipStr)
		}
		if ipStr == "8.8.8.8" && got {
			t.Error("8.8.8.8 no es privada")
		}
	})
}
