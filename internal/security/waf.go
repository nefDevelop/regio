package security

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// ErrWAF envuelve todos los bloqueos del WAF para que los handlers puedan
// distinguirlos (errors.Is) y responder 403 con su propio mensaje, en lugar
// de caer en el default de rate limiting (429) — fix deuda #1.
var ErrWAF = errors.New("bloqueo del WAF")

var (
	rePathTraversal = regexp.MustCompile(`(?i)(\.\.\/|\.\.\\)`)
	reSQLi          = regexp.MustCompile(`(?i)(union\s+.*select|select\s+.*\s+from|drop\s+table|insert\s+into|update\s+.*set|delete\s+from|--|#|\/\*|exec\s*\(|waitfor\s+delay|sleep\s*\(|pg_sleep|0x[0-9a-f]{8,}|information_schema|char\s*\(|nchar\s*\()`)
	reXSS           = regexp.MustCompile(`(?i)(<script[^>]*>|javascript:|<iframe|<object|<embed|<svg[^>]*>|on\w+\s*=)`)
)

// CheckWAF realiza una inspección básica de seguridad en la petición HTTP
func CheckWAF(r *http.Request) error {
	// 1. Filtrado de URI y query parameters (evitar path traversal y SQLi/XSS básico)
	if isMalicious(r.URL.Path) {
		return fmt.Errorf("%w: ruta sospechosa", ErrWAF)
	}

	// Detectar path traversal con doble encoding (ej: %252e%252e%252f)
	if decodedPath, err := url.PathUnescape(r.URL.Path); err == nil && decodedPath != r.URL.Path {
		if isMalicious(decodedPath) {
			return fmt.Errorf("%w: ruta sospechosa (doble encode)", ErrWAF)
		}
	}
	// Verificar RawPath si existe (path original sin decodificar)
	if r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path {
		if isMalicious(r.URL.RawPath) {
			return fmt.Errorf("%w: ruta sospechosa", ErrWAF)
		}
		if decodedRawPath, err := url.PathUnescape(r.URL.RawPath); err == nil && decodedRawPath != r.URL.RawPath {
			if isMalicious(decodedRawPath) {
				return fmt.Errorf("%w: ruta sospechosa (doble encode)", ErrWAF)
			}
		}
	}

	if r.URL.RawQuery != "" {
		decodedQuery, err := url.QueryUnescape(r.URL.RawQuery)
		if err == nil {
			if isMalicious(decodedQuery) {
				return fmt.Errorf("%w: parámetros sospechosos", ErrWAF)
			}
		}
		// Doble decode en query params
		if doubleDecoded, err := url.QueryUnescape(decodedQuery); err == nil && doubleDecoded != decodedQuery {
			if isMalicious(doubleDecoded) {
				return fmt.Errorf("%w: parámetros sospechosos (doble encode)", ErrWAF)
			}
		}
	}

	// 2. Filtrado básico de User-Agent (bloquear escáneres comunes)
	ua := strings.ToLower(r.UserAgent())
	if strings.Contains(ua, "nmap") || strings.Contains(ua, "sqlmap") || strings.Contains(ua, "nikto") || strings.Contains(ua, "curl") || strings.Contains(ua, "wget") {
		return fmt.Errorf("%w: user-agent bloqueado", ErrWAF)
	}

	return nil
}

// Prefiltros por familia de ataque (fix deuda #5): si el input no contiene
// ninguno de los literales ASCII mínimos que la regex de esa familia exige,
// la regex no puede coincidir y se salta (el 92% del tiempo de CheckWAF se
// iba en regexp.backtrack por los `.*` del patrón SQLi).
//
// CORRECTITUD: cada token es un subliteral del patrón correspondiente, así
// que "regex habría coincidido ⇒ el lowered contiene el token" vale para
// inputs ASCII (fold (?i) ASCII ≡ ToLower). Los inputs con runes no-ASCII
// saltan el prefilter y van directo a las regex para respetar el fold de
// Unicode del stdlib (p. ej. (?i)select también casa con "ſelect").
var (
	tokensTraversal = []string{".."}
	tokensXSS       = []string{"<script", "javascript", "<iframe", "<object", "<embed", "<svg", "on"}
	tokensSQLi      = []string{"union", "select", "drop", "insert", "update", "delete", "--", "#", "/*", "exec", "waitfor", "sleep", "0x", "information_schema", "char"}
)

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7F {
			return false
		}
	}
	return true
}

func containsAnyToken(lower string, tokens []string) bool {
	for _, tok := range tokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

// runFamily aplica el prefilter de una familia y, si procede, su regex.
func runFamily(input, lower string, ascii bool, tokens []string, re *regexp.Regexp) bool {
	if ascii && !containsAnyToken(lower, tokens) {
		return false
	}
	return re.MatchString(input)
}

// isMalicious utiliza expresiones regulares para detectar patrones comunes de ataque.
func isMalicious(input string) bool {
	// Bloquear inputs muy grandes (prevención de ReDoS)
	if len(input) > 4096 {
		return true
	}

	ascii := isASCII(input)
	lower := ""
	if ascii {
		lower = strings.ToLower(input)
	}

	// Directory traversal
	if runFamily(input, lower, ascii, tokensTraversal, rePathTraversal) {
		return true
	}
	// XSS
	if runFamily(input, lower, ascii, tokensXSS, reXSS) {
		return true
	}
	// SQLi
	if runFamily(input, lower, ascii, tokensSQLi, reSQLi) {
		return true
	}

	return false
}
