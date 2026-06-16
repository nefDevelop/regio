package security

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var (
	rePathTraversal = regexp.MustCompile(`(?i)(\.\.\/|\.\.\\)`)
	reSQLi         = regexp.MustCompile(`(?i)(union\s+.*select|select\s+.*\s+from|drop\s+table|insert\s+into|update\s+.*set|delete\s+from|--|#|\/\*|exec\s*\(|waitfor\s+delay|sleep\s*\(|pg_sleep|0x[0-9a-f]{8,}|information_schema|char\s*\(|nchar\s*\()`)
	reXSS          = regexp.MustCompile(`(?i)(<script[^>]*>|javascript:|<iframe|<object|<embed|<svg[^>]*>|on\w+\s*=)`)
)

// CheckWAF realiza una inspección básica de seguridad en la petición HTTP
func CheckWAF(r *http.Request) error {
	// 1. Filtrado de URI y query parameters (evitar path traversal y SQLi/XSS básico)
	if isMalicious(r.URL.Path) {
		return fmt.Errorf("petición bloqueada por WAF (ruta sospechosa)")
	}

	// Detectar path traversal con doble encoding (ej: %252e%252e%252f)
	if decodedPath, err := url.PathUnescape(r.URL.Path); err == nil && decodedPath != r.URL.Path {
		if isMalicious(decodedPath) {
			return fmt.Errorf("petición bloqueada por WAF (ruta sospechosa - doble encode)")
		}
	}
	// Verificar RawPath si existe (path original sin decodificar)
	if r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path {
		if isMalicious(r.URL.RawPath) {
			return fmt.Errorf("petición bloqueada por WAF (ruta sospechosa)")
		}
		if decodedRawPath, err := url.PathUnescape(r.URL.RawPath); err == nil && decodedRawPath != r.URL.RawPath {
			if isMalicious(decodedRawPath) {
				return fmt.Errorf("petición bloqueada por WAF (ruta sospechosa - doble encode)")
			}
		}
	}

	if r.URL.RawQuery != "" {
		decodedQuery, err := url.QueryUnescape(r.URL.RawQuery)
		if err == nil {
			if isMalicious(decodedQuery) {
				return fmt.Errorf("petición bloqueada por WAF (parámetros sospechosos)")
			}
		}
		// Doble decode en query params
		if doubleDecoded, err := url.QueryUnescape(decodedQuery); err == nil && doubleDecoded != decodedQuery {
			if isMalicious(doubleDecoded) {
				return fmt.Errorf("petición bloqueada por WAF (parámetros sospechosos - doble encode)")
			}
		}
	}

	// 2. Filtrado básico de User-Agent (bloquear escáneres comunes)
	ua := strings.ToLower(r.UserAgent())
	if strings.Contains(ua, "nmap") || strings.Contains(ua, "sqlmap") || strings.Contains(ua, "nikto") || strings.Contains(ua, "curl") || strings.Contains(ua, "wget") {
		return fmt.Errorf("user-agent bloqueado por WAF")
	}

	return nil
}

// isMalicious utiliza expresiones regulares para detectar patrones comunes de ataque.
func isMalicious(input string) bool {
	// Bloquear inputs muy grandes (prevención de ReDoS)
	if len(input) > 4096 {
		return true
	}

	// Directory traversal
	if rePathTraversal.MatchString(input) {
		return true
	}

	// XSS
	if reXSS.MatchString(input) {
		return true
	}

	// SQLi
	if reSQLi.MatchString(input) {
		return true
	}

	return false
}
