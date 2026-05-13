package security

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// CheckWAF realiza una inspección básica de seguridad en la petición HTTP
func CheckWAF(r *http.Request) error {
	// 1. Filtrado de URI y query parameters (evitar path traversal y SQLi/XSS básico)
	if isMalicious(r.URL.Path) {
		return fmt.Errorf("petición bloqueada por WAF (ruta sospechosa)")
	}
	
	if r.URL.RawQuery != "" {
		decodedQuery, err := url.QueryUnescape(r.URL.RawQuery)
		if err == nil {
			if isMalicious(decodedQuery) {
				return fmt.Errorf("petición bloqueada por WAF (parámetros sospechosos)")
			}
		}
	}

	// 2. Filtrado básico de User-Agent (bloquear escáneres comunes)
	ua := strings.ToLower(r.UserAgent())
	if strings.Contains(ua, "nmap") || strings.Contains(ua, "sqlmap") || strings.Contains(ua, "nikto") || strings.Contains(ua, "curl") || strings.Contains(ua, "wget") && !AllowLoopback {
		return fmt.Errorf("user-agent bloqueado por WAF")
	}

	return nil
}

// isMalicious es una función muy básica para ilustrar un WAF.
func isMalicious(input string) bool {
	lower := strings.ToLower(input)
	
	// Directory traversal
	if strings.Contains(lower, "../") || strings.Contains(lower, "..\\") {
		return true
	}
	
	// XSS básico
	if strings.Contains(lower, "<script") || strings.Contains(lower, "javascript:") {
		return true
	}
	
	// SQLi básico
	if strings.Contains(lower, "union select") || strings.Contains(lower, "drop table") || strings.Contains(lower, "information_schema") {
		return true
	}
	
	return false
}
