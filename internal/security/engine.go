package security

import (
	"fmt"
	"net/http"
	"regio/internal/db"
)

// SecurityEngine es el middleware principal que ejecuta todas las protecciones.
func SecurityEngine(ip string, r *http.Request) error {
	// 1. Verificar bloqueo por IP (Fail2Ban)
	if blocked, reason := IsIPBlocked(ip); blocked {
		return fmt.Errorf("IP bloqueada: %s", reason)
	}

	// 2. Rate Limiting Global
	if !CheckRateLimit(ip) {
		return fmt.Errorf("demasiadas peticiones")
	}

	// 3. WAF (Futuro: Inyecciones SQL, XSS, etc.)
	// if err := CheckWAF(r); err != nil { return err }

	return nil
}

// LogSecurityEvent centraliza el registro de incidentes.
func LogSecurityEvent(message string, performer string) {
	db.LogEvent(message, performer)
}
