package security

import (
	"fmt"
	"net/http"
	"regio/internal/db"
)

// SecurityEngine es el middleware principal que ejecuta todas las protecciones.
func SecurityEngine(ip string, r *http.Request) error {
	// 0. Filtrado geográfico por país (GeoIP)
	if err := CheckGeoPolicy(ip, r.Host); err != nil {
		return err
	}

	// 1. Verificar bloqueo por IP (Fail2Ban)
	if blocked, reason := IsIPBlocked(ip); blocked {
		return fmt.Errorf("IP bloqueada: %s", reason)
	}

	// 2. Rate Limiting: 100 req/min por (IP, servicio) + techo global de 300
	// por IP entre todos los servicios
	if !CheckRateLimit(ip, NormalizeHost(r.Host)) {
		return fmt.Errorf("demasiadas peticiones")
	}

	// 3. WAF (Futuro: Inyecciones SQL, XSS, etc.)
	if err := CheckWAF(r); err != nil { return err }

	return nil
}

// LogSecurityEvent centraliza el registro de incidentes.
func LogSecurityEvent(message string, performer string) {
	db.LogEvent(message, performer)
}
