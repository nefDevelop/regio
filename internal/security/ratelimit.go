package security

import (
	"sync"
	"time"
)

var (
	peticionesDB  = make(map[string][]time.Time)
	maxPeticiones = 100 // 100 peticiones
	ventanaTiempo = 1 * time.Minute
	rlMu          sync.Mutex
)

// CheckRateLimit comprueba si una IP ha excedido el límite de peticiones.
func CheckRateLimit(ip string) bool {
	rlMu.Lock()
	defer rlMu.Unlock()

	ahora := time.Now()

	// Protección contra memory exhaustion
	if len(peticionesDB) > 10000 {
		if _, ok := peticionesDB[ip]; !ok {
			return false // Si es una IP nueva y estamos llenos, denegamos
		}
	}

	// 1. Limpiar peticiones antiguas fuera de la ventana
	if times, ok := peticionesDB[ip]; ok {
		var validas []time.Time
		for _, t := range times {
			if ahora.Sub(t) < ventanaTiempo {
				validas = append(validas, t)
			}
		}
		peticionesDB[ip] = validas
	}

	// 2. Comprobar si excede el límite
	if len(peticionesDB[ip]) >= maxPeticiones {
		return false
	}

	// 3. Registrar nueva petición
	peticionesDB[ip] = append(peticionesDB[ip], ahora)
	return true
}

// ResetRateLimiter limpia todas las peticiones registradas (útil para tests).
func ResetRateLimiter() {
	rlMu.Lock()
	defer rlMu.Unlock()
	peticionesDB = make(map[string][]time.Time)
}

// LimpiarRateLimiter purga IPs inactivas para liberar memoria.
func LimpiarRateLimiter() {
	rlMu.Lock()
	defer rlMu.Unlock()

	ahora := time.Now()
	for ip, times := range peticionesDB {
		if len(times) == 0 || ahora.Sub(times[len(times)-1]) > 10*ventanaTiempo {
			delete(peticionesDB, ip)
		}
	}
}
