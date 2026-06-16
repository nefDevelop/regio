package security

import (
	"regio/internal/db"
	"sync"
	"time"
)

var (
	peticionesMem  = make(map[string][]time.Time)
	maxPeticiones  = 100
	ventanaTiempo  = 1 * time.Minute
	rlMu           sync.Mutex
	rlDirty        bool
)

// CheckRateLimit comprueba si una IP ha excedido el límite de peticiones.
// Persiste en SQLite para sobrevivir a reinicios del servidor.
func CheckRateLimit(ip string) bool {
	rlMu.Lock()
	defer rlMu.Unlock()

	ahora := time.Now()
	ventana := ahora.Add(-ventanaTiempo)

	// Cargar desde DB si no tenemos datos en memoria para esta IP
	if _, exists := peticionesMem[ip]; !exists {
		loadFromDB(ip, ventana)
	}

	// Protección contra memory exhaustion
	if len(peticionesMem) > 10000 {
		if _, ok := peticionesMem[ip]; !ok {
			rlMu.Unlock()
			LimpiarRateLimiter()
			rlMu.Lock()
			if len(peticionesMem) > 10000 {
				return false
			}
		}
	}

	// Limpiar peticiones antiguas fuera de la ventana
	if times, ok := peticionesMem[ip]; ok {
		var validas []time.Time
		for _, t := range times {
			if ahora.Sub(t) < ventanaTiempo {
				validas = append(validas, t)
			}
		}
		peticionesMem[ip] = validas
	}

	// Comprobar si excede el límite
	if len(peticionesMem[ip]) >= maxPeticiones {
		return false
	}

	// Registrar nueva petición
	peticionesMem[ip] = append(peticionesMem[ip], ahora)
	rlDirty = true

	// Persistir cada 10 peticiones para balance rendimiento/durabilidad
	if len(peticionesMem[ip])%10 == 0 {
		persistIP(ip, ahora)
	}

	return true
}

func loadFromDB(ip string, ventana time.Time) {
	rows, err := db.DB.Query("SELECT timestamp FROM rate_limits WHERE ip = ? AND timestamp >= ? ORDER BY timestamp ASC", ip, ventana)
	if err != nil {
		return
	}
	defer rows.Close()

	var times []time.Time
	for rows.Next() {
		var ts time.Time
		if err := rows.Scan(&ts); err == nil {
			times = append(times, ts)
		}
	}
	if len(times) > 0 {
		peticionesMem[ip] = times
	}
}

func persistIP(ip string, hasta time.Time) {
	ventana := hasta.Add(-ventanaTiempo)
	// Limpiar entradas antiguas y guardar las actuales
	db.DB.Exec("DELETE FROM rate_limits WHERE ip = ? AND timestamp < ?", ip, ventana)
	for _, t := range peticionesMem[ip] {
		db.DB.Exec("INSERT OR IGNORE INTO rate_limits (ip, timestamp) VALUES (?, ?)", ip, t)
	}
}

// ResetRateLimiter limpia todas las peticiones registradas (útil para tests).
func ResetRateLimiter() {
	rlMu.Lock()
	defer rlMu.Unlock()
	peticionesMem = make(map[string][]time.Time)
	db.DB.Exec("DELETE FROM rate_limits")
	rlDirty = false
}

// LimpiarRateLimiter purga IPs inactivas y persiste cambios pendientes.
func LimpiarRateLimiter() {
	rlMu.Lock()
	defer rlMu.Unlock()

	ahora := time.Now()
	ventana := ahora.Add(-ventanaTiempo)

	// Persistir datos sucios antes de limpiar
	if rlDirty {
		for ip, times := range peticionesMem {
			if len(times) > 0 {
				db.DB.Exec("DELETE FROM rate_limits WHERE ip = ? AND timestamp < ?", ip, ventana)
				for _, t := range times {
					if ahora.Sub(t) < ventanaTiempo {
						db.DB.Exec("INSERT OR IGNORE INTO rate_limits (ip, timestamp) VALUES (?, ?)", ip, t)
					}
				}
			}
		}
		rlDirty = false
	}

	// Limpiar memoria: IPs inactivas por más de 10 ventanas
	for ip, times := range peticionesMem {
		if len(times) == 0 || ahora.Sub(times[len(times)-1]) > 10*ventanaTiempo {
			delete(peticionesMem, ip)
		}
	}

	// Limpiar DB: entradas más viejas que 10 ventanas
	db.DB.Exec("DELETE FROM rate_limits WHERE timestamp < ?", ahora.Add(-10*ventanaTiempo))
}
