package security

import (
	"database/sql"
	"net"
	"regio/internal/db"
	"strings"
	"sync"
	"time"
)

var (
	// peticionesMem agrupa por IP -> servicio: cada servicio tiene su propio
	// presupuesto (100 req/min) para que el tráfico ruidoso de un servicio
	// público no agote el acceso de esa IP al resto (servicios y panel admin).
	peticionesMem = make(map[string]map[string][]time.Time)
	// globalMem es el techo global por IP (todos los servicios sumados):
	// evita que multiplicar servicios multiplique la capacidad de abuso.
	globalMem     = make(map[string][]time.Time)
	maxPeticiones = 100
	maxGlobalIP   = 300
	ventanaTiempo = 1 * time.Minute
	rlMu          sync.Mutex
	rlDirty       bool
)

// CheckRateLimit comprueba si una IP ha excedido el límite de peticiones:
//   - 100 req/min por (IP, servicio)
//   - 300 req/min por IP entre todos los servicios (techo global)
//
// Persiste en SQLite para sobrevivir a reinicios del servidor. El host debe
// llegar normalizado (NormalizeHost, sin puerto y en minúsculas).
func CheckRateLimit(ip, host string) bool {
	rlMu.Lock()
	defer rlMu.Unlock()

	ahora := time.Now()
	ventana := ahora.Add(-ventanaTiempo)

	// Cargar desde DB la primera vez que vemos esta IP o este servicio
	if _, ipCargada := peticionesMem[ip]; !ipCargada {
		loadGlobalFromDB(ip, ventana)
	}
	if peticionesMem[ip] == nil {
		peticionesMem[ip] = make(map[string][]time.Time)
	}
	if _, exists := peticionesMem[ip][host]; !exists {
		loadFromDB(ip, host, ventana)
		// Entrada vacía cacheada: evita repetir la consulta a DB en cada
		// petición cuando el servicio no tiene filas (p. ej. rechazadas
		// por el techo global, que no registran).
		if peticionesMem[ip][host] == nil {
			peticionesMem[ip][host] = []time.Time{}
		}
	}

	// Protección contra memory exhaustion
	if len(peticionesMem) > 10000 {
		if len(peticionesMem[ip][host]) == 0 {
			rlMu.Unlock()
			LimpiarRateLimiter()
			rlMu.Lock()
			if len(peticionesMem) > 10000 {
				return false
			}
			if peticionesMem[ip] == nil {
				peticionesMem[ip] = make(map[string][]time.Time)
			}
		}
	}

	// Limpiar peticiones antiguas fuera de la ventana (in-place, sin allocs)
	if times, ok := peticionesMem[ip][host]; ok {
		n := 0
		for _, t := range times {
			if ahora.Sub(t) < ventanaTiempo {
				times[n] = t
				n++
			}
		}
		peticionesMem[ip][host] = times[:n]
	}
	if times, ok := globalMem[ip]; ok {
		n := 0
		for _, t := range times {
			if ahora.Sub(t) < ventanaTiempo {
				times[n] = t
				n++
			}
		}
		globalMem[ip] = times[:n]
	}

	// Comprobar el límite del servicio y el techo global de la IP
	if len(peticionesMem[ip][host]) >= maxPeticiones {
		return false
	}
	if len(globalMem[ip]) >= maxGlobalIP {
		return false
	}

	// Registrar nueva petición
	peticionesMem[ip][host] = append(peticionesMem[ip][host], ahora)
	globalMem[ip] = append(globalMem[ip], ahora)
	rlDirty = true

	// Persistir cada 10 peticiones para balance rendimiento/durabilidad
	if len(peticionesMem[ip][host])%10 == 0 {
		persistIP(ip, host, ahora)
	}

	return true
}

// NormalizeHost elimina el puerto y pasa el host a minúsculas para que la
// clave del rate limiter sea canónica. Compartida con handlers.
func NormalizeHost(host string) string {
	// Evita el import cycle: handlers delega aquí en vez de al revés.
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(h)
}

func loadFromDB(ip, host string, ventana time.Time) {
	rows, err := db.DB.Query("SELECT timestamp FROM rate_limits WHERE ip = ? AND host = ? AND timestamp >= ? ORDER BY timestamp ASC", ip, host, ventana)
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
		peticionesMem[ip][host] = times
	}
}

// loadGlobalFromDB carga el histórico de TODOS los servicios de una IP para
// que el techo global sobreviva a reinicios. Solo se llama la primera vez.
func loadGlobalFromDB(ip string, ventana time.Time) {
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
		globalMem[ip] = times
	}
}

func persistIP(ip, host string, hasta time.Time) {
	ventana := hasta.Add(-ventanaTiempo)
	// Limpiar entradas antiguas (fuera de la ventana)
	db.DB.Exec("DELETE FROM rate_limits WHERE ip = ? AND host = ? AND timestamp < ?", ip, host, ventana)

	// Fix deuda #5: solo insertar timestamps nuevos — los anteriores ya están
	// en DB y el índice único idx_rate_limits_unique hace el resto (antes se
	// reinsertaba la lista completa en cada persistencia: O(n²) y duplicados).
	var maxTs sql.NullTime
	db.DB.QueryRow("SELECT MAX(timestamp) FROM rate_limits WHERE ip = ? AND host = ?", ip, host).Scan(&maxTs)

	for _, t := range peticionesMem[ip][host] {
		if maxTs.Valid && !t.After(maxTs.Time) {
			continue
		}
		db.DB.Exec("INSERT OR IGNORE INTO rate_limits (ip, host, timestamp) VALUES (?, ?, ?)", ip, host, t)
	}
}

// ResetRateLimiter limpia todas las peticiones registradas (útil para tests).
func ResetRateLimiter() {
	rlMu.Lock()
	defer rlMu.Unlock()
	peticionesMem = make(map[string]map[string][]time.Time)
	globalMem = make(map[string][]time.Time)
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
		for ip, hosts := range peticionesMem {
			for host, times := range hosts {
				if len(times) == 0 {
					continue
				}
				db.DB.Exec("DELETE FROM rate_limits WHERE ip = ? AND host = ? AND timestamp < ?", ip, host, ventana)
				for _, t := range times {
					if ahora.Sub(t) < ventanaTiempo {
						db.DB.Exec("INSERT OR IGNORE INTO rate_limits (ip, host, timestamp) VALUES (?, ?, ?)", ip, host, t)
					}
				}
			}
		}
		rlDirty = false
	}

	// Limpiar memoria: servicios inactivos por más de 10 ventanas
	for ip, hosts := range peticionesMem {
		for host, times := range hosts {
			if len(times) == 0 || ahora.Sub(times[len(times)-1]) > 10*ventanaTiempo {
				delete(hosts, host)
			}
		}
		if len(hosts) == 0 {
			delete(peticionesMem, ip)
		}
	}
	for ip, times := range globalMem {
		if len(times) == 0 || ahora.Sub(times[len(times)-1]) > 10*ventanaTiempo {
			delete(globalMem, ip)
			continue
		}
		n := 0
		for _, t := range times {
			if ahora.Sub(t) < ventanaTiempo {
				times[n] = t
				n++
			}
		}
		globalMem[ip] = times[:n]
	}

	// Limpiar DB: entradas más viejas que 10 ventanas
	db.DB.Exec("DELETE FROM rate_limits WHERE timestamp < ?", ahora.Add(-10*ventanaTiempo))
}
