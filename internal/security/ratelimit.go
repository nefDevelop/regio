package security

import (
	"cmp"
	"database/sql"
	"regio/internal/db"
	"slices"
	"sync"
	"time"
)

const (
	maxPeticiones = 100
	ventanaTiempo = 1 * time.Minute

	// maxTrackedIPs acota la memoria del rate limiter.
	//
	// El guard anterior ("protección contra memory exhaustion") llamaba a
	// LimpiarRateLimiter() por CADA IP nueva al superar 10.000 entradas. Como
	// LimpiarRateLimiter solo borra IPs con 10 min de inactividad, un atacante
	// que rotase IPs de origen mantenía todas las entradas como "activas": la
	// limpieza no borraba nada, el contador se quedaba en >10.000 y cada
	// petición nueva pagaba un volcado completo de las 10.000 entradas a SQLite
	// — medido en 165 ms/petición frente a 2–18 µs antes del umbral, y sin
	// recuperación posible. Es decir, el guard era un DoS autoinfligido.
	//
	// Ahora el guard expulsa las entradas más antiguas y sigue atendiendo la
	// petición: Acota la memoria, no el tráfico.
	maxTrackedIPs = 10000

	// evictFloor: al llegar al techo se retrocede hasta aquí, en vez de expulsar
	// de una en una. Amortiza el barrido O(n) a ~1 comprobación por petición.
	evictFloor = 9000
)

// ipEntry agrupa el historial de una IP con un número de secuencia monotónico.
// El seq permite saber qué entrada es la más antigua sin tener que comparar
// tiempos: el más antiguo es el de seq más bajo.
type ipEntry struct {
	times []time.Time
	seq   uint64
}

type ipStamp struct {
	ip  string
	seq uint64
}

var (
	peticionesMem = make(map[string]ipEntry)
	rlSeq         uint64
	rlMu          sync.Mutex
	rlDirty       bool
)

// CheckRateLimit comprueba si una IP ha excedido el límite de peticiones.
// Persiste en SQLite para sobrevivir a reinicios del servidor.
func CheckRateLimit(ip string) bool {
	rlMu.Lock()
	defer rlMu.Unlock()

	ahora := time.Now()
	ventana := ahora.Add(-ventanaTiempo)

	// Cargar desde DB si no tenemos datos en memoria para esta IP
	e, exists := peticionesMem[ip]
	if !exists {
		// Acotar el mapa ANTES de insertar: si ya está en el techo, se expulsa
		// lo más antiguo en vez de rechazar la petición.
		evictLocked(evictFloor)
		e = loadFromDB(ip, ventana)
		rlSeq++
		e.seq = rlSeq
	}

	// Limpiar peticiones antiguas fuera de la ventana. Se reutiliza la backing
	// array del slice anterior (times[:0]): la ventana se acota a 100 elementos,
	// así que no crece y se eliminan las asignaciones por petición.
	validas := e.times[:0]
	for _, t := range e.times {
		if ahora.Sub(t) < ventanaTiempo {
			validas = append(validas, t)
		}
	}
	e.times = validas

	// Comprobar si excede el límite.
	//
	// El seq se refresca también al RECHAZAR: la expulsión es por último uso
	// (LRU), no por antigüedad de creación. Si solo se refrescara al aceptar, el
	// cliente legítimo más activo (que agota su cuota y sigue recibiendo
	// peticiones) quedaría con el seq más bajo y sería la primera en expulsarse,
	// mientras el tráfico rotatorio se llevaría las de los demás.
	if len(e.times) >= maxPeticiones {
		rlSeq++
		e.seq = rlSeq
		peticionesMem[ip] = e // la ventana recorta también hay que guardarla
		return false
	}

	// Registrar nueva petición
	e.times = append(e.times, ahora)
	rlSeq++
	e.seq = rlSeq
	peticionesMem[ip] = e
	rlDirty = true

	// Persistir cada 10 peticiones para balance rendimiento/durabilidad
	if len(e.times)%10 == 0 {
		persistIP(ip, e.times, ahora)
	}

	return true
}

// evictLocked deja el mapa como mucho en `hasta` entradas.
//
// Estrategia en dos pasada, de la más barata a la más cara:
//  1. Borrar todo lo que ya está fuera de la ventana. Es el caso normal (tráfico
//     corriente deja pocas IPs vivas por minuto) y una sola pasada O(n) basta.
//  2. Si no basta, expulsar las más antiguas por seq. Solo ocurre con rotación
//     masiva de IPs, y como se retrocede de golpe hasta evictFloor el barrido
//     se amortiza a ~1 operación por petición en vez de O(n) por petición.
//
// Debe llamarse con rlMu tomado.
func evictLocked(hasta int) {
	if len(peticionesMem) <= maxTrackedIPs {
		return
	}

	// 1) Pasada barata: entradas cuya última actividad salió de la ventana.
	ventana := time.Now().Add(-ventanaTiempo)
	for ip, e := range peticionesMem {
		if n := len(e.times); n == 0 || e.times[n-1].Before(ventana) {
			delete(peticionesMem, ip)
		}
	}
	if len(peticionesMem) <= hasta {
		return
	}

	// 2) Pasada de precisión: expulsar las de seq más bajo.
	stamps := make([]ipStamp, 0, len(peticionesMem))
	for ip, e := range peticionesMem {
		stamps = append(stamps, ipStamp{ip: ip, seq: e.seq})
	}
	slices.SortFunc(stamps, func(a, b ipStamp) int { return cmp.Compare(a.seq, b.seq) })
	for _, s := range stamps[:len(peticionesMem)-hasta] {
		delete(peticionesMem, s.ip)
	}
}

// loadFromDB recupera el historial persistido de una IP. Devolver el valor (y no
// escribirlo en el mapa) evita un segundo acceso al mapa bajo el mismo lock.
func loadFromDB(ip string, ventana time.Time) ipEntry {
	rows, err := db.DB.Query("SELECT timestamp FROM rate_limits WHERE ip = ? AND timestamp >= ? ORDER BY timestamp ASC", ip, ventana)
	if err != nil {
		return ipEntry{}
	}
	defer rows.Close()

	var times []time.Time
	for rows.Next() {
		var ts time.Time
		if err := rows.Scan(&ts); err == nil {
			times = append(times, ts)
		}
	}
	return ipEntry{times: times}
}

func persistIP(ip string, times []time.Time, hasta time.Time) {
	ventana := hasta.Add(-ventanaTiempo)
	// Limpiar entradas antiguas (fuera de la ventana)
	db.DB.Exec("DELETE FROM rate_limits WHERE ip = ? AND timestamp < ?", ip, ventana)

	// Fix deuda #5: solo insertar timestamps nuevos — los anteriores ya están
	// en DB y el índice único idx_rate_limits_unique hace el resto (antes se
	// reinsertaba la lista completa en cada persistencia: O(n²) y duplicados).
	var maxTs sql.NullTime
	db.DB.QueryRow("SELECT MAX(timestamp) FROM rate_limits WHERE ip = ?", ip).Scan(&maxTs)

	for _, t := range times {
		if maxTs.Valid && !t.After(maxTs.Time) {
			continue
		}
		db.DB.Exec("INSERT OR IGNORE INTO rate_limits (ip, timestamp) VALUES (?, ?)", ip, t)
	}
}

// ResetRateLimiter limpia todas las peticiones registradas (útil para tests).
func ResetRateLimiter() {
	rlMu.Lock()
	defer rlMu.Unlock()
	peticionesMem = make(map[string]ipEntry)
	rlDirty = false
	db.DB.Exec("DELETE FROM rate_limits")
}

// LimpiarRateLimiter purga IPs inactivas y persiste cambios pendientes.
// La ejecuta la rutina periódica de cmd/regio cada 10 minutos; desde el arreglo
// del guard ya no está en el camino de ninguna petición.
func LimpiarRateLimiter() {
	rlMu.Lock()
	defer rlMu.Unlock()

	ahora := time.Now()
	ventana := ahora.Add(-ventanaTiempo)

	// Persistir datos sucios antes de limpiar
	if rlDirty {
		for ip, e := range peticionesMem {
			if len(e.times) > 0 {
				db.DB.Exec("DELETE FROM rate_limits WHERE ip = ? AND timestamp < ?", ip, ventana)
				for _, t := range e.times {
					if ahora.Sub(t) < ventanaTiempo {
						db.DB.Exec("INSERT OR IGNORE INTO rate_limits (ip, timestamp) VALUES (?, ?)", ip, t)
					}
				}
			}
		}
		rlDirty = false
	}

	// Limpiar memoria: IPs inactivas por más de 10 ventanas
	for ip, e := range peticionesMem {
		if len(e.times) == 0 || ahora.Sub(e.times[len(e.times)-1]) > 10*ventanaTiempo {
			delete(peticionesMem, ip)
		}
	}

	// Limpiar DB: entradas más viejas que 10 ventanas
	db.DB.Exec("DELETE FROM rate_limits WHERE timestamp < ?", ahora.Add(-10*ventanaTiempo))
}
