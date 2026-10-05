package security

import (
	"database/sql"
	"net"
	"regio/internal/db"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// maxTrackedIPs acota la memoria del rate limiter (pares IP+servicio).
	//
	// El guard anterior ("protección contra memory exhaustion") llamaba a
	// LimpiarRateLimiter() por CADA petición con par nuevo al superar 10.000
	// entradas. Como LimpiarRateLimiter solo borra pares con 10 min de
	// inactividad, rotar IPs mantenía todo "activo": la limpieza no borraba
	// nada y cada petición pagaba el volcado completo a SQLite — medido en
	// 165 ms/petición frente a 2–18 µs antes del umbral, sin recuperación
	// posible. Es decir, el guard era un DoS autoinfligido.
	//
	// Ahora el guard expulsa los pares menos recientemente usados y sigue
	// atendiendo la petición: acota la memoria, no el tráfico.
	maxTrackedIPs = 10000

	// evictFloor: al llegar al techo se retrocede hasta aquí, en vez de
	// expulsar de uno en uno. Amortiza el barrido a ~1 operación por petición.
	evictFloor = 9000
)

// svcKey identifica un par (IP, servicio) para el seguimiento de último uso.
type svcKey struct {
	ip   string
	host string
}

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
	// rlLastUse registra el último uso (por número de secuencia) de cada par.
	// Se refresca también al RECHAZAR: la expulsión es por último uso, no por
	// antigüedad de creación. Si solo se refrescara al aceptar, el cliente
	// legítimo más activo (cuota agotada, sigue pidiendo) sería el primero en
	// expulsarse mientras el tráfico rotatorio se llevaría las de los demás.
	rlLastUse = make(map[svcKey]uint64)
	rlSeq     uint64
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

	// Protección contra memory exhaustion: al superar el techo se expulsa lo
	// menos recientemente usado en vez de rechazar la petición. Va ANTES de
	// crear la entrada: así el par de la petición en curso nunca es candidato
	// a expulsión propia.
	if len(peticionesMem) > maxTrackedIPs {
		evictLocked(evictFloor)
	}

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

	// Marcar último uso (también al rechazar: la expulsión es por último uso,
	// no por antigüedad; si no, el cliente legítimo con cuota agotada sería el
	// primero en expulsarse mientras el tráfico rotatorio se lleva las demás).
	rlSeq++
	rlLastUse[svcKey{ip, host}] = rlSeq

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

// countSvcPairs cuenta pares (IP, servicio) rastreados. Solo se llama desde
// el guard de memoria, ya amortizado por evictFloor.
func countSvcPairs() int {
	n := 0
	for _, hosts := range peticionesMem {
		n += len(hosts)
	}
	return n
}

// evictLocked deja como mucho `hasta` pares (IP, servicio) rastreados.
//
// Estrategia en dos pasadas, de la más barata a la más cara:
//  1. Borrar pares cuya última actividad salió de la ventana. Es el caso
//     normal y una sola pasada O(n) basta.
//  2. Si no basta, expulsar por último uso (rlLastUse). Solo ocurre con
//     rotación masiva, y como se retrocede de golpe hasta evictFloor el
//     barrido se amortiza en vez de pagarse por petición.
//
// Debe llamarse con rlMu tomado.
func evictLocked(hasta int) {
	if len(peticionesMem) <= maxTrackedIPs {
		return
	}

	// 1) Pasada barata: pares inactivos fuera de la ventana.
	ventana := time.Now().Add(-ventanaTiempo)
	for ip, hosts := range peticionesMem {
		for host, times := range hosts {
			if n := len(times); n == 0 || times[n-1].Before(ventana) {
				delete(hosts, host)
				delete(rlLastUse, svcKey{ip, host})
			}
		}
		if len(hosts) == 0 {
			delete(peticionesMem, ip)
			delete(globalMem, ip)
		}
	}
	if countSvcPairs() <= hasta {
		return
	}

	// 2) Pasada de precisión: los de seq más bajo fuera.
	type stamp struct {
		k   svcKey
		seq uint64
	}
	stamps := make([]stamp, 0, countSvcPairs())
	for ip, hosts := range peticionesMem {
		for host := range hosts {
			k := svcKey{ip, host}
			stamps = append(stamps, stamp{k, rlLastUse[k]})
		}
	}
	sort.Slice(stamps, func(a, b int) bool { return stamps[a].seq < stamps[b].seq })
	for _, s := range stamps[:len(stamps)-hasta] {
		delete(peticionesMem[s.k.ip], s.k.host)
		if len(peticionesMem[s.k.ip]) == 0 {
			delete(peticionesMem, s.k.ip)
			delete(globalMem, s.k.ip)
		}
		delete(rlLastUse, s.k)
	}
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
	rlLastUse = make(map[svcKey]uint64)
	rlSeq = 0
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
				delete(rlLastUse, svcKey{ip, host})
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
