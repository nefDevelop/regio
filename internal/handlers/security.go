package handlers

import (
	"fmt"
	"net"
	"regio/internal/db"
	"regio/internal/models"
	"time"
)

var (
	peticionesDB  = make(map[string][]time.Time)
	maxPeticiones = 100 // 100 peticiones
	ventanaTiempo = 1 * time.Minute

	// Rate-limit por usuario: protección contra fuerza bruta distribuida (botnet)
	intentosUsuario    = make(map[string]*models.Intento)
	maxFallosUsuario   = 10             // 10 intentos fallidos desde cualquier IP
	bloqueoUsuario     = 30 * time.Minute // Bloqueo de 30 minutos por cuenta
)

func InitSecurity() {
	Mu.Lock()
	defer Mu.Unlock()
	rows, err := db.DB.Query("SELECT ip, hasta, razon FROM banned_ips WHERE hasta > ?", time.Now())
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var ip, razon string
		var hasta time.Time
		rows.Scan(&ip, &hasta, &razon)
		IntentosDB[ip] = &models.Intento{
			Fallos:         99, // Forzar bloqueo
			BloqueadoHasta: hasta,
		}
	}
}

func CheckRateLimit(ip string) bool {
	Mu.Lock()
	defer Mu.Unlock()

	ahora := time.Now()

	// MED-01: Protección contra memory exhaustion
	if len(peticionesDB) > 10000 {
		// Purgar todo si hay demasiadas IPs rastreadas (ataque distribuido)
		peticionesDB = make(map[string][]time.Time)
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

func LimpiarRateLimiter() {
	// Purgar IPs que no han hecho peticiones en 10 minutos para liberar memoria.
	ahora := time.Now()
	for ip, times := range peticionesDB {
		if len(times) == 0 || ahora.Sub(times[len(times)-1]) > 10*ventanaTiempo {
			delete(peticionesDB, ip)
		}
	}
}

func GetSubnet(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return ip.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func RegistrarFallo(ip string) {
	Mu.Lock()
	defer Mu.Unlock()

	ahora := time.Now()

	if _, ok := IntentosDB[ip]; !ok {
		IntentosDB[ip] = &models.Intento{Fallos: 1}
	} else {
		IntentosDB[ip].Fallos++
		if IntentosDB[ip].Fallos >= 5 {
			hasta := ahora.Add(15 * time.Minute)
			IntentosDB[ip].BloqueadoHasta = hasta
			db.DB.Exec("INSERT OR REPLACE INTO banned_ips (ip, hasta, razon) VALUES (?, ?, ?)", ip, hasta, "Fuerza bruta individual")
			db.LogEvent(fmt.Sprintf("⊘ IP BLOQUEADA (Fuerza bruta): %s", ip), "Sistema")
		}
	}

	subnet := GetSubnet(ip)
	if subnet != "" {
		if _, ok := IntentosDB[subnet]; !ok {
			IntentosDB[subnet] = &models.Intento{Fallos: 1}
		} else {
			IntentosDB[subnet].Fallos++
			if IntentosDB[subnet].Fallos >= 15 {
				hasta := ahora.Add(1 * time.Hour)
				IntentosDB[subnet].BloqueadoHasta = hasta
				db.DB.Exec("INSERT OR REPLACE INTO banned_ips (ip, hasta, razon) VALUES (?, ?, ?)", subnet, hasta, "Ataque múltiple desde rango")
				db.LogEvent(fmt.Sprintf("⊘ RANGO BLOQUEADO (Ataque múltiple): %s", subnet), "Sistema")
			}
		}
	}
}

func UnbanIP(target string) {
	Mu.Lock()
	defer Mu.Unlock()
	delete(IntentosDB, target)
	db.DB.Exec("DELETE FROM banned_ips WHERE ip = ?", target)
}

func IsIPBlocked(ip string) (bool, string) {
	Mu.Lock()
	defer Mu.Unlock()

	if reg, ok := IntentosDB[ip]; ok && time.Now().Before(reg.BloqueadoHasta) {
		return true, "IP bloqueada individualmente"
	}

	subnet := GetSubnet(ip)
	if reg, ok := IntentosDB[subnet]; ok && time.Now().Before(reg.BloqueadoHasta) {
		return true, "Rango de red bloqueado"
	}

	return false, ""
}

// RegistrarFalloUsuario registra un intento fallido de login para un username específico.
// Bloquea la cuenta tras maxFallosUsuario intentos, independientemente de la IP.
func RegistrarFalloUsuario(username string) {
	Mu.Lock()
	defer Mu.Unlock()

	key := "user:" + username
	if _, ok := intentosUsuario[key]; !ok {
		intentosUsuario[key] = &models.Intento{Fallos: 1}
	} else {
		intentosUsuario[key].Fallos++
		if intentosUsuario[key].Fallos >= maxFallosUsuario {
			intentosUsuario[key].BloqueadoHasta = time.Now().Add(bloqueoUsuario)
			db.LogEvent(fmt.Sprintf("⊘ CUENTA BLOQUEADA (fuerza bruta distribuida): %s (%d intentos)", username, intentosUsuario[key].Fallos), "Sistema")
		}
	}
}

// IsUserBlocked comprueba si un username está bloqueado por exceso de intentos fallidos.
func IsUserBlocked(username string) bool {
	Mu.Lock()
	defer Mu.Unlock()

	key := "user:" + username
	if reg, ok := intentosUsuario[key]; ok && time.Now().Before(reg.BloqueadoHasta) {
		return true
	}
	return false
}

// ResetearIntentosUsuario limpia los fallos tras un login exitoso.
func ResetearIntentosUsuario(username string) {
	Mu.Lock()
	defer Mu.Unlock()
	delete(intentosUsuario, "user:"+username)
}

// LimpiarIntentosUsuario purga entradas expiradas de la tabla de intentos por usuario.
func LimpiarIntentosUsuario() {
	Mu.Lock()
	defer Mu.Unlock()
	ahora := time.Now()
	for key, intento := range intentosUsuario {
		if ahora.After(intento.BloqueadoHasta) && intento.Fallos > 0 {
			// Reducir gradualmente los fallos (decay)
			intento.Fallos = intento.Fallos / 2
			if intento.Fallos == 0 {
				delete(intentosUsuario, key)
			}
		}
	}
}
