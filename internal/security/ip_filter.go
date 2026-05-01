package security

import (
	"fmt"
	"net"
	"regio/internal/db"
	"regio/internal/models"
	"sync"
	"time"
)

var (
	// IntentosDB almacena los fallos de login por IP o Subnet
	IntentosDB = make(map[string]*models.Intento)
	ipMu       sync.Mutex
)

// InitIPFilter carga las IPs bloqueadas desde la base de datos al iniciar.
func InitIPFilter() {
	ipMu.Lock()
	defer ipMu.Unlock()

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

// IsIPBlocked comprueba si una IP o su rango están en la lista negra.
func IsIPBlocked(ip string) (bool, string) {
	ipMu.Lock()
	defer ipMu.Unlock()

	if reg, ok := IntentosDB[ip]; ok && time.Now().Before(reg.BloqueadoHasta) {
		return true, "IP bloqueada individualmente"
	}

	subnet := GetSubnet(ip)
	if reg, ok := IntentosDB[subnet]; ok && time.Now().Before(reg.BloqueadoHasta) {
		return true, "Rango de red bloqueado"
	}

	return false, ""
}

// RegistrarFallo anota un intento fallido y bloquea tras varios reincidentes.
func RegistrarFallo(ip string) {
	ipMu.Lock()
	defer ipMu.Unlock()

	ahora := time.Now()

	if _, ok := IntentosDB[ip]; !ok {
		IntentosDB[ip] = &models.Intento{Fallos: 1}
	} else {
		IntentosDB[ip].Fallos++
		if IntentosDB[ip].Fallos >= 5 {
			hasta := ahora.Add(15 * time.Minute)
			IntentosDB[ip].BloqueadoHasta = hasta
			db.DB.Exec("INSERT OR REPLACE INTO banned_ips (ip, hasta, razon) VALUES (?, ?, ?)", ip, hasta, "Fuerza bruta individual")
			db.LogEvent(fmt.Sprintf("[BLOCK] IP BLOQUEADA (Fuerza bruta): %s", ip), "Sistema")
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
				db.LogEvent(fmt.Sprintf("[BLOCK] RANGO BLOQUEADO (Ataque múltiple): %s", subnet), "Sistema")
			}
		}
	}
}

// BanIP bloquea manualmente una IP o rango.
func BanIP(ip string, reason string, duration time.Duration) {
	ipMu.Lock()
	defer ipMu.Unlock()
	hasta := time.Now().Add(duration)
	IntentosDB[ip] = &models.Intento{
		Fallos:         99,
		BloqueadoHasta: hasta,
	}
	db.DB.Exec("INSERT OR REPLACE INTO banned_ips (ip, hasta, razon) VALUES (?, ?, ?)", ip, hasta, reason)
}

// UnbanIP elimina el bloqueo manual o automático.
func UnbanIP(target string) {
	ipMu.Lock()
	defer ipMu.Unlock()
	delete(IntentosDB, target)
	db.DB.Exec("DELETE FROM banned_ips WHERE ip = ?", target)
}

// GetSubnet devuelve la red /24 o /64 de una IP.
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

// GetBannedIPs devuelve una lista de IPs bloqueadas actualmente.
func GetBannedIPs() []models.BannedIP {
	ipMu.Lock()
	defer ipMu.Unlock()

	var banned []models.BannedIP
	ahora := time.Now()
	for k, v := range IntentosDB {
		if ahora.Before(v.BloqueadoHasta) {
			banned = append(banned, models.BannedIP{
				Target: k,
				Hasta:  v.BloqueadoHasta.Format("02/01/2006 15:04:05"),
			})
		}
	}
	return banned
}

// LimpiarBloqueosExpirados purga los bloqueos antiguos de memoria.
func LimpiarBloqueosExpirados() {
	ipMu.Lock()
	defer ipMu.Unlock()
	ahora := time.Now()
	for ip, intento := range IntentosDB {
		if ahora.After(intento.BloqueadoHasta) {
			delete(IntentosDB, ip)
		}
	}
}
