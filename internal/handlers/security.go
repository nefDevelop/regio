package handlers

import (
	"fmt"
	"net"
	"regio/internal/db"
	"regio/internal/models"
	"time"
)

var (
	peticionesDB = make(map[string][]time.Time)
	maxPeticiones = 100 // 100 peticiones
	ventanaTiempo = 1 * time.Minute
)

func CheckRateLimit(ip string) bool {
	Mu.Lock()
	defer Mu.Unlock()

	ahora := time.Now()
	
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

	if _, ok := IntentosDB[ip]; !ok {
		IntentosDB[ip] = &models.Intento{Fallos: 1}
	} else {
		IntentosDB[ip].Fallos++
		if IntentosDB[ip].Fallos >= 5 {
			IntentosDB[ip].BloqueadoHasta = time.Now().Add(15 * time.Minute)
			db.LogEvent(fmt.Sprintf("⊘ IP BLOQUEADA (Fuerza bruta): %s", ip))
		}
	}

	subnet := GetSubnet(ip)
	if subnet != "" {
		if _, ok := IntentosDB[subnet]; !ok {
			IntentosDB[subnet] = &models.Intento{Fallos: 1}
		} else {
			IntentosDB[subnet].Fallos++
			if IntentosDB[subnet].Fallos >= 15 {
				IntentosDB[subnet].BloqueadoHasta = time.Now().Add(1 * time.Hour)
				db.LogEvent(fmt.Sprintf("⊘ RANGO BLOQUEADO (Ataque múltiple): %s", subnet))
			}
		}
	}
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
