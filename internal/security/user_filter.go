package security

import (
	"fmt"
	"regio/internal/db"
	"regio/internal/models"
	"sync"
	"time"
)

var (
	// Rate-limit por usuario: protección contra fuerza bruta distribuida (botnet)
	intentosUsuario  = make(map[string]*models.Intento)
	maxFallosUsuario = 10             // 10 intentos fallidos desde cualquier IP
	bloqueoUsuario   = 30 * time.Minute // Bloqueo de 30 minutos por cuenta
	userMu           sync.Mutex
)

// RegistrarFalloUsuario registra un intento fallido de login para un username específico.
func RegistrarFalloUsuario(username string) {
	userMu.Lock()
	defer userMu.Unlock()

	key := "user:" + username
	if _, ok := intentosUsuario[key]; !ok {
		intentosUsuario[key] = &models.Intento{Fallos: 1}
	} else {
		intentosUsuario[key].Fallos++
		if intentosUsuario[key].Fallos >= maxFallosUsuario {
			intentosUsuario[key].BloqueadoHasta = time.Now().Add(bloqueoUsuario)
			db.LogEvent(fmt.Sprintf("[BLOCK] CUENTA BLOQUEADA (fuerza bruta distribuida): %s (%d intentos)", username, intentosUsuario[key].Fallos), "Sistema")
		}
	}
}

// IsUserBlocked comprueba si un username está bloqueado por exceso de intentos fallidos.
func IsUserBlocked(username string) bool {
	userMu.Lock()
	defer userMu.Unlock()

	key := "user:" + username
	if reg, ok := intentosUsuario[key]; ok && time.Now().Before(reg.BloqueadoHasta) {
		return true
	}
	return false
}

// ResetearIntentosUsuario limpia los fallos tras un login exitoso.
func ResetearIntentosUsuario(username string) {
	userMu.Lock()
	defer userMu.Unlock()
	delete(intentosUsuario, "user:"+username)
}

// LimpiarIntentosUsuario purga entradas expiradas de la tabla de intentos por usuario.
func LimpiarIntentosUsuario() {
	userMu.Lock()
	defer userMu.Unlock()
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
