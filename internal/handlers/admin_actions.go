package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"regio/internal/auth"
	"regio/internal/db"
	"regio/internal/models"
	"regio/internal/security"
)

// adminAction es una acción del panel admin (extracción R2 del switch de
// HandleAdmin). Contrato de retorno idéntico a la semántica original:
//
//   - stop=true  → la respuesta ya está escrita; HandleAdmin aborta SIN
//     rotar el CSRF (equivalente al `return` dentro del switch original).
//   - stop=false → éxito o no-op; HandleAdmin rota el CSRF y responde 303
//     (equivalente a caer al final del switch original).
type adminAction func(w http.ResponseWriter, r *http.Request, user *models.User) (stop bool)

// adminActions centraliza el dispatch de las acciones del panel. Las acciones
// no presentes en el mapa se tratan como no-op con 303, igual que el switch
// original sin rama default.
var adminActions = map[string]adminAction{
	"add_service":       actionAddService,
	"update_service":    actionUpdateService,
	"delete_service":    actionDeleteService,
	"set_geo_policy":    actionSetGeoPolicy,
	"set_service_geo":   actionSetServiceGeo,
	"add_bypass_key":    actionAddBypassKey,
	"delete_bypass_key": actionDeleteBypassKey,
	"add_user":          actionAddUser,
	"delete_user":       actionDeleteUser,
	"ban_ip":            actionBanIP,
	"unban_ip":          actionUnbanIP,
	"revoke_session":    actionRevokeSession,
}

func actionAddService(w http.ResponseWriter, r *http.Request, user *models.User) bool {
	host := strings.TrimSpace(r.FormValue("host"))
	target := strings.TrimSpace(r.FormValue("target"))
	csp := r.FormValue("csp")
	if host != "" && target != "" {
		if err := security.IsValidTarget(target); err != nil {
			db.LogEvent(fmt.Sprintf("%s Intento de añadir target inválido/SSRF: %s -> %s (%v)", db.PrefixWARN, host, target, err), user.Username)
			http.Error(w, "El destino (target) no es válido o está restringido por seguridad", http.StatusBadRequest)
			return true
		}

		geoMode := r.FormValue("geo_mode")
		geoCountries := strings.TrimSpace(r.FormValue("geo_countries"))
		geoParsed, errGeo := security.ValidateGeoSelection(geoMode, geoCountries)
		if errGeo != nil {
			http.Error(w, errGeo.Error(), http.StatusBadRequest)
			return true
		}

		// Gestión de Bypass Key integrada (operación de DB fuera de Mu)
		bypassName := strings.TrimSpace(r.FormValue("bypass_name"))
		bypassToken := r.FormValue("bypass_token")
		if bypassName != "" && bypassToken != "" {
			security.AddBypassKey(bypassToken, bypassName, host)
			db.LogEvent(fmt.Sprintf("%s Bypass key creada automáticamente para: %s (%s)", db.PrefixKEY, host, bypassName), user.Username)
		}

		Mu.Lock()
		if Config.Servicios == nil {
			Config.Servicios = make(map[string]string)
		}
		if Config.Publicos == nil {
			Config.Publicos = make(map[string]bool)
		}
		if Config.BypassHeaders == nil {
			Config.BypassHeaders = make(map[string]string)
		}
		if Config.CSPs == nil {
			Config.CSPs = make(map[string]string)
		}
		if Config.GeoModes == nil {
			Config.GeoModes = make(map[string]string)
		}
		if Config.GeoCountries == nil {
			Config.GeoCountries = make(map[string]string)
		}

		Config.Servicios[host] = target
		Config.Publicos[host] = r.FormValue("public") == "on"
		Config.CSPs[host] = csp
		Config.GeoModes[host] = geoMode
		Config.GeoCountries[host] = geoCountries

		// Clonamos configuración para guardar fuera del lock principal
		configToSave := Config
		UpdateAllowedNetworksFromConfig()
		Mu.Unlock()

		db.SaveConfig(configToSave)
		security.SetHostGeoPolicy(host, geoMode, geoParsed)
		db.LogEvent(fmt.Sprintf("%s Puente añadido: %s -> %s (Público: %v)", db.PrefixREGIO, host, target, Config.Publicos[host]), user.Username)
	}
	return false
}

func actionUpdateService(w http.ResponseWriter, r *http.Request, user *models.User) bool {
	host := r.FormValue("old_host")
	newHost := strings.TrimSpace(r.FormValue("host"))
	target := strings.TrimSpace(r.FormValue("target"))
	csp := r.FormValue("csp")
	if host != "" && newHost != "" && target != "" {
		if err := security.IsValidTarget(target); err != nil {
			db.LogEvent(fmt.Sprintf("%s Intento de actualizar target inválido/SSRF: %s -> %s (%v)", db.PrefixWARN, newHost, target, err), user.Username)
			http.Error(w, "El destino (target) no es válido o está restringido por seguridad", http.StatusBadRequest)
			return true
		}
		Mu.Lock()
		if Config.Servicios == nil {
			Config.Servicios = make(map[string]string)
		}
		if Config.Publicos == nil {
			Config.Publicos = make(map[string]bool)
		}
		if Config.BypassHeaders == nil {
			Config.BypassHeaders = make(map[string]string)
		}
		if Config.CSPs == nil {
			Config.CSPs = make(map[string]string)
		}
		if Config.GeoModes == nil {
			Config.GeoModes = make(map[string]string)
		}
		if Config.GeoCountries == nil {
			Config.GeoCountries = make(map[string]string)
		}
		delete(Config.Servicios, host)
		Config.Servicios[newHost] = target

		// Actualizar estado de "Público" desde el formulario
		isPublic := r.FormValue("public") == "on"
		delete(Config.Publicos, host)
		Config.Publicos[newHost] = isPublic

		bypass := Config.BypassHeaders[host]
		delete(Config.BypassHeaders, host)
		Config.BypassHeaders[newHost] = bypass

		delete(Config.CSPs, host)
		Config.CSPs[newHost] = csp

		geoMode := Config.GeoModes[host]
		delete(Config.GeoModes, host)
		Config.GeoModes[newHost] = geoMode

		geoCountries := Config.GeoCountries[host]
		delete(Config.GeoCountries, host)
		Config.GeoCountries[newHost] = geoCountries

		configToSave := Config
		UpdateAllowedNetworksFromConfig()
		Mu.Unlock()

		db.SaveConfig(configToSave)
		if host != newHost {
			security.DeleteHostGeoPolicy(host)
		}
		geoParsed, _ := security.ParseCountries(geoCountries)
		security.SetHostGeoPolicy(newHost, geoMode, geoParsed)
		db.LogEvent(fmt.Sprintf("%s Puente actualizado: %s -> %s (Público: %v)", db.PrefixREGIO, newHost, target, isPublic), user.Username)
	}
	return false
}

func actionDeleteService(w http.ResponseWriter, r *http.Request, user *models.User) bool {
	host := r.FormValue("host")
	Mu.Lock()
	delete(Config.Servicios, host)
	delete(Config.Publicos, host)
	delete(Config.BypassHeaders, host)
	delete(Config.CSPs, host)
	delete(Config.GeoModes, host)
	delete(Config.GeoCountries, host)
	configToSave := Config
	UpdateAllowedNetworksFromConfig()
	Mu.Unlock()

	db.SaveConfig(configToSave)
	security.DeleteHostGeoPolicy(host)
	db.LogEvent(fmt.Sprintf("%s Puente eliminado: %s", db.PrefixREGIO, host), user.Username)
	return false
}

func actionSetGeoPolicy(w http.ResponseWriter, r *http.Request, user *models.User) bool {
	policy, errGeo := security.NewGeoPolicy(
		r.FormValue("geo_mode"),
		strings.TrimSpace(r.FormValue("geo_countries")),
		r.FormValue("geo_fail_mode"),
	)
	if errGeo != nil {
		http.Error(w, errGeo.Error(), http.StatusBadRequest)
		return true
	}
	if err := security.SaveGlobalGeoPolicy(policy); err != nil {
		http.Error(w, "Error guardando la política geográfica: "+err.Error(), http.StatusInternalServerError)
		return true
	}
	db.LogEvent(fmt.Sprintf("%s Política geográfica actualizada: modo=%s países=[%s] fail=%s",
		db.PrefixREGIO, policy.Mode, security.FormatCountries(policy.Countries), policy.FailMode), user.Username)
	return false
}

func actionSetServiceGeo(w http.ResponseWriter, r *http.Request, user *models.User) bool {
	host := normalizeHost(strings.TrimSpace(r.FormValue("host")))
	geoMode := r.FormValue("geo_mode")
	geoCountries := strings.TrimSpace(r.FormValue("geo_countries"))
	geoParsed, errGeo := security.ValidateGeoSelection(geoMode, geoCountries)
	if errGeo != nil {
		http.Error(w, errGeo.Error(), http.StatusBadRequest)
		return true
	}
	Mu.Lock()
	if Config.GeoModes == nil {
		Config.GeoModes = make(map[string]string)
	}
	if Config.GeoCountries == nil {
		Config.GeoCountries = make(map[string]string)
	}
	if _, existe := Config.Servicios[host]; !existe {
		Mu.Unlock()
		http.Error(w, "Servicio no encontrado", http.StatusNotFound)
		return true
	}
	// Guardar también con la clave tal y como se registró el servicio
	serviceKey := host
	for h := range Config.Servicios {
		if normalizeHost(h) == host {
			serviceKey = h
			break
		}
	}
	Config.GeoModes[serviceKey] = geoMode
	Config.GeoCountries[serviceKey] = geoCountries
	configToSave := Config
	Mu.Unlock()

	db.SaveConfig(configToSave)
	security.SetHostGeoPolicy(host, geoMode, geoParsed)
	db.LogEvent(fmt.Sprintf("%s Política por país del servicio %s: modo=%s países=[%s]",
		db.PrefixREGIO, host, geoMode, security.FormatCountries(geoParsed)), user.Username)
	return false
}

func actionAddBypassKey(w http.ResponseWriter, r *http.Request, user *models.User) bool {
	token := r.FormValue("token")
	name := r.FormValue("name")
	host := r.FormValue("host")
	if token == "" || name == "" || host == "" {
		http.Error(w, "Todos los campos son obligatorios para crear una Bypass Key", http.StatusBadRequest)
		return true
	}
	security.AddBypassKey(token, name, host)
	db.LogEvent(fmt.Sprintf("%s Bypass key creada: %s para host %s", db.PrefixKEY, name, host), user.Username)
	return false
}

func actionDeleteBypassKey(w http.ResponseWriter, r *http.Request, user *models.User) bool {
	token := r.FormValue("token")
	security.DeleteBypassKey(token)
	db.LogEvent(fmt.Sprintf("%s Bypass key eliminada: %s", db.PrefixKEY, token), user.Username)
	return false
}

func actionAddUser(w http.ResponseWriter, r *http.Request, user *models.User) bool {
	newUser := r.FormValue("new_user")
	if newUser != "" {
		totp := auth.GenerateTOTPSecret()
		totpEnc, _ := auth.Encrypt(totp)
		inviteToken := auth.GenerateSessionToken() // Usamos la misma función para el token de invitación
		db.DB.Exec("INSERT INTO users (username, password_hash, totp_secret, invite_token, is_admin, totp_active) VALUES (?, '', ?, ?, 0, 0)", newUser, totpEnc, inviteToken)

		// Generamos la URL solo para informar en la UI si fuera necesario en el futuro, pero no en el log
		_ = fmt.Sprintf("https://%s/REGIO-login?invite=%s", AdminDomain, inviteToken)
		db.LogEvent(fmt.Sprintf("%s Usuario creado: %s. Enlace de invitación generado.", db.PrefixUSER, newUser), user.Username)
	}
	return false
}

func actionDeleteUser(w http.ResponseWriter, r *http.Request, user *models.User) bool {
	delUser := r.FormValue("del_user")
	var idToDelete int
	db.DB.QueryRow("SELECT id FROM users WHERE username = ?", delUser).Scan(&idToDelete)
	if idToDelete != 1 {
		// Verificar que quede al menos un administrador
		var adminCount int
		db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND id != ?", idToDelete).Scan(&adminCount)
		if adminCount == 0 {
			http.Error(w, "No se puede eliminar el único administrador", http.StatusBadRequest)
			return true
		}
		db.DB.Exec("DELETE FROM users WHERE username = ?", delUser)
		db.LogEvent(fmt.Sprintf("%s Usuario eliminado: %s", db.PrefixUSER, delUser), user.Username)
	}
	return false
}

func actionBanIP(w http.ResponseWriter, r *http.Request, user *models.User) bool {
	targetIP := r.FormValue("target_ip")
	if targetIP != "" {
		security.BanIP(targetIP, "Bloqueo manual del administrador", 365*24*time.Hour)
		db.LogEvent(fmt.Sprintf("%s IP/Rango bloqueado manualmente: %s", db.PrefixBLOCK, targetIP), user.Username)
	}
	return false
}

func actionUnbanIP(w http.ResponseWriter, r *http.Request, user *models.User) bool {
	targetIP := r.FormValue("target_ip")
	security.UnbanIP(targetIP)
	db.LogEvent(fmt.Sprintf("%s IP/Rango desbloqueado: %s", db.PrefixOK, targetIP), user.Username)
	return false
}

func actionRevokeSession(w http.ResponseWriter, r *http.Request, user *models.User) bool {
	tokensToRevoke := r.Form["tokens"]
	if len(tokensToRevoke) == 0 {
		// Fallback para cuando solo viene un 'token' (antiguo comportamiento o individual)
		if t := r.FormValue("token"); t != "" {
			tokensToRevoke = []string{t}
		}
	}
	Mu.Lock()
	for _, t := range tokensToRevoke {
		delete(ActiveSessions, t)
		db.DB.Exec("DELETE FROM sessions WHERE token = ?", t)
	}
	Mu.Unlock()
	db.LogEvent(fmt.Sprintf("%s %d sesiones revocadas por el administrador", db.PrefixBLOCK, len(tokensToRevoke)), user.Username)
	return false
}
