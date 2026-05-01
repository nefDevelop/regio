package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"regio/internal/auth"
	"regio/internal/db"
	"regio/internal/models"
	"regio/internal/security"
)

// UpdateAllowedNetworksFromConfig refresca la lista blanca de redes permitidas basándose en los servicios configurados.
func UpdateAllowedNetworksFromConfig() {
	security.RefreshAllowedNetworks(Config.Servicios)
}

//go:embed templates/*.html
var templateFiles embed.FS

//go:embed static/*
var staticFiles embed.FS

var (
	ActiveSessions  = make(map[string]*models.User)
	Mu              sync.Mutex
	Config          models.Config
	NeedsSetup      bool
	AdminDomain     string
	SessionKey      = "REGIO_session"
	Tmpls           *template.Template
	TrustedProxies  []string
	// Transport personalizado para el proxy con validación DNS anti-rebinding (MED-04)
	proxyTransport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           security.SafeDialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
)

const DefaultCSP = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; img-src 'self' data: https://cdn.simpleicons.org; connect-src 'self' https://wttr.in; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; report-uri /api/csp-report"

func sessionHash(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func Init() {
	Tmpls = template.Must(template.ParseFS(templateFiles, "templates/*.html"))

	// Registrar tipos MIME comunes (blindaje si falta mailcap/mime.types en el sistema)
	mime.AddExtensionType(".js", "application/javascript")
	mime.AddExtensionType(".css", "text/css")
	mime.AddExtensionType(".svg", "image/svg+xml")
	mime.AddExtensionType(".png", "image/png")
	mime.AddExtensionType(".jpg", "image/jpeg")
	mime.AddExtensionType(".jpeg", "image/jpeg")
	mime.AddExtensionType(".gif", "image/gif")
	mime.AddExtensionType(".ico", "image/x-icon")
	mime.AddExtensionType(".html", "text/html")
	mime.AddExtensionType(".json", "application/json")
	mime.AddExtensionType(".woff", "font/woff")
	mime.AddExtensionType(".woff2", "font/woff2")

	// Cargar proxies de confianza desde el entorno
	proxies := os.Getenv("TRUSTED_PROXIES")
	if proxies != "" {
		TrustedProxies = strings.Split(proxies, ",")
		for i := range TrustedProxies {
			TrustedProxies[i] = strings.TrimSpace(TrustedProxies[i])
		}
	}

	security.LoadBypassKeys()
	security.InitIPFilter()
	LoadSessions()
}

func isTrustedProxy(ip string) bool {
	if len(TrustedProxies) == 0 {
		return false
	}
	for _, trusted := range TrustedProxies {
		if trusted == ip {
			return true
		}
		if strings.Contains(trusted, "/") {
			_, ipnet, err := net.ParseCIDR(trusted)
			if err == nil && ipnet.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}
	return false
}

func getRealIP(r *http.Request) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if isTrustedProxy(remoteIP) {
		if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
			return cfIP
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			return strings.TrimSpace(ips[0])
		}
	}
	return remoteIP
}

func LoadSessions() {
	Mu.Lock()
	defer Mu.Unlock()
	rows, err := db.DB.Query("SELECT s.token, s.user_id, COALESCE(s.csrf_token, ''), u.username, u.is_admin, u.totp_active, s.ip, s.last_active FROM sessions s JOIN users u ON s.user_id = u.id")
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var token, username, ip, csrf string
		var userID int
		var isAdmin, totpActive bool
		var lastActive time.Time
		rows.Scan(&token, &userID, &csrf, &username, &isAdmin, &totpActive, &ip, &lastActive)

		// Si por alguna razón la sesión vieja no tiene CSRF (migración), generamos uno
		if csrf == "" {
			csrf = auth.GenerateSessionToken()
			db.DB.Exec("UPDATE sessions SET csrf_token = ? WHERE token = ?", csrf, token)
		}

		ActiveSessions[token] = &models.User{
			ID:         userID,
			Username:   username,
			IsAdmin:    isAdmin,
			TotpActive: totpActive,
			CSRFToken:  csrf,
			LastActive: lastActive,
			RemoteIP:   ip,
		}
	}
}

func ServeStatic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	ext := filepath.Ext(r.URL.Path)
	if ct := mime.TypeByExtension(ext); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	http.FileServer(http.FS(staticFiles)).ServeHTTP(w, r)
}

func HandleLogin(w http.ResponseWriter, r *http.Request, ip string) {
	if r.Method == "POST" {
		inputUser := r.FormValue("user")
		LogEvent(fmt.Sprintf("%s Intento de login para usuario: %s desde %s", db.PrefixSCAN, inputUser, ip), "Sistema")

		// Verificar si la cuenta está bloqueada por fuerza bruta distribuida
		if security.IsUserBlocked(inputUser) {
			db.LogEvent(fmt.Sprintf("%s Intento de login en cuenta bloqueada: %s desde %s", db.PrefixBLOCK, inputUser, ip), "Sistema")
			http.Redirect(w, r, "/REGIO-login?error=locked", http.StatusSeeOther)
			return
		}

		var hash, totpEnc, inviteStored string
		var id int
		var isAdmin, totpActive bool
		err := db.DB.QueryRow("SELECT id, COALESCE(password_hash, ''), COALESCE(totp_secret, ''), COALESCE(invite_token, ''), is_admin, totp_active FROM users WHERE username = ?", inputUser).Scan(&id, &hash, &totpEnc, &inviteStored, &isAdmin, &totpActive)
		if err != nil {
			LogEvent(fmt.Sprintf("%s Error buscando usuario %s en DB: %v", db.PrefixERR, inputUser, err), "Sistema")
		}

		if err == nil && hash == "" {
			// El usuario no tiene contraseña, verificamos el token de invitación
			inviteGiven := r.URL.Query().Get("invite")
			if inviteGiven == "" || subtle.ConstantTimeCompare([]byte(inviteGiven), []byte(inviteStored)) != 1 {
				db.LogEvent(fmt.Sprintf("%s Intento de acceso a usuario sin contraseña sin token válido: %s", db.PrefixWARN, inputUser), ip)
				http.Redirect(w, r, "/REGIO-login?error=invalid_invite", http.StatusSeeOther)
				return
			}

			step := r.FormValue("step")
			if step == "set_password" {
				newPass := r.FormValue("new_pass")
				confirmPass := r.FormValue("confirm_pass")
				if len(newPass) < 8 {
					Tmpls.ExecuteTemplate(w, "setpassword.html", map[string]interface{}{"User": inputUser, "Error": "La contraseña debe tener al menos 8 caracteres"})
					return
				}
				if newPass != "" && newPass == confirmPass {
					newHash := auth.HashPassword(newPass)
					// Guardamos la pass y BORRAMOS el invite_token
					db.DB.Exec("UPDATE users SET password_hash = ?, invite_token = NULL WHERE id = ?", newHash, id)

					rawToken := auth.GenerateSessionToken()
					setSessionCookie(w, r, rawToken)
					tokenHash := sessionHash(rawToken)

					csrf := auth.GenerateSessionToken()
					Mu.Lock()
					ActiveSessions[tokenHash] = &models.User{
						ID:         id,
						Username:   inputUser,
						IsAdmin:    isAdmin,
						TotpActive: totpActive,
						CSRFToken:  csrf,
						LastActive: time.Now(),
						RemoteIP:   ip,
					}
					Mu.Unlock()
					security.UnbanIP(ip)

					db.DB.Exec("INSERT INTO sessions (token, user_id, csrf_token, ip, user_agent, last_active) VALUES (?, ?, ?, ?, ?, ?)", tokenHash, id, csrf, ip, r.UserAgent(), time.Now())
					db.LogEvent(fmt.Sprintf("%s Contraseña inicial creada y sesión iniciada: %s", db.PrefixPASS, inputUser), inputUser)
					http.Redirect(w, r, "/", http.StatusSeeOther)
					return
				}
				Tmpls.ExecuteTemplate(w, "setpassword.html", map[string]interface{}{"User": inputUser, "Error": "Las contraseñas no coinciden"})
				return
			}
			Tmpls.ExecuteTemplate(w, "setpassword.html", map[string]interface{}{"User": inputUser})
			return
		}

		inputPass := r.FormValue("pass")
		input2fa := r.FormValue("2fa")

		loginValido := false
		if err == nil && auth.VerifyPassword(inputPass, hash) {
			LogEvent(fmt.Sprintf("%s Contraseña correcta para %s", inputUser), "Sistema")
			if !totpActive {
				loginValido = true
			} else {
				// Descifrar secreto para validar TOTP
				totpSecret, decErr := auth.Decrypt(totpEnc)
				if decErr == nil && input2fa == auth.GetTOTPCode(totpSecret) {
					loginValido = true
				} else {
					LogEvent(fmt.Sprintf("%s Fallo TOTP para %s", inputUser), "Sistema")
				}
			}
		} else {
			LogEvent(fmt.Sprintf("%s Contraseña incorrecta para %s", inputUser), "Sistema")
		}

		if loginValido {
			security.ResetearIntentosUsuario(inputUser)
			rawToken := auth.GenerateSessionToken()
			setSessionCookie(w, r, rawToken)
			tokenHash := sessionHash(rawToken)

			csrf := auth.GenerateSessionToken()
			Mu.Lock()
			ActiveSessions[tokenHash] = &models.User{
				ID:         id,
				Username:   inputUser,
				IsAdmin:    isAdmin,
				TotpActive: totpActive,
				CSRFToken:  csrf,
				LastActive: time.Now(),
				RemoteIP:   ip,
			}
			Mu.Unlock()
			security.ResetearIntentosUsuario(inputUser)
			security.UnbanIP(ip)

			db.DB.Exec("INSERT INTO sessions (token, user_id, csrf_token, ip, user_agent, last_active) VALUES (?, ?, ?, ?, ?, ?)", tokenHash, id, csrf, ip, r.UserAgent(), time.Now())
			db.LogEvent(fmt.Sprintf("%s Inicio de sesión exitoso: %s (%s)", db.PrefixOK, inputUser, ip), inputUser)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		security.RegistrarFallo(ip)
		security.RegistrarFalloUsuario(inputUser)
		http.Redirect(w, r, "/REGIO-login?error=1", http.StatusSeeOther)
		return
	}
	Tmpls.ExecuteTemplate(w, "login.html", r.URL.Query().Get("error") != "")
}

func HandleAdmin(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(SessionKey)
	cookieHash := sessionHash(cookie.Value)
	Mu.Lock()
	user, ok := ActiveSessions[cookieHash]
	Mu.Unlock()
	if !ok {
		http.Error(w, "Sesión inválida", http.StatusUnauthorized)
		return
	}

	if r.Method == "GET" && r.URL.Query().Get("action") == "get_service_details" {
		host := r.URL.Query().Get("host")
		if host == "" {
			http.Error(w, "Host requerido", http.StatusBadRequest)
			return
		}

		type ServiceDetails struct {
			Events     []models.Event      `json:"events"`
			CSPReports []models.CSPReport  `json:"csp_reports"`
			BypassKeys []models.BypassKey  `json:"bypass_keys"`
		}
		var details ServiceDetails
		details.Events = []models.Event{}
		details.CSPReports = []models.CSPReport{}
		details.BypassKeys = []models.BypassKey{}

		// Get CSP reports for this host
		rowsCSP, errCSP := db.DB.Query("SELECT id, host, blocked_uri, violated_directive, original_policy, datetime(created_at, 'localtime') FROM csp_reports WHERE host = ? ORDER BY id DESC LIMIT 50", host)
		if errCSP == nil {
			defer rowsCSP.Close()
			for rowsCSP.Next() {
				var report models.CSPReport
				rowsCSP.Scan(&report.ID, &report.Host, &report.BlockedURI, &report.ViolatedDirective, &report.OriginalPolicy, &report.CreatedAt)
				details.CSPReports = append(details.CSPReports, report)
			}
		}

		// Get events containing the host name
		rowsEvents, errEv := db.DB.Query("SELECT datetime(timestamp, 'localtime'), message, performer FROM events WHERE message LIKE ? ORDER BY id DESC LIMIT 50", "%"+host+"%")
		if errEv == nil {
			defer rowsEvents.Close()
			for rowsEvents.Next() {
				var e models.Event
				rowsEvents.Scan(&e.Timestamp, &e.Message, &e.Performer)
				details.Events = append(details.Events, e)
			}
		}

		// Get bypass keys for this host
		allKeys := security.GetBypassKeys()
		for _, k := range allKeys {
			if k.Host == host {
				details.BypassKeys = append(details.BypassKeys, k)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(details)
		return
	}

	if r.Method == "POST" {
		if r.FormValue("csrf_token") != user.CSRFToken {
			http.Error(w, "Error de validación CSRF", http.StatusForbidden)
			return
		}
		accion := r.FormValue("accion")
		switch accion {
		case "add_service":
			host := r.FormValue("host")
			target := r.FormValue("target")
			csp := r.FormValue("csp")
			if host != "" && target != "" {
				if err := security.IsValidTarget(target); err != nil {
					db.LogEvent(fmt.Sprintf("%s Intento de añadir target inválido/SSRF: %s -> %s (%v)", db.PrefixWARN, host, target, err), user.Username)
					http.Error(w, "Target inválido: "+err.Error(), http.StatusBadRequest)
					return
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

				Config.Servicios[host] = target
				Config.Publicos[host] = r.FormValue("public") == "on"
				Config.CSPs[host] = csp

				// Gestión de Bypass Key integrada
				bypassName := r.FormValue("bypass_name")
				bypassToken := r.FormValue("bypass_token")
				if bypassName != "" && bypassToken != "" {
					security.AddBypassKey(bypassToken, bypassName, host)
					db.LogEvent(fmt.Sprintf("%s Bypass key creada automáticamente para: %s (%s)", db.PrefixKEY, host, bypassName), user.Username)
				}

				db.SaveConfig(Config)
				UpdateAllowedNetworksFromConfig()
				Mu.Unlock()
				db.LogEvent(fmt.Sprintf("%s Puente añadido: %s -> %s (Público: %v)", db.PrefixREGIO, host, target, Config.Publicos[host]), user.Username)
			}
		case "update_service":
			host := r.FormValue("old_host")
			newHost := r.FormValue("host")
			target := r.FormValue("target")
			csp := r.FormValue("csp")
			if host != "" && newHost != "" && target != "" {
				if err := security.IsValidTarget(target); err != nil {
					db.LogEvent(fmt.Sprintf("%s Intento de actualizar target inválido/SSRF: %s -> %s (%v)", db.PrefixWARN, newHost, target, err), user.Username)
					http.Error(w, "Target inválido: "+err.Error(), http.StatusBadRequest)
					return
				}
				Mu.Lock()
				if Config.Servicios == nil {
					Config.Servicios = make(map[string]string)
				}
				if Config.CSPs == nil {
					Config.CSPs = make(map[string]string)
				}
				delete(Config.Servicios, host)
				Config.Servicios[newHost] = target
				// Mantener sincronizado el estado de "Público" y "Bypass"
				isPublic := Config.Publicos[host]
				delete(Config.Publicos, host)
				Config.Publicos[newHost] = isPublic

				bypass := Config.BypassHeaders[host]
				delete(Config.BypassHeaders, host)
				Config.BypassHeaders[newHost] = bypass

				delete(Config.CSPs, host)
				Config.CSPs[newHost] = csp

				db.SaveConfig(Config)
				UpdateAllowedNetworksFromConfig()
				Mu.Unlock()
				db.LogEvent(fmt.Sprintf("%s Puente actualizado: %s -> %s", db.PrefixREGIO, newHost, target), user.Username)
			}
		case "delete_service":
			host := r.FormValue("host")
			Mu.Lock()
			delete(Config.Servicios, host)
			delete(Config.Publicos, host)
			delete(Config.BypassHeaders, host)
			delete(Config.CSPs, host)
			db.SaveConfig(Config)
			UpdateAllowedNetworksFromConfig()
			Mu.Unlock()
			db.LogEvent(fmt.Sprintf("%s Puente eliminado: %s", db.PrefixREGIO, host), user.Username)
		case "add_bypass_key":
			token := r.FormValue("token")
			name := r.FormValue("name")
			host := r.FormValue("host")
			if token == "" || name == "" || host == "" {
				http.Error(w, "Todos los campos son obligatorios para crear una Bypass Key", http.StatusBadRequest)
				return
			}
			security.AddBypassKey(token, name, host)
			db.LogEvent(fmt.Sprintf("%s Bypass key creada: %s para host %s", db.PrefixKEY, name, host), user.Username)
		case "delete_bypass_key":
			token := r.FormValue("token")
			security.DeleteBypassKey(token)
			db.LogEvent(fmt.Sprintf("%s Bypass key eliminada: %s", db.PrefixKEY, token), user.Username)
		case "add_user":
			newUser := r.FormValue("new_user")
			if newUser != "" {
				totp := auth.GenerateTOTPSecret()
				totpEnc, _ := auth.Encrypt(totp)
				inviteToken := auth.GenerateSessionToken() // Usamos la misma función para el token de invitación
				db.DB.Exec("INSERT INTO users (username, password_hash, totp_secret, invite_token, is_admin, totp_active) VALUES (?, '', ?, ?, 0, 0)", newUser, totpEnc, inviteToken)

				inviteURL := fmt.Sprintf("https://%s/REGIO-login?invite=%s", AdminDomain, inviteToken)
				db.LogEvent(fmt.Sprintf("%s Usuario creado: %s. URL de invitación: %s", db.PrefixUSER, newUser, inviteURL), user.Username)
				}
				case "delete_user":
				delUser := r.FormValue("del_user")
				var idToDelete int
				db.DB.QueryRow("SELECT id FROM users WHERE username = ?", delUser).Scan(&idToDelete)
				if idToDelete != 1 {
				db.DB.Exec("DELETE FROM users WHERE username = ?", delUser)
				db.LogEvent(fmt.Sprintf("%s Usuario eliminado: %s", db.PrefixUSER, delUser), user.Username)
				}
				case "ban_ip":
				targetIP := r.FormValue("target_ip")
				if targetIP != "" {
				security.BanIP(targetIP, "Bloqueo manual del administrador", 365*24*time.Hour)
				db.LogEvent(fmt.Sprintf("%s IP/Rango bloqueado manualmente: %s", db.PrefixBLOCK, targetIP), user.Username)
				}
				case "unban_ip":
				targetIP := r.FormValue("target_ip")
				security.UnbanIP(targetIP)
				db.LogEvent(fmt.Sprintf("%s IP/Rango desbloqueado: %s", db.PrefixOK, targetIP), user.Username)

		case "revoke_session":
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

		}
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	var users []models.User
	rows, _ := db.DB.Query("SELECT id, username, COALESCE(totp_secret, ''), is_admin, totp_active FROM users")
	defer rows.Close()
	for rows.Next() {
		var u models.User
		rows.Scan(&u.ID, &u.Username, &u.TotpSecret, &u.IsAdmin, &u.TotpActive)
		users = append(users, u)
	}

	bypassList := security.GetBypassKeys()

	bannedList := security.GetBannedIPs()

	var events []models.Event
	rowsEvents, _ := db.DB.Query("SELECT datetime(timestamp, 'localtime'), message, performer FROM events ORDER BY id DESC LIMIT 50")
	defer rowsEvents.Close()
	for rowsEvents.Next() {
		var e models.Event
		rowsEvents.Scan(&e.Timestamp, &e.Message, &e.Performer)
		events = append(events, e)
	}

	hostSuggestions := make(map[string]bool)
	targetSuggestions := make(map[string]bool)

	Mu.Lock()
	for host, target := range Config.Servicios {
		hostSuggestions[host] = true
		targetSuggestions[target] = true
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			baseDomain := strings.Join(parts[len(parts)-2:], ".")
			hostSuggestions["."+baseDomain] = true
		}
		if strings.HasPrefix(target, "http") {
			urlParts := strings.Split(target, "/")
			if len(urlParts) >= 3 {
				domainPart := urlParts[2]
				ipParts := strings.Split(domainPart, ".")
				if len(ipParts) >= 3 {
					targetSuggestions["http://"+strings.Join(ipParts[:3], ".")+".:"] = true
				}
				targetSuggestions["http://"+domainPart] = true
			}
		}
	}
	Mu.Unlock()

	var hosts []string
	for h := range hostSuggestions {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	var targets []string
	for t := range targetSuggestions {
		targets = append(targets, t)
	}
	sort.Strings(targets)

	type ServiceStatus struct {
		Host   string
		Target string
		Alive  bool
	}
	var healthResults []ServiceStatus
	var wg sync.WaitGroup
	var healthMu sync.Mutex

	Mu.Lock()
	for host, target := range Config.Servicios {
		wg.Add(1)
		go func(h, t string) {
			defer wg.Done()
			alive := checkServiceHealth(t)
			healthMu.Lock()
			healthResults = append(healthResults, ServiceStatus{Host: h, Target: t, Alive: alive})
			healthMu.Unlock()
		}(host, target)
	}
	Mu.Unlock()
	wg.Wait()

	sort.Slice(healthResults, func(i, j int) bool {
		return healthResults[i].Host < healthResults[j].Host
	})

	type GlobalSessionDisplay struct {
		Username   string
		IP         string
		LastActive string
		Count      int
		IsCurrent  bool
		Tokens     []string // Guardar tokens para revocación masiva si se desea
	}
	var allSessions []GlobalSessionDisplay
	sessionMap := make(map[string]*GlobalSessionDisplay)

	Mu.Lock()
	for token, sUser := range ActiveSessions {
		key := sUser.Username + "|" + sUser.RemoteIP
		if s, exists := sessionMap[key]; exists {
			s.Count++
			s.Tokens = append(s.Tokens, token)
			if token == cookieHash {
				s.IsCurrent = true
			}
		} else {
			sd := &GlobalSessionDisplay{
				Username:   sUser.Username,
				IP:         sUser.RemoteIP,
				LastActive: RelTime(sUser.LastActive),
				Count:      1,
				IsCurrent:  token == cookieHash,
				Tokens:     []string{token},
			}
			sessionMap[key] = sd
			allSessions = append(allSessions, *sd)
		}
	}
	Mu.Unlock()

	// Actualizar el slice con los datos finales del mapa (para mantener punteros/conteos si fuera necesario)
	// Pero como ya añadimos el struct al slice, necesitamos reconstruirlo o usar punteros.
	// Re-recorrer el slice para asignar los valores finales.
	for i := range allSessions {
		key := allSessions[i].Username + "|" + allSessions[i].IP
		allSessions[i] = *sessionMap[key]
	}

	sort.Slice(allSessions, func(i, j int) bool {
		if allSessions[i].Username != allSessions[j].Username {
			return allSessions[i].Username < allSessions[j].Username
		}
		return allSessions[i].IP < allSessions[j].IP
	})

	data := struct {
		Config            models.Config
		Users             []models.User
		BypassKeys        []models.BypassKey
		CSRFToken         string
		BannedIPs         []models.BannedIP
		Events            []models.Event
		HostSuggestions   []string
		TargetSuggestions []string
		HealthResults     []ServiceStatus
		AllSessions       []GlobalSessionDisplay
		CSPReports        []models.CSPReport
	}{
		Config:            Config,
		Users:             users,
		BypassKeys:        bypassList,
		CSRFToken:         user.CSRFToken,
		BannedIPs:         bannedList,
		Events:            events,
		HostSuggestions:   hosts,
		TargetSuggestions: targets,
		HealthResults:     healthResults,
		AllSessions:       allSessions,
		CSPReports:        db.GetRecentCSPReports(20),
	}
	Tmpls.ExecuteTemplate(w, "admin.html", data)
}

func HandleProfile(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(SessionKey)
	cookieHash := sessionHash(cookie.Value)
	Mu.Lock()
	userSession, ok := ActiveSessions[cookieHash]
	Mu.Unlock()
	if !ok {
		http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
		return
	}

	var u models.User
	var totpEnc, passwordHash string
	db.DB.QueryRow("SELECT id, username, COALESCE(password_hash, ''), COALESCE(totp_secret, ''), totp_active, is_admin FROM users WHERE id = ?", userSession.ID).Scan(&u.ID, &u.Username, &passwordHash, &totpEnc, &u.TotpActive, &u.IsAdmin)

	if totpEnc == "" {
		rawTotp := auth.GenerateTOTPSecret()
		totpEnc, _ = auth.Encrypt(rawTotp)
		db.DB.Exec("UPDATE users SET totp_secret = ? WHERE id = ?", totpEnc, u.ID)
		u.TotpSecret = rawTotp
	} else {
		u.TotpSecret, _ = auth.Decrypt(totpEnc)
	}

	var newToken string
	errorMsg := false

	if r.Method == "POST" {
		if r.FormValue("csrf_token") != userSession.CSRFToken {
			http.Error(w, "Error de validación CSRF", http.StatusForbidden)
			return
		}
		accion := r.FormValue("accion")
		if accion == "update_profile" {
			newUsername := r.FormValue("new_username")
			newPassword := r.FormValue("new_password")
			currentPassword := r.FormValue("current_password")

			// Verificar contraseña actual para cualquier cambio de credenciales
			needsVerification := newPassword != "" || (newUsername != "" && newUsername != u.Username)
			if needsVerification && !auth.VerifyPassword(currentPassword, passwordHash) {
				http.Error(w, "Contraseña actual incorrecta", http.StatusForbidden)
				return
			}

			if newUsername != "" && newUsername != u.Username {
				_, err := db.DB.Exec("UPDATE users SET username = ? WHERE id = ?", newUsername, u.ID)
				if err == nil {
					u.Username = newUsername
					Mu.Lock()
					userSession.Username = newUsername
					Mu.Unlock()
					db.LogEvent(fmt.Sprintf("%s Nombre de usuario actualizado: %s", newUsername), u.Username)
				}
			}
			if newPassword != "" {
				if len(newPassword) < 8 {
					http.Error(w, "La contraseña debe tener al menos 8 caracteres", http.StatusBadRequest)
					return
				}
				newHash := auth.HashPassword(newPassword)
				db.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", newHash, u.ID)
				// Invalidar todas las demás sesiones del usuario (LOW-02)
				Mu.Lock()
				for token, sUser := range ActiveSessions {
					if sUser.ID == u.ID && token != cookieHash {
						delete(ActiveSessions, token)
					}
				}
				Mu.Unlock()
				db.DB.Exec("DELETE FROM sessions WHERE user_id = ? AND token != ?", u.ID, cookieHash)
				db.LogEvent(fmt.Sprintf("%s Contraseña actualizada por el usuario: %s (sesiones previas invalidadas)", u.Username), u.Username)
			}
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		} else if accion == "enable_2fa" {
			if r.FormValue("code") == auth.GetTOTPCode(u.TotpSecret) {
				db.DB.Exec("UPDATE users SET totp_active = 1 WHERE id = ?", u.ID)
				db.LogEvent(fmt.Sprintf("%s 2FA activado por el usuario: %s", u.Username), u.Username)
				http.Redirect(w, r, "/profile", http.StatusSeeOther)
				return
			} else {
				errorMsg = true
			}
		} else if accion == "disable_2fa" {
			db.DB.Exec("UPDATE users SET totp_active = 0 WHERE id = ?", u.ID)
			db.LogEvent(fmt.Sprintf("%s 2FA desactivado por el usuario: %s", u.Username), u.Username)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		} else if accion == "create_token" {
			tokenName := r.FormValue("token_name")
			if tokenName == "" {
				http.Error(w, "El nombre del token es obligatorio", http.StatusBadRequest)
				return
			}
			rawToken := auth.GenerateSessionToken()
			hash := sha256.Sum256([]byte(rawToken))
			tokenHash := base64.StdEncoding.EncodeToString(hash[:])
			_, err := db.DB.Exec("INSERT INTO app_tokens (user_id, name, token_hash) VALUES (?, ?, ?)", u.ID, tokenName, tokenHash)
			if err == nil {
				newToken = rawToken
				db.LogEvent(fmt.Sprintf("%s App Token creado: %s para el usuario: %s", tokenName, u.Username), u.Username)
			}
		} else if accion == "revoke_token" {
			tokenID := r.FormValue("token_id")
			db.DB.Exec("DELETE FROM app_tokens WHERE id = ? AND user_id = ?", tokenID, u.ID)
			db.LogEvent(fmt.Sprintf("%s App Token revocado por el usuario: %s", u.Username), u.Username)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		} else if accion == "revoke_session" {
			tokenToRevoke := r.FormValue("token")
			Mu.Lock()
			delete(ActiveSessions, tokenToRevoke)
			Mu.Unlock()
			db.DB.Exec("DELETE FROM sessions WHERE token = ?", tokenToRevoke)
			db.LogEvent(fmt.Sprintf("%s Sesión de navegador revocada por el usuario: %s", u.Username), u.Username)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		} else if accion == "add_bypass_key" && u.IsAdmin {
			token := r.FormValue("token")
			name := r.FormValue("name")
			host := r.FormValue("host")
			if token == "" || name == "" || host == "" {
				http.Error(w, "Todos los campos son obligatorios para crear una Bypass Key", http.StatusBadRequest)
				return
			}
			security.AddBypassKey(token, name, host)
			db.LogEvent(fmt.Sprintf("%s Bypass key creada: %s para host %s", name, host), u.Username)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		} else if accion == "delete_bypass_key" && u.IsAdmin {
			token := r.FormValue("token")
			security.DeleteBypassKey(token)
			db.LogEvent(fmt.Sprintf("%s Bypass key eliminada: %s", token), u.Username)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		}
	}

	var appTokens []models.AppToken
	rows, _ := db.DB.Query("SELECT id, name, last_used, created_at FROM app_tokens WHERE user_id = ?", u.ID)
	defer rows.Close()
	for rows.Next() {
		var t models.AppToken
		rows.Scan(&t.ID, &t.Name, &t.LastUsed, &t.CreatedAt)
		appTokens = append(appTokens, t)
	}

	var bypassKeys []models.BypassKey
	if u.IsAdmin {
		bypassKeys = security.GetBypassKeys()
	}

	otpUrl := fmt.Sprintf("otpauth://totp/reGIO:%%20%s?secret=%s&issuer=reGIO", u.Username, u.TotpSecret)

	type SessionDisplay struct {
		Token      string
		IP         string
		LastActive string
		IsCurrent  bool
	}
	var sessions []SessionDisplay
	Mu.Lock()
	for token, sUser := range ActiveSessions {
		if sUser.ID == u.ID {
			sessions = append(sessions, SessionDisplay{
				Token:      token,
				IP:         sUser.RemoteIP,
				LastActive: RelTime(sUser.LastActive),
				IsCurrent:  token == cookieHash,
			})
		}
	}
	Mu.Unlock()

	type TokenDisplay struct {
		models.AppToken
		LastUsedRel string
	}
	var displayTokens []TokenDisplay
	for _, t := range appTokens {
		displayTokens = append(displayTokens, TokenDisplay{
			AppToken:    t,
			LastUsedRel: RelTime(t.LastUsed.Time),
		})
	}

	Tmpls.ExecuteTemplate(w, "profile.html", struct {
		User       models.User
		OtpUrl     string
		Error      bool
		Tokens     []TokenDisplay
		BypassKeys []models.BypassKey
		NewToken   string
		CSRFToken  string
		Sessions   []SessionDisplay
	}{u, otpUrl, errorMsg, displayTokens, bypassKeys, newToken, userSession.CSRFToken, sessions})
}

func HandleSetup(w http.ResponseWriter, r *http.Request) {
	// CRIT-04: Verificar NeedsSetup dentro del handler para evitar race condition
	Mu.Lock()
	if !NeedsSetup {
		Mu.Unlock()
		http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
		return
	}
	Mu.Unlock()

	if r.Method == "POST" {
		user := r.FormValue("user")
		pass := r.FormValue("pass")
		if len(pass) < 12 {
			Tmpls.ExecuteTemplate(w, "setup.html", "La contraseña del administrador debe tener al menos 12 caracteres")
			return
		}
		if user != "" && pass != "" {
			hash := auth.HashPassword(pass)
			rawSecret := auth.GenerateTOTPSecret()
			encryptedSecret, _ := auth.Encrypt(rawSecret)
			Mu.Lock()
			if !NeedsSetup {
				Mu.Unlock()
				http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
				return
			}
			_, err := db.DB.Exec("INSERT INTO users (username, password_hash, totp_secret, is_admin, totp_active) VALUES (?, ?, ?, 1, 0)", user, hash, encryptedSecret)
			if err == nil {
				db.LogEvent("%s Instalación completada. Administrador original creado.", "Sistema")
				NeedsSetup = false
			}
			Mu.Unlock()
			if err == nil {
				http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
				return
			}
		}
	}
	Tmpls.ExecuteTemplate(w, "setup.html", nil)
}

func checkServiceHealth(target string) bool {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 500
}

func RelTime(t time.Time) string {
	if t.IsZero() {
		return "Nunca"
	}
	diff := time.Since(t)
	if diff < time.Minute {
		return "hace unos segundos"
	}
	if diff < time.Hour {
		return fmt.Sprintf("hace %d min", int(diff.Minutes()))
	}
	if diff < 24*time.Hour {
		return fmt.Sprintf("hace %d horas", int(diff.Hours()))
	}
	return t.Format("02/01/2006")
}

func LogEvent(message string, performer string) {
	db.LogEvent(message, performer)
}

func UpdateSessionActivity(token string) {
	Mu.Lock()
	user, ok := ActiveSessions[token]
	if ok {
		user.LastActive = time.Now()
	}
	Mu.Unlock()
	if ok {
		db.DB.Exec("UPDATE sessions SET last_active = ? WHERE token = ?", time.Now(), token)
	}
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     SessionKey,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600 * 24,
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	Mu.Lock()
	target, ok := Config.Servicios[r.Host]
	Mu.Unlock()
	if !ok {
		http.Error(w, "Dominio no configurado", http.StatusNotFound)
		return
	}
	remote, _ := url.Parse(target)
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.Transport = proxyTransport
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Header.Get("Content-Type") == "" {
			ext := filepath.Ext(resp.Request.URL.Path)
			if ct := mime.TypeByExtension(ext); ct != "" {
				resp.Header.Set("Content-Type", ct)
			}
		}
		return nil
	}
	r.URL.Host, r.URL.Scheme = remote.Host, remote.Scheme
	r.Header.Set("X-Forwarded-Host", r.Host)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Host = remote.Host
	proxy.ServeHTTP(w, r)
}

func HandleCSPReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("%s Error leyendo cuerpo de reporte CSP: %v", err)
		return
	}
	defer r.Body.Close()

	log.Printf("%s REPORTE CSP RECIBIDO (RAW): %s", string(body))

	// Intentar parsear con el wrapper "csp-report"
	var payload models.CSPReportPayload
	var report struct {
		DocumentURI       string `json:"document-uri"`
		ViolatedDirective string `json:"violated-directive"`
		OriginalPolicy    string `json:"original-policy"`
		BlockedURI        string `json:"blocked-uri"`
	}

	if err := json.Unmarshal(body, &payload); err == nil && (payload.CSPReport.BlockedURI != "" || payload.CSPReport.ViolatedDirective != "") {
		report.DocumentURI = payload.CSPReport.DocumentURI
		report.ViolatedDirective = payload.CSPReport.ViolatedDirective
		report.OriginalPolicy = payload.CSPReport.OriginalPolicy
		report.BlockedURI = payload.CSPReport.BlockedURI
	} else {
		// Intentar parsear el objeto plano (algunos navegadores)
		if err := json.Unmarshal(body, &report); err != nil {
			log.Printf("%s Error parseando reporte CSP: %v (Body: %s)", err, string(body))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	// Guardar reporte si hay URI bloqueada O si hay directiva violada (para inline/eval)
	if report.BlockedURI != "" || report.ViolatedDirective != "" {
		host := r.Host
		if report.DocumentURI != "" {
			if u, err := url.Parse(report.DocumentURI); err == nil {
				host = u.Host
			}
		}

		blocked := report.BlockedURI
		if blocked == "" {
			blocked = "inline/eval/other"
		}

		db.SaveCSPReport(host, blocked, report.ViolatedDirective, report.OriginalPolicy)
		db.LogEvent(fmt.Sprintf("%s Bloqueo CSP en %s: %s (Directiva: %s)", host, blocked, report.ViolatedDirective), "Sistema")
		log.Printf("%s Reporte CSP recibido para %s: %s violó %s", host, blocked, report.ViolatedDirective)
	}

	w.WriteHeader(http.StatusNoContent)
}

func MainHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s INCOMING: %s %s (Host: %s, Remote: %s)", db.PrefixIN, r.Method, r.URL.Path, r.Host, r.RemoteAddr)

	if r.URL.Path == "/api/csp-report" {
		HandleCSPReport(w, r)
		return
	}

	sw := &statusWriter{ResponseWriter: w, status: 200}
	ip := getRealIP(r)

	// Sanitizar URI para logs (eliminar parámetros sensibles)
	logURI := r.URL.Path
	if r.URL.RawQuery != "" {
		logURI += "?[redacted]"
	}

	defer func() {
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			log.Printf("%s [%d] %s %s %s (Host: %s)", db.PrefixOUT, sw.status, r.Method, logURI, ip, r.Host)
		}
	}()

	sw.Header().Set("X-Content-Type-Options", "nosniff")
	sw.Header().Set("X-Frame-Options", "DENY")
	sw.Header().Set("X-XSS-Protection", "1; mode=block")
	sw.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	sw.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	sw.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

	Mu.Lock()
	customCSP := Config.CSPs[r.Host]
	Mu.Unlock()

	if r.Host == AdminDomain {
		// El admin necesita unsafe-eval para qrcode.js
		if customCSP != "" {
			if !strings.Contains(customCSP, "'unsafe-eval'") {
				customCSP = strings.Replace(customCSP, "script-src", "script-src 'unsafe-eval'", 1)
			}
		} else {
			customCSP = strings.Replace(DefaultCSP, "script-src 'self'", "script-src 'self' 'unsafe-eval'", 1)
		}
	}

	if customCSP != "" {
		if !strings.Contains(customCSP, "report-uri") {
			customCSP += "; report-uri /api/csp-report"
		}
		sw.Header().Set("Content-Security-Policy", customCSP)
	} else {
		sw.Header().Set("Content-Security-Policy", DefaultCSP)
	}

	if err := security.SecurityEngine(ip, r); err != nil {
		if strings.Contains(err.Error(), "IP bloqueada") {
			sw.status = http.StatusForbidden
			http.Error(sw, err.Error(), http.StatusForbidden)
		} else {
			sw.status = http.StatusTooManyRequests
			http.Error(sw, "Demasiadas peticiones. Por favor, espera un minuto.", http.StatusTooManyRequests)
		}
		return
	}

	if strings.HasPrefix(r.URL.Path, "/static/") {
		ServeStatic(sw, r)
		return
	}

	// Fallback para favicon.ico usando el logo SVG
	if r.URL.Path == "/favicon.ico" {
		r.URL.Path = "/static/reGIO.svg"
		ServeStatic(sw, r)
		return
	}

	Mu.Lock()
	isSetup := NeedsSetup
	Mu.Unlock()
	if isSetup {
		if r.URL.Path == "/setup" {
			HandleSetup(sw, r)
			return
		}
		sw.status = http.StatusTemporaryRedirect
		http.Redirect(sw, r, "/setup", http.StatusTemporaryRedirect)
		return
	}
	if r.URL.Path == "/REGIO-login" {
		HandleLogin(sw, r, ip)
		return
	}

	var user *models.User
	var validSession bool
	var tokenUsed string

	cookie, err := r.Cookie(SessionKey)
	if err == nil {
		cHash := sessionHash(cookie.Value)
		Mu.Lock()
		user, validSession = ActiveSessions[cHash]
		Mu.Unlock()
		if validSession {
			UpdateSessionActivity(cHash)
		}
	}

	if !validSession {
		// 1. Verificar token en Path: /r-auth/TOKEN/actual-path
		if strings.HasPrefix(r.URL.Path, "/r-auth/") {
			rest := strings.TrimPrefix(r.URL.Path, "/r-auth/")
			parts := strings.SplitN(rest, "/", 2)
			if len(parts) >= 1 {
				potentialToken := parts[0]
				user, tokenUsed, validSession = auth.VerifyAppToken(potentialToken)
				if validSession {
					newPath := "/"
					if len(parts) > 1 {
						newPath += parts[1]
					}
					r.URL.Path = newPath
				}
			}
		}

		// 2. Verificar token en Query: ?api_key=TOKEN
		if !validSession {
			if apiKey := r.URL.Query().Get("api_key"); apiKey != "" {
				user, tokenUsed, validSession = auth.VerifyAppToken(apiKey)
				if validSession {
					q := r.URL.Query()
					q.Del("api_key")
					r.URL.RawQuery = q.Encode()
				}
			}
		}

		if !validSession {
			if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
				user, tokenUsed, validSession = auth.VerifyAppToken(apiKey)
			}
		}

		if !validSession {
			reqUser, reqPass, ok := r.BasicAuth()
			if ok {
				user, tokenUsed, validSession = auth.VerifyAppToken(reqPass)
				if !validSession {
					user, tokenUsed, validSession = auth.VerifyAppToken(reqUser)
				}
			}
		}
	}

	if !validSession && r.Host != AdminDomain {
		// 2. Comprobar Bypass por API Key (Identidad)
		bypassToken := r.Header.Get("X-REGIO-Bypass")
		if bypassToken != "" {
			if ok, name := security.CheckBypass(bypassToken, r.Host); ok {
				db.LogEvent(fmt.Sprintf("%s Acceso Bypass: %s -> %s", name, r.Host), "API-Key")
				ProxyHandler(w, r)
				return
			}
		}

		// 3. Comprobar si es un dominio público
		Mu.Lock()
		bypass, okBypass := Config.BypassHeaders[r.Host]
		publico := Config.Publicos[r.Host]
		Mu.Unlock()

		if okBypass && bypass != "" {
			parts := strings.SplitN(bypass, ":", 2)
			if len(parts) == 2 {
				headerName, expectedValue := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
				if r.Header.Get(headerName) == expectedValue {
					validSession, tokenUsed = true, "bypass-"+headerName
					user = &models.User{Username: "bypass-header", IsAdmin: false}
				}
			}
		}
		if !validSession && publico {
			validSession = true
			user = &models.User{Username: "public", IsAdmin: false}
		}
	}

	if !validSession {
		if !strings.Contains(r.Header.Get("Accept"), "text/html") {
			sw.Header().Set("WWW-Authenticate", `Basic realm="reGIO protegido"`)
			sw.status = http.StatusUnauthorized
			http.Error(sw, "No autorizado", http.StatusUnauthorized)
			return
		}
		sw.status = http.StatusSeeOther
		http.Redirect(sw, r, "/REGIO-login", http.StatusSeeOther)
		return
	}

	if r.URL.Path == "/logout" {
		cookie, err := r.Cookie(SessionKey)
		Mu.Lock()
		if err == nil {
			delete(ActiveSessions, sessionHash(cookie.Value))
		}
		Mu.Unlock()
		http.SetCookie(sw, &http.Cookie{Name: SessionKey, Value: "", Path: "/", MaxAge: -1})
		sw.status = http.StatusSeeOther
		http.Redirect(sw, r, "/REGIO-login", http.StatusSeeOther)
		return
	}

	if r.Host == AdminDomain {
		if r.URL.Path == "/profile" {
			HandleProfile(sw, r)
			return
		}
		if r.URL.Path == "/admin" || r.URL.Path == "/" {
			if !user.IsAdmin {
				sw.status = http.StatusSeeOther
				http.Redirect(sw, r, "/profile", http.StatusSeeOther)
				return
			}
			if r.URL.Path == "/" {
				sw.status = http.StatusSeeOther
				http.Redirect(sw, r, "/admin", http.StatusSeeOther)
				return
			}
			HandleAdmin(sw, r)
			return
		}
	}

	Mu.Lock()
	target, ok := Config.Servicios[r.Host]
	Mu.Unlock()
	if !ok {
		sw.status = http.StatusNotFound
		http.Error(sw, "Dominio no configurado en ReGiO: "+r.Host, http.StatusNotFound)
		return
	}

	remote, _ := url.Parse(target)
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.Transport = proxyTransport // Usar nuestro transporte con timeouts
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Header.Get("Content-Type") == "" {
			ext := filepath.Ext(resp.Request.URL.Path)
			if ct := mime.TypeByExtension(ext); ct != "" {
				resp.Header.Set("Content-Type", ct)
			}
		}
		return nil
	}
	// r.URL.Host y Scheme son necesarios para que el proxy sepa a dónde ir
	r.URL.Host, r.URL.Scheme = remote.Host, remote.Scheme

	// X-Forwarded headers para el backend
	r.Header.Set("X-Forwarded-Host", r.Host)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Host = remote.Host // Restaurar comportamiento original (ayer)

	if tokenUsed != "" {
		r.Header.Del("Authorization")
	}
	r.Header.Del("X-API-Key")
	proxy.ServeHTTP(sw, r)
}

func CleanupSessions() {
	Mu.Lock()
	defer Mu.Unlock()
	limite := time.Now().Add(-7 * 24 * time.Hour)
	for token, user := range ActiveSessions {
		if user.LastActive.Before(limite) {
			delete(ActiveSessions, token)
		}
	}
	db.DB.Exec("DELETE FROM sessions WHERE last_active < ?", limite)
}
