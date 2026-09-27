package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
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
	ActiveSessions = make(map[string]*models.User)
	Mu             sync.Mutex
	Config         models.Config
	NeedsSetup     bool
	AdminDomain    string
	SessionKey     = "REGIO_session"
	Tmpls          *template.Template
	TrustedProxies []string
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

func IsTrustedProxy(ip string) bool {
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

func isTrustedProxy(ip string) bool {
	return IsTrustedProxy(ip)
}

func getRealIP(r *http.Request) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if isTrustedProxy(remoteIP) {
		if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
			return cfIP
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			// Tomar la primera IP (la del cliente real).
			// El proxy de confianza añade la IP del cliente al final de la cadena,
			// pero previene spoofing porque las IPs anteriores vienen del cliente
			// y no son de fiar. Para evitar spoofing, el proxy de confianza debería
			// sobrescribir o sanitizar el header completo.
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
		// Fix S5: anti login-CSRF (login/setup no tienen token)
		if !sameOriginPOST(r) {
			http.Error(w, "Origen no permitido", http.StatusForbidden)
			return
		}
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
			inviteGiven := r.FormValue("invite_token")
			if inviteGiven == "" || subtle.ConstantTimeCompare([]byte(inviteGiven), []byte(inviteStored)) != 1 {
				db.LogEvent(fmt.Sprintf("%s Intento de acceso a usuario sin contraseña sin token válido: %s", db.PrefixWARN, inputUser), ip)
				security.RegistrarFallo(ip)
				security.RegistrarFalloUsuario(inputUser)
				http.Redirect(w, r, "/REGIO-login?error=invalid_invite", http.StatusSeeOther)
				return
			}

			step := r.FormValue("step")
			if step == "set_password" {
				newPass := r.FormValue("new_pass")
				confirmPass := r.FormValue("confirm_pass")
				if len(newPass) < 12 {
					Tmpls.ExecuteTemplate(w, "setpassword.html", map[string]interface{}{"User": inputUser, "Error": "La contraseña debe tener al menos 12 caracteres"})
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
		totpEpoch := int64(0)
		if err == nil && auth.VerifyPassword(inputPass, hash) {
			LogEvent(fmt.Sprintf("%s Contraseña correcta para %s", db.PrefixOK, inputUser), "Sistema")
			if !totpActive {
				loginValido = true
			} else {
				// Descifrar secreto y validar TOTP con ventana ±1 (mejora A2)
				totpSecret, decErr := auth.Decrypt(totpEnc)
				if decErr == nil {
					if ok, epoch := auth.VerifyTOTP(totpSecret, input2fa); ok {
						loginValido = true
						totpEpoch = epoch
					} else {
						LogEvent(fmt.Sprintf("%s Fallo TOTP para %s", db.PrefixWARN, inputUser), "Sistema")
					}
				} else {
					LogEvent(fmt.Sprintf("%s Fallo TOTP para %s", db.PrefixWARN, inputUser), "Sistema")
				}
			}
		} else {
			LogEvent(fmt.Sprintf("%s Contraseña incorrecta para %s", db.PrefixWARN, inputUser), "Sistema")
		}

		// Anti-replay TOTP (mejora A2): el epoch aceptado no puede repetirse.
		// UPDATE condicional y atómico: si otra sesión ya usó este epoch,
		// afecta a 0 filas y el login se considera inválido.
		if loginValido && totpActive && totpEpoch > 0 {
			res, execErr := db.DB.Exec(
				"UPDATE users SET totp_last_epoch = ? WHERE id = ? AND (totp_last_epoch IS NULL OR totp_last_epoch < ?)",
				totpEpoch, id, totpEpoch)
			if execErr == nil {
				if n, _ := res.RowsAffected(); n == 0 {
					db.LogEvent(fmt.Sprintf("%s Código TOTP reutilizado (replay) para %s", db.PrefixBLOCK, inputUser), "Sistema")
					loginValido = false
				}
			} else {
				// Fallo de DB puntual: no bloquear el login por eso (solo log)
				db.LogEvent(fmt.Sprintf("%s Anti-replay TOTP no disponible: %v", db.PrefixWARN, execErr), "Sistema")
			}
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
	cookie, err := r.Cookie(SessionKey)
	if err != nil {
		http.Error(w, "Sesión inválida", http.StatusUnauthorized)
		return
	}
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
			Events     []models.Event     `json:"events"`
			CSPReports []models.CSPReport `json:"csp_reports"`
			BypassKeys []models.BypassKey `json:"bypass_keys"`
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
		// Dispatch de acciones (R2): ver admin_actions.go.
		// stop=true → la acción ya escribió la respuesta (error) y NO rota CSRF;
		// stop=false o acción desconocida → rota CSRF + 303 (como el switch original).
		if action, ok := adminActions[accion]; ok && action(w, r, user) {
			return
		}
		// Rotar CSRF token tras uso exitoso para prevenir reuso
		user.CSRFToken = auth.GenerateSessionToken()
		db.DB.Exec("UPDATE sessions SET csrf_token = ? WHERE token = ?", user.CSRFToken, cookieHash)
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
	if Config.GeoModes == nil {
		Config.GeoModes = make(map[string]string)
	}
	if Config.GeoCountries == nil {
		Config.GeoCountries = make(map[string]string)
	}
	for host, target := range Config.Servicios {
		hostSuggestions[host] = true
		
		targetClean := target
		if strings.HasPrefix(target, "http://") {
			targetClean = strings.TrimPrefix(target, "http://")
		} else if strings.HasPrefix(target, "https://") {
			targetClean = strings.TrimPrefix(target, "https://")
		}
		targetSuggestions[targetClean] = true

		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			baseDomain := strings.Join(parts[len(parts)-2:], ".")
			hostSuggestions["."+baseDomain] = true
			hostSuggestions[baseDomain] = true
		}
		if strings.HasPrefix(target, "http") {
			urlParts := strings.Split(target, "/")
			if len(urlParts) >= 3 {
				domainPart := urlParts[2]
				ipParts := strings.Split(domainPart, ".")
				if len(ipParts) >= 3 {
					targetSuggestions[strings.Join(ipParts[:3], ".")+".:"] = true
				}
				targetSuggestions[domainPart] = true
			}
		}
	}
	Mu.Unlock()

	if r.Host != "" {
		hostSuggestions[r.Host] = true
		parts := strings.Split(r.Host, ".")
		if len(parts) >= 2 {
			baseDomain := strings.Join(parts[len(parts)-2:], ".")
			hostSuggestions["."+baseDomain] = true
			hostSuggestions[baseDomain] = true
		}
	}



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
		GeoPolicy         security.GeoPolicyView
		GeoIP             security.GeoIPView
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
		CSPReports:        db.GetRecentCSPReports(50),
		GeoPolicy:         security.GetGeoPolicyView(),
		GeoIP:             security.GetGeoIPView(),
	}
	Tmpls.ExecuteTemplate(w, "admin.html", data)
}

func HandleProfile(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionKey)
	if err != nil {
		http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
		return
	}
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

	if !u.TotpActive {
		if totpEnc == "" {
			rawTotp := auth.GenerateTOTPSecret()
			totpEnc, _ = auth.Encrypt(rawTotp)
			db.DB.Exec("UPDATE users SET totp_secret = ? WHERE id = ?", totpEnc, u.ID)
			u.TotpSecret = rawTotp
		} else {
			u.TotpSecret, _ = auth.Decrypt(totpEnc)
		}
	}

	var newToken string
	errorMsg := false

	if r.Method == "POST" {
		if r.FormValue("csrf_token") != userSession.CSRFToken {
			http.Error(w, "Error de validación CSRF", http.StatusForbidden)
			return
		}
		// Rotar CSRF token tras uso exitoso para prevenir reuso
		userSession.CSRFToken = auth.GenerateSessionToken()
		db.DB.Exec("UPDATE sessions SET csrf_token = ? WHERE token = ?", userSession.CSRFToken, cookieHash)
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
					db.LogEvent(fmt.Sprintf("%s Nombre de usuario actualizado: %s", db.PrefixUSER, newUsername), u.Username)
				}
			}
			if newPassword != "" {
				if len(newPassword) < 12 {
					http.Error(w, "La contraseña debe tener al menos 12 caracteres", http.StatusBadRequest)
					return
				}
				newHash := auth.HashPassword(newPassword)
				db.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", newHash, u.ID)
				// Invalidar todas las demás sesiones y tokens del usuario (LOW-02 + MED-01)
				Mu.Lock()
				for token, sUser := range ActiveSessions {
					if sUser.ID == u.ID && token != cookieHash {
						delete(ActiveSessions, token)
					}
				}
				Mu.Unlock()
				db.DB.Exec("DELETE FROM sessions WHERE user_id = ? AND token != ?", u.ID, cookieHash)
				db.DB.Exec("DELETE FROM app_tokens WHERE user_id = ?", u.ID)
				db.LogEvent(fmt.Sprintf("%s Contraseña actualizada por el usuario: %s (sesiones y tokens invalidados)", db.PrefixUSER, u.Username), u.Username)
			}
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		} else if accion == "enable_2fa" {
			// Ventana ±1 + anti-replay (mejora A2): el UPDATE condicional
			// solo activa si el epoch es mayor que el último usado.
			if ok, epoch := auth.VerifyTOTP(u.TotpSecret, r.FormValue("code")); ok {
				res, execErr := db.DB.Exec(
					"UPDATE users SET totp_active = 1, totp_last_epoch = ? WHERE id = ? AND (totp_last_epoch IS NULL OR totp_last_epoch < ?)",
					epoch, u.ID, epoch)
				activado := false
				if execErr == nil {
					if n, _ := res.RowsAffected(); n > 0 {
						activado = true
					}
				}
				if activado {
					db.LogEvent(fmt.Sprintf("%s 2FA activado por el usuario: %s", db.PrefixUSER, u.Username), u.Username)
					http.Redirect(w, r, "/profile", http.StatusSeeOther)
					return
				}
				db.LogEvent(fmt.Sprintf("%s 2FA no activado (código TOTP reutilizado o error) para %s", db.PrefixBLOCK, u.Username), u.Username)
				errorMsg = true
			} else {
				errorMsg = true
			}
		} else if accion == "disable_2fa" {
			// Se limpia totp_last_epoch para que un nuevo enable en la misma
			// ventana no quede bloqueado por el anti-replay.
			db.DB.Exec("UPDATE users SET totp_active = 0, totp_last_epoch = NULL WHERE id = ?", u.ID)
			db.LogEvent(fmt.Sprintf("%s 2FA desactivado por el usuario: %s", db.PrefixUSER, u.Username), u.Username)
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
				db.LogEvent(fmt.Sprintf("%s App Token creado: %s para el usuario: %s", db.PrefixKEY, tokenName, u.Username), u.Username)
			}
		} else if accion == "revoke_token" {
			tokenID := r.FormValue("token_id")
			db.DB.Exec("DELETE FROM app_tokens WHERE id = ? AND user_id = ?", tokenID, u.ID)
			db.LogEvent(fmt.Sprintf("%s App Token revocado por el usuario: %s", db.PrefixKEY, u.Username), u.Username)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		} else if accion == "revoke_session" {
			tokenToRevoke := r.FormValue("token")
			Mu.Lock()
			delete(ActiveSessions, tokenToRevoke)
			Mu.Unlock()
			db.DB.Exec("DELETE FROM sessions WHERE token = ?", tokenToRevoke)
			db.LogEvent(fmt.Sprintf("%s Sesión de navegador revocada por el usuario: %s", db.PrefixBLOCK, u.Username), u.Username)
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
			db.LogEvent(fmt.Sprintf("%s Bypass key creada: %s para host %s", db.PrefixKEY, name, host), u.Username)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		} else if accion == "delete_bypass_key" && u.IsAdmin {
			token := r.FormValue("token")
			security.DeleteBypassKey(token)
			db.LogEvent(fmt.Sprintf("%s Bypass key eliminada: %s", db.PrefixKEY, token), u.Username)
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
		// Fix S5: anti CSRF en el wizard de instalación
		if !sameOriginPOST(r) {
			http.Error(w, "Origen no permitido", http.StatusForbidden)
			return
		}
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
				db.LogEvent(fmt.Sprintf("%s Instalación completada. Administrador original creado.", db.PrefixOK), "Sistema")
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
	client := http.Client{
		Timeout:   2 * time.Second,
		Transport: proxyTransport, // Protege contra SSRF y DNS Rebinding
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // No seguir redirecciones
		},
	}
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
	http.SetCookie(w, &http.Cookie{ // #nosec G124 — Secure depende de TLS, HttpOnly y SameSite Strict están fijados
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

func normalizeHost(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(h)
}

// IsKnownHost indica si el host es servible por reGIO: el dominio de admin o
// un servicio configurado. Se usa para no redirigir peticiones hacia Hosts
// desconocidos (anti open-redirect, fix deuda #3).
func IsKnownHost(host string) bool {
	h := normalizeHost(host)
	if h == AdminDomain {
		return true
	}
	Mu.Lock()
	defer Mu.Unlock()
	_, ok := Config.Servicios[h]
	return ok
}

// sameOriginPOST valida que un POST provenga del propio host usando Origin
// (o Referer como fallback). Fix S5: los formularios de login y setup no
// llevan token CSRF, por lo que este check cierra el login-CSRF. Sin ninguna
// de las dos cabeceras se permite (clientes nativos/curl no las envían).
func sameOriginPOST(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// ProxyHandler es la ruta de proxy por bypass token (X-REGIO-Bypass).
// Comparte implementación con la ruta inline de MainHandler vía serveProxy (R1).
// MainHandler la invoca pasando el statusWriter como writer, por lo que el
// log de cierre refleja el status real (antes registraba [200] en un 404).
func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	serveProxy(w, r, proxyOptions{})
}

// sanitizeCSPText neutraliza un campo de un reporte CSP antes de persistirlo
// (fix S1: XSS almacenado en el panel): solo ASCII imprimible, sin caracteres
// que rompen HTML/atributos/JS (< > " ' ` \) y con longitud acotada.
func sanitizeCSPText(s string, maxLen int) string {
	var b strings.Builder
	b.Grow(min(len(s), maxLen))
	for _, r := range s {
		if r < 0x20 || r > 0x7E {
			continue // controles y no-ASCII
		}
		switch r {
		case '<', '>', '"', '\'', '`', '\\':
			continue // rompen HTML / atributos / strings JS
		}
		if b.Len() >= maxLen {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// sanitizeCSPDirective restringe una directiva CSP a [a-z0-9 .-] (≤64).
func sanitizeCSPDirective(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == ' ' || r == '.' || r == '-' {
			if b.Len() >= 64 {
				break
			}
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func HandleCSPReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Validar Content-Type (solo application/json o application/csp-report)
	ct := r.Header.Get("Content-Type")
	if ct != "application/json" && ct != "application/csp-report" && ct != "" {
		http.Error(w, "Tipo de contenido no soportado", http.StatusUnsupportedMediaType)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10*1024)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("%s Error leyendo cuerpo de reporte CSP: %v", db.PrefixERR, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

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
			log.Printf("%s Error parseando reporte CSP: %v (Body: %s)", db.PrefixERR, err, db.SanitizeLog(string(body)))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	// Fix S1: sanitizar TODOS los campos antes de persistirlos. El panel los
	// renderiza (y antes lo hacía vía innerHTML): un blocked-uri con <img
	// onerror=...> era XSS almacenado desde un endpoint sin autenticación.
	report.BlockedURI = sanitizeCSPText(report.BlockedURI, 512)
	report.ViolatedDirective = sanitizeCSPDirective(report.ViolatedDirective)
	report.OriginalPolicy = sanitizeCSPText(report.OriginalPolicy, 1024)
	report.DocumentURI = sanitizeCSPText(report.DocumentURI, 1024)

	// Guardar reporte si hay URI bloqueada O si hay directiva violada (para inline/eval)
	if report.BlockedURI != "" || report.ViolatedDirective != "" {
		host := r.Host
		if report.DocumentURI != "" {
			if u, err := url.Parse(report.DocumentURI); err == nil {
				host = u.Host
			}
		}

		// Normalizar host (quitar puerto si existe) para coincidir con Config
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		blocked := report.BlockedURI
		if blocked == "" {
			blocked = "inline/eval/other"
		}

		db.SaveCSPReport(host, blocked, report.ViolatedDirective, report.OriginalPolicy)
		db.LogEvent(fmt.Sprintf("%s Bloqueo CSP en %s: %s (Directiva: %s)", db.PrefixWARN, host, blocked, report.ViolatedDirective), "Sistema")
		log.Printf("%s Reporte CSP guardado para %s: %s violó %s", db.PrefixOK, db.SanitizeLog(host), db.SanitizeLog(blocked), db.SanitizeLog(report.ViolatedDirective)) // #nosec G706 — entrada saneada con db.SanitizeLog
	}

	w.WriteHeader(http.StatusNoContent)
}

func MainHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s INCOMING: %s %s (Host: %s, Remote: %s)", db.PrefixIN, r.Method, db.SanitizeLog(r.URL.Path), db.SanitizeLog(r.Host), r.RemoteAddr) // #nosec G706 — entrada saneada con db.SanitizeLog

	if r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		return
	}

	sw := &statusWriter{ResponseWriter: w, status: 200}
	ip := getRealIP(r)

	// Limitar tamaño de cuerpo de request a 10MB para peticiones proxy (prevenir agotamiento de memoria)
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		r.Body = http.MaxBytesReader(sw, r.Body, 10*1024*1024)
	}

	// Sanitizar URI para logs (eliminar parámetros sensibles)
	logURI := sanitizeLogURI(r.URL)

	defer func() {
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			log.Printf("%s [%d] %s %s %s (Host: %s)", db.PrefixOUT, sw.status, r.Method, db.SanitizeLog(logURI), ip, db.SanitizeLog(r.Host)) // #nosec G706 — entrada saneada con db.SanitizeLog
		}
	}()

	setSecurityHeaders(sw.Header())

	Mu.Lock()
	customCSP := Config.CSPs[normalizeHost(r.Host)]
	Mu.Unlock()

	if normalizeHost(r.Host) == AdminDomain {
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

	// Añadir soporte para report-to moderno
	sw.Header().Set("Reporting-Endpoints", `main-endpoint="/api/csp-report"`)
	if !strings.Contains(sw.Header().Get("Content-Security-Policy"), "report-to") {
		sw.Header().Set("Content-Security-Policy", sw.Header().Get("Content-Security-Policy")+"; report-to main-endpoint")
	}

	if !strings.HasPrefix(r.URL.Path, "/static/") {
		log.Printf("%s [CSP DEBUG] Host: %s, CSP: %s", db.PrefixINFO, db.SanitizeLog(r.Host), sw.Header().Get("Content-Security-Policy")) // #nosec G706 — host saneado con db.SanitizeLog
	}

	if err := security.SecurityEngine(ip, r); err != nil {
		switch {
		case errors.Is(err, security.ErrGeoBlocked):
			sw.status = http.StatusForbidden
			http.Error(sw, "Acceso denegado desde tu región.", http.StatusForbidden)
		case errors.Is(err, security.ErrWAF):
			// Fix deuda #1: antes caía en el default y respondía 429
			// "Demasiadas peticiones" (código y mensaje falsos).
			sw.status = http.StatusForbidden
			http.Error(sw, "Solicitud bloqueada por las reglas de seguridad.", http.StatusForbidden)
		case strings.Contains(err.Error(), "IP bloqueada"):
			sw.status = http.StatusForbidden
			http.Error(sw, err.Error(), http.StatusForbidden)
		default:
			sw.status = http.StatusTooManyRequests
			http.Error(sw, "Demasiadas peticiones. Por favor, espera un minuto.", http.StatusTooManyRequests)
		}
		return
	}

	// Fix S2: los reportes CSP pasan por el SecurityEngine (rate limit, geo y
	// WAF). Antes se atendían antes de todo: endpoint sin autenticar, sin
	// limitar y con la tabla csp_reports sin purga (DoS de disco).
	if strings.HasPrefix(r.URL.Path, "/api/csp-report") {
		HandleCSPReport(sw, r)
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
	if err == nil && cookie != nil {
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

	if !validSession && normalizeHost(r.Host) != AdminDomain {
		// 2. Comprobar Bypass por API Key (Identidad)
		bypassToken := r.Header.Get("X-REGIO-Bypass")
		if bypassToken != "" {
			if ok, name := security.CheckBypass(bypassToken, normalizeHost(r.Host)); ok {
				db.LogEvent(fmt.Sprintf("%s Acceso Bypass: %s -> %s", db.PrefixKEY, name, r.Host), "API-Key")
				// Pasamos sw (statusWriter) para que el log de cierre refleje
				// el status real de la respuesta del proxy (fix deuda #6).
				ProxyHandler(sw, r)
				return
			}
		}

		// 3. Comprobar si es un dominio público
		Mu.Lock()
		bypass, okBypass := Config.BypassHeaders[normalizeHost(r.Host)]
		publico := Config.Publicos[normalizeHost(r.Host)]
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
			// Evitar el desafío Basic Auth en navegadores para peticiones AJAX/assets
			// sw.Header().Set("WWW-Authenticate", `Basic realm="reGIO protegido"`)
			sw.status = http.StatusUnauthorized
			http.Error(sw, "Sesión expirada o no autorizada. Refresque la página.", http.StatusUnauthorized)
			return
		}
		sw.status = http.StatusSeeOther
		http.Redirect(sw, r, "/REGIO-login", http.StatusSeeOther)
		return
	}

	if r.URL.Path == "/logout" {
		if r.Method != "POST" {
			http.Error(sw, "Método no permitido", http.StatusMethodNotAllowed)
			return
		}
		if r.FormValue("csrf_token") != user.CSRFToken {
			http.Error(sw, "Error de validación CSRF", http.StatusForbidden)
			return
		}
		cookie, err := r.Cookie(SessionKey)
		if err == nil {
			tokenHash := sessionHash(cookie.Value)
			Mu.Lock()
			delete(ActiveSessions, tokenHash)
			Mu.Unlock()
			// Fix S3: logout persistente. Sin este DELETE, la fila seguía en
			// la tabla sessions y LoadSessions revivía la sesión en el
			// próximo reinicio del proceso (sesión "cerrada" válida otra vez).
			db.DB.Exec("DELETE FROM sessions WHERE token = ?", tokenHash)
		}
		http.SetCookie(sw, &http.Cookie{ // #nosec G124 — Secure condicional a TLS/proxy (criterio de setSessionCookie); HttpOnly y SameSite Strict fijados
			Name:     SessionKey,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
			SameSite: http.SameSiteStrictMode,
		})
		sw.status = http.StatusSeeOther
		http.Redirect(sw, r, "/REGIO-login", http.StatusSeeOther)
		return
	}

	if normalizeHost(r.Host) == AdminDomain {
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

	// Ruta de proxy inline (auth de sesión/token) — comparte implementación con
	// ProxyHandler vía serveProxy: mismo 404, mismo saneo de credenciales.
	// `sw` como writer permite registrar el status real en el log de cierre.
	serveProxy(sw, r, proxyOptions{tokenUsed: tokenUsed})
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
