package handlers

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"regio/internal/auth"
	"regio/internal/db"
	"regio/internal/models"
)

//go:embed templates/*.html
var templateFiles embed.FS

//go:embed static/*
var staticFiles embed.FS

var (
	ActiveSessions  = make(map[string]*models.User)
	IntentosDB      = make(map[string]*models.Intento)
	IntentosUsuario = make(map[string]*models.Intento)
	BypassKeys      = make(map[string]models.BypassKey)
	Mu              sync.Mutex
	Config          models.Config
	NeedsSetup      bool
	AdminDomain     string
	SessionKey      = "REGIO_session"
	Tmpls           *template.Template
	TrustedProxies  []string
	AllowLoopback   bool // Solo para pruebas
	// Transport personalizado para el proxy con validación DNS anti-rebinding (MED-04)
	proxyTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: safeDialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
)

// safeDialContext resuelve DNS y valida que la IP no sea privada antes de conectar.
// Previene ataques SSRF por DNS rebinding (TOCTOU).
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("dirección inválida: %s", addr)
	}

	// Si ya es una IP, validarla directamente
	if ip := net.ParseIP(host); ip != nil {
		if !AllowLoopback && (isPrivateIP(ip) || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
			return nil, fmt.Errorf("proxy bloqueado: IP restringida %s", ip)
		}
		dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
		return dialer.DialContext(ctx, network, addr)
	}

	// Resolver DNS y validar todas las IPs resultantes
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolución DNS fallida para %s: %v", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("sin resultados DNS para %s", host)
	}

	for _, ip := range ips {
		if !AllowLoopback && (isPrivateIP(ip.IP) || ip.IP.IsLoopback() || ip.IP.IsLinkLocalUnicast() || ip.IP.IsLinkLocalMulticast()) {
			db.LogEvent(fmt.Sprintf("⚠ SSRF bloqueado: %s resuelve a IP restringida %s", host, ip.IP), "Sistema")
			return nil, fmt.Errorf("proxy bloqueado: %s resuelve a IP restringida %s", host, ip.IP)
		}
	}

	// Conectar usando la primera IP validada (evita re-resolución)
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

// sessionHash genera un hash SHA-256 del token de sesión para almacenamiento seguro.
func sessionHash(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func Init() {
	Tmpls = template.Must(template.ParseFS(templateFiles, "templates/*.html"))

	// Cargar proxies de confianza desde el entorno
	proxies := os.Getenv("TRUSTED_PROXIES")
	if proxies != "" {
		TrustedProxies = strings.Split(proxies, ",")
		for i := range TrustedProxies {
			TrustedProxies[i] = strings.TrimSpace(TrustedProxies[i])
		}
	}

	loadBypassKeys()
	InitSecurity()
	LoadSessions()
}

func loadBypassKeys() {
	rows, err := db.DB.Query("SELECT token, name, host FROM bypass_keys")
	if err != nil {
		return
	}
	defer rows.Close()

	Mu.Lock()
	defer Mu.Unlock()
	for rows.Next() {
		var k models.BypassKey
		if err := rows.Scan(&k.Token, &k.Name, &k.Host); err == nil {
			BypassKeys[k.Token] = k
		}
	}
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
	if strings.HasSuffix(r.URL.Path, ".css") {
		w.Header().Set("Content-Type", "text/css")
	}
	http.FileServer(http.FS(staticFiles)).ServeHTTP(w, r)
}

func HandleLogin(w http.ResponseWriter, r *http.Request, ip string) {
	if r.Method == "POST" {
		inputUser := r.FormValue("user")
		LogEvent(fmt.Sprintf("🔍 Intento de login para usuario: %s desde %s", inputUser, ip), "Sistema")

		// Verificar si la cuenta está bloqueada por fuerza bruta distribuida
		if IsUserBlocked(inputUser) {
			db.LogEvent(fmt.Sprintf("⊜ Intento de login en cuenta bloqueada: %s desde %s", inputUser, ip), "Sistema")
			http.Redirect(w, r, "/REGIO-login?error=locked", http.StatusSeeOther)
			return
		}

		var hash, totpEnc, inviteStored string
		var id int
		var isAdmin, totpActive bool
		err := db.DB.QueryRow("SELECT id, COALESCE(password_hash, ''), COALESCE(totp_secret, ''), COALESCE(invite_token, ''), is_admin, totp_active FROM users WHERE username = ?", inputUser).Scan(&id, &hash, &totpEnc, &inviteStored, &isAdmin, &totpActive)
		if err != nil {
			LogEvent(fmt.Sprintf("❌ Error buscando usuario %s en DB: %v", inputUser, err), "Sistema")
		}

		if err == nil && hash == "" {
			// El usuario no tiene contraseña, verificamos el token de invitación
			inviteGiven := r.URL.Query().Get("invite")
			if inviteGiven == "" || subtle.ConstantTimeCompare([]byte(inviteGiven), []byte(inviteStored)) != 1 {
				db.LogEvent(fmt.Sprintf("⚠ Intento de acceso a usuario sin contraseña sin token válido: %s", inputUser), ip)
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
					delete(IntentosDB, ip)
					Mu.Unlock()

					db.DB.Exec("INSERT INTO sessions (token, user_id, csrf_token, ip, user_agent, last_active) VALUES (?, ?, ?, ?, ?, ?)", tokenHash, id, csrf, ip, r.UserAgent(), time.Now())
					db.LogEvent(fmt.Sprintf("⚿ Contraseña inicial creada y sesión iniciada: %s", inputUser), inputUser)
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
			LogEvent(fmt.Sprintf("✅ Contraseña correcta para %s", inputUser), "Sistema")
			if !totpActive {
				loginValido = true
			} else {
				// Descifrar secreto para validar TOTP
				totpSecret, decErr := auth.Decrypt(totpEnc)
				if decErr == nil && input2fa == auth.GetTOTPCode(totpSecret) {
					loginValido = true
				} else {
					LogEvent(fmt.Sprintf("❌ Fallo TOTP para %s", inputUser), "Sistema")
				}
			}
		} else {
			LogEvent(fmt.Sprintf("❌ Contraseña incorrecta para %s", inputUser), "Sistema")
		}

		if loginValido {
			ResetearIntentosUsuario(inputUser)
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
			delete(IntentosDB, ip)
			Mu.Unlock()

			db.DB.Exec("INSERT INTO sessions (token, user_id, csrf_token, ip, user_agent, last_active) VALUES (?, ?, ?, ?, ?, ?)", tokenHash, id, csrf, ip, r.UserAgent(), time.Now())
			db.LogEvent(fmt.Sprintf("✓ Inicio de sesión exitoso: %s (%s)", inputUser, ip), inputUser)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		RegistrarFallo(ip)
		RegistrarFalloUsuario(inputUser)
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

	if r.Method == "POST" {
		if r.FormValue("csrf_token") != user.CSRFToken {
			http.Error(w, "Error de validación CSRF", http.StatusForbidden)
			return
		}
		accion := r.FormValue("accion")
		if accion == "add_service" {
			host := r.FormValue("host")
			target := r.FormValue("target")
			if host != "" && target != "" {
				if err := isValidTarget(target); err != nil {
					db.LogEvent(fmt.Sprintf("⚠ Intento de añadir target inválido/SSRF: %s -> %s (%v)", host, target, err), user.Username)
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

				Config.Servicios[host] = target
				Config.Publicos[host] = r.FormValue("public") == "on"
				Config.BypassHeaders[host] = r.FormValue("bypass")

				db.SaveConfig(Config)
				Mu.Unlock()
				db.LogEvent(fmt.Sprintf("⎈ Puente añadido: %s -> %s (Público: %v)", host, target, Config.Publicos[host]), user.Username)
			}
		} else if accion == "update_service" {
			host := r.FormValue("old_host")
			newHost := r.FormValue("host")
			target := r.FormValue("target")
			if host != "" && newHost != "" && target != "" {
				if err := isValidTarget(target); err != nil {
					db.LogEvent(fmt.Sprintf("⚠ Intento de actualizar target inválido/SSRF: %s -> %s (%v)", newHost, target, err), user.Username)
					http.Error(w, "Target inválido: "+err.Error(), http.StatusBadRequest)
					return
				}
				Mu.Lock()
				if Config.Servicios == nil {
					Config.Servicios = make(map[string]string)
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

				db.SaveConfig(Config)
				Mu.Unlock()
				db.LogEvent(fmt.Sprintf("⎈ Puente actualizado: %s -> %s", newHost, target), user.Username)
			}
		} else if accion == "delete_service" {
			host := r.FormValue("host")
			Mu.Lock()
			delete(Config.Servicios, host)
			delete(Config.Publicos, host)
			delete(Config.BypassHeaders, host)
			db.SaveConfig(Config)
			Mu.Unlock()
			db.LogEvent(fmt.Sprintf("⎈ Puente eliminado: %s", host), user.Username)
		} else if accion == "add_bypass_key" {
			token := r.FormValue("token")
			name := r.FormValue("name")
			host := r.FormValue("host")
			if token != "" && name != "" && host != "" {
				db.DB.Exec("INSERT INTO bypass_keys (token, name, host) VALUES (?, ?, ?)", token, name, host)
				loadBypassKeys()
				db.LogEvent(fmt.Sprintf("🔑 Bypass key creada: %s para host %s", name, host), user.Username)
			}
		} else if accion == "delete_bypass_key" {
			token := r.FormValue("token")
			db.DB.Exec("DELETE FROM bypass_keys WHERE token = ?", token)
			loadBypassKeys()
			db.LogEvent(fmt.Sprintf("🔑 Bypass key eliminada: %s", token), user.Username)
		} else if accion == "add_user" {
			newUser := r.FormValue("new_user")
			if newUser != "" {
				totp := auth.GenerateTOTPSecret()
				totpEnc, _ := auth.Encrypt(totp)
				inviteToken := auth.GenerateSessionToken() // Usamos la misma función para el token de invitación
				db.DB.Exec("INSERT INTO users (username, password_hash, totp_secret, invite_token, is_admin, totp_active) VALUES (?, '', ?, ?, 0, 0)", newUser, totpEnc, inviteToken)

				inviteURL := fmt.Sprintf("https://%s/REGIO-login?invite=%s", AdminDomain, inviteToken)
				db.LogEvent(fmt.Sprintf("⚇ Usuario creado: %s. URL de invitación: %s", newUser, inviteURL), user.Username)
			}
		} else if accion == "delete_user" {
			delUser := r.FormValue("del_user")
			var idToDelete int
			db.DB.QueryRow("SELECT id FROM users WHERE username = ?", delUser).Scan(&idToDelete)
			if idToDelete != 1 {
				db.DB.Exec("DELETE FROM users WHERE username = ?", delUser)
				db.LogEvent(fmt.Sprintf("⚇ Usuario eliminado: %s", delUser), user.Username)
			}
		} else if accion == "ban_ip" {
			targetIP := r.FormValue("target_ip")
			if targetIP != "" {
				hasta := time.Now().Add(365 * 24 * time.Hour)
				Mu.Lock()
				IntentosDB[targetIP] = &models.Intento{Fallos: 99, BloqueadoHasta: hasta}
				Mu.Unlock()
				db.DB.Exec("INSERT OR REPLACE INTO banned_ips (ip, hasta, razon) VALUES (?, ?, ?)", targetIP, hasta, "Bloqueo manual del administrador")
				db.LogEvent(fmt.Sprintf("⊘ IP/Rango bloqueado manualmente: %s", targetIP), user.Username)
			}
		} else if accion == "unban_ip" {
			targetIP := r.FormValue("target_ip")
			UnbanIP(targetIP)
			db.LogEvent(fmt.Sprintf("✓ IP/Rango desbloqueado: %s", targetIP), user.Username)
		} else if accion == "revoke_session" {
			tokenToRevoke := r.FormValue("token")
			Mu.Lock()
			delete(ActiveSessions, tokenToRevoke)
			Mu.Unlock()
			db.DB.Exec("DELETE FROM sessions WHERE token = ?", tokenToRevoke)
			db.LogEvent(fmt.Sprintf("⊘ Sesión revocada por el administrador: %s", user.Username), user.Username)
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

	var bypassList []models.BypassKey
	rowsB, _ := db.DB.Query("SELECT token, name, host FROM bypass_keys")
	defer rowsB.Close()
	for rowsB.Next() {
		var k models.BypassKey
		rowsB.Scan(&k.Token, &k.Name, &k.Host)
		bypassList = append(bypassList, k)
	}

	var bannedList []models.BannedIP
	Mu.Lock()
	for k, v := range IntentosDB {
		if time.Now().Before(v.BloqueadoHasta) {
			bannedList = append(bannedList, models.BannedIP{Target: k, Hasta: v.BloqueadoHasta.Format("02/01/2006 15:04:05")})
		}
	}
	Mu.Unlock()

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
		Token      string
		Username   string
		IP         string
		LastActive string
		IsCurrent  bool
	}
	var allSessions []GlobalSessionDisplay
	Mu.Lock()
	for token, sUser := range ActiveSessions {
		allSessions = append(allSessions, GlobalSessionDisplay{
			Token:      token,
			Username:   sUser.Username,
			IP:         sUser.RemoteIP,
			LastActive: RelTime(sUser.LastActive),
			IsCurrent:  token == cookieHash,
		})
	}
	Mu.Unlock()

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
					db.LogEvent(fmt.Sprintf("⚇ Nombre de usuario actualizado: %s", newUsername), u.Username)
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
				db.LogEvent(fmt.Sprintf("⚿ Contraseña actualizada por el usuario: %s (sesiones previas invalidadas)", u.Username), u.Username)
			}
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		} else if accion == "enable_2fa" {
			if r.FormValue("code") == auth.GetTOTPCode(u.TotpSecret) {
				db.DB.Exec("UPDATE users SET totp_active = 1 WHERE id = ?", u.ID)
				db.LogEvent(fmt.Sprintf("⚿ 2FA activado por el usuario: %s", u.Username), u.Username)
				http.Redirect(w, r, "/profile", http.StatusSeeOther)
				return
			} else {
				errorMsg = true
			}
		} else if accion == "disable_2fa" {
			db.DB.Exec("UPDATE users SET totp_active = 0 WHERE id = ?", u.ID)
			db.LogEvent(fmt.Sprintf("⊘ 2FA desactivado por el usuario: %s", u.Username), u.Username)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		} else if accion == "create_token" {
			tokenName := r.FormValue("token_name")
			if tokenName != "" {
				rawToken := auth.GenerateSessionToken()
				hash := sha256.Sum256([]byte(rawToken))
				tokenHash := base64.StdEncoding.EncodeToString(hash[:])
				_, err := db.DB.Exec("INSERT INTO app_tokens (user_id, name, token_hash) VALUES (?, ?, ?)", u.ID, tokenName, tokenHash)
				if err == nil {
					newToken = rawToken
					db.LogEvent(fmt.Sprintf("⚿ App Token creado: %s para el usuario: %s", tokenName, u.Username), u.Username)
				}
			}
		} else if accion == "revoke_token" {
			tokenID := r.FormValue("token_id")
			db.DB.Exec("DELETE FROM app_tokens WHERE id = ? AND user_id = ?", tokenID, u.ID)
			db.LogEvent(fmt.Sprintf("⊘ App Token revocado por el usuario: %s", u.Username), u.Username)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		} else if accion == "revoke_session" {
			tokenToRevoke := r.FormValue("token")
			Mu.Lock()
			delete(ActiveSessions, tokenToRevoke)
			Mu.Unlock()
			db.DB.Exec("DELETE FROM sessions WHERE token = ?", tokenToRevoke)
			db.LogEvent(fmt.Sprintf("⊘ Sesión de navegador revocada por el usuario: %s", u.Username), u.Username)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		}
	}

	var rawTokens []models.AppToken
	rows, _ := db.DB.Query("SELECT id, name, last_used, datetime(created_at, 'localtime') FROM app_tokens WHERE user_id = ?", u.ID)
	defer rows.Close()
	for rows.Next() {
		var t models.AppToken
		rows.Scan(&t.ID, &t.Name, &t.LastUsed, &t.CreatedAt)
		rawTokens = append(rawTokens, t)
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
	for _, t := range rawTokens {
		displayTokens = append(displayTokens, TokenDisplay{
			AppToken:    t,
			LastUsedRel: RelTime(t.LastUsed.Time),
		})
	}

	Tmpls.ExecuteTemplate(w, "profile.html", struct {
		User      models.User
		OtpUrl    string
		Error     bool
		Tokens    []TokenDisplay
		NewToken  string
		CSRFToken string
		Sessions  []SessionDisplay
	}{u, otpUrl, errorMsg, displayTokens, newToken, userSession.CSRFToken, sessions})
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
				db.LogEvent("✓ Instalación completada. Administrador original creado.", "Sistema")
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

func isValidTarget(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("URL inválida")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("solo se permite http o https")
	}
	if u.Host == "" {
		return fmt.Errorf("host no especificado")
	}

	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
	}

	// Bloquear loopback
	if !AllowLoopback && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
		return fmt.Errorf("no se permite apuntar a la interfaz de loopback")
	}

	// Bloquear TODAS las IPs privadas y restringidas
	ip := net.ParseIP(host)
	if ip != nil {
		if !AllowLoopback && (ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || isPrivateIP(ip)) {
			return fmt.Errorf("IP privada o restringida")
		}
	} else {
		// Intentar resolver el nombre para verificar si apunta a una IP privada
		ips, err := net.LookupIP(host)
		if err == nil {
			for _, resolvedIP := range ips {
				if !AllowLoopback && (resolvedIP.IsLoopback() || isPrivateIP(resolvedIP)) {
					return fmt.Errorf("el dominio resuelve a una IP restringida")
				}
			}
		}
	}
	return nil
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// RFC 1918 (IPv4)
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	// RFC 4193 (IPv6 Unique Local Address)
	return len(ip) == 16 && (ip[0] == 0xfc || ip[0] == 0xfd)
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
	r.URL.Host, r.URL.Scheme = remote.Host, remote.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Host = remote.Host
	proxy.ServeHTTP(w, r)
}

func MainHandler(w http.ResponseWriter, r *http.Request) {
	sw := &statusWriter{ResponseWriter: w, status: 200}
	ip := getRealIP(r)

	// Sanitizar URI para logs (eliminar parámetros sensibles)
	logURI := r.URL.Path
	if r.URL.RawQuery != "" {
		logURI += "?[redacted]"
	}

	defer func() {
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			log.Printf("📤 [%d] %s %s %s (Host: %s)", sw.status, r.Method, logURI, ip, r.Host)
		}
	}()

	sw.Header().Set("X-Content-Type-Options", "nosniff")
	sw.Header().Set("X-Frame-Options", "DENY")
	sw.Header().Set("X-XSS-Protection", "1; mode=block")
	sw.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	sw.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	sw.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	sw.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")

	if !CheckRateLimit(ip) {
		sw.status = http.StatusTooManyRequests
		http.Error(sw, "Demasiadas peticiones. Por favor, espera un minuto.", http.StatusTooManyRequests)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/static/") {
		ServeStatic(sw, r)
		return
	}
	blocked, _ := IsIPBlocked(ip)
	if blocked {
		sw.status = http.StatusForbidden
		http.Error(sw, "IP bloqueada temporalmente por seguridad.", http.StatusForbidden)
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
			Mu.Lock()
			key, exists := BypassKeys[bypassToken]
			Mu.Unlock()

			if exists && key.Host == r.Host {
				db.LogEvent(fmt.Sprintf("🔑 Acceso Bypass: %s -> %s", key.Name, r.Host), "API-Key")
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
	r.URL.Host, r.URL.Scheme = remote.Host, remote.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Host = remote.Host

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
