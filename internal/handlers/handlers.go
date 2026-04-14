package handlers

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
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
	ActiveSessions = make(map[string]*models.User)
	IntentosDB     = make(map[string]*models.Intento)
	Mu             sync.Mutex
	Config         models.Config
	NeedsSetup     bool
	AdminDomain    string
	SessionKey     = "REGIO_session"
	Tmpls          *template.Template
)

func Init() {
	Tmpls = template.Must(template.ParseFS(templateFiles, "templates/*.html"))
	InitSecurity()
	LoadSessions()
}

func LoadSessions() {
	Mu.Lock()
	defer Mu.Unlock()
	rows, err := db.DB.Query("SELECT s.token, s.user_id, u.username, u.is_admin, u.totp_active, s.ip, s.last_active FROM sessions s JOIN users u ON s.user_id = u.id")
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var token, username, ip string
		var userID int
		var isAdmin, totpActive bool
		var lastActive time.Time
		rows.Scan(&token, &userID, &username, &isAdmin, &totpActive, &ip, &lastActive)
		ActiveSessions[token] = &models.User{
			ID:         userID,
			Username:   username,
			IsAdmin:    isAdmin,
			TotpActive: totpActive,
			CSRFToken:  auth.GenerateSessionToken(), // Nuevo CSRF por reinicio para seguridad
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

		var hash, totp string
		var id int
		var isAdmin, totpActive bool
		err := db.DB.QueryRow("SELECT id, password_hash, totp_secret, is_admin, totp_active FROM users WHERE username = ?", inputUser).Scan(&id, &hash, &totp, &isAdmin, &totpActive)

		if err == nil && hash == "" {
			step := r.FormValue("step")
			if step == "set_password" {
				newPass := r.FormValue("new_pass")
				confirmPass := r.FormValue("confirm_pass")
				if newPass != "" && newPass == confirmPass {
					newHash := auth.HashPassword(newPass)
					db.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", newHash, id)

					token := auth.GenerateSessionToken()
					http.SetCookie(w, &http.Cookie{Name: SessionKey, Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 3600 * 24})

					Mu.Lock()
					ActiveSessions[token] = &models.User{
						ID:         id,
						Username:   inputUser,
						IsAdmin:    isAdmin,
						TotpActive: totpActive,
						CSRFToken:  auth.GenerateSessionToken(),
						LastActive: time.Now(),
						RemoteIP:   ip,
					}
					delete(IntentosDB, ip)
					Mu.Unlock()

					db.DB.Exec("INSERT INTO sessions (token, user_id, ip, user_agent, last_active) VALUES (?, ?, ?, ?, ?)", token, id, ip, r.UserAgent(), time.Now())
					db.LogEvent(fmt.Sprintf("⚿ Contraseña inicial creada y sesión iniciada: %s", inputUser), inputUser)
					http.Redirect(w, r, "/", http.StatusSeeOther)
					return
				}
				// Redirigir de nuevo a setpassword con error si no coinciden
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
			if !totpActive || input2fa == auth.GetTOTPCode(totp) {
				loginValido = true
			}
		}

		if loginValido {
			token := auth.GenerateSessionToken()
			http.SetCookie(w, &http.Cookie{Name: SessionKey, Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 3600 * 24})

			Mu.Lock()
			ActiveSessions[token] = &models.User{
				ID:         id,
				Username:   inputUser,
				IsAdmin:    isAdmin,
				TotpActive: totpActive,
				CSRFToken:  auth.GenerateSessionToken(),
				LastActive: time.Now(),
				RemoteIP:   ip,
			}
			delete(IntentosDB, ip)
			Mu.Unlock()

			db.DB.Exec("INSERT INTO sessions (token, user_id, ip, user_agent, last_active) VALUES (?, ?, ?, ?, ?)", token, id, ip, r.UserAgent(), time.Now())
			db.LogEvent(fmt.Sprintf("✓ Inicio de sesión exitoso: %s (%s)", inputUser, ip), inputUser)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		RegistrarFallo(ip)
		http.Redirect(w, r, "/REGIO-login?error=1", http.StatusSeeOther)
		return
	}
	Tmpls.ExecuteTemplate(w, "login.html", r.URL.Query().Get("error") != "")
}

func HandleAdmin(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(SessionKey)
	Mu.Lock()
	user, ok := ActiveSessions[cookie.Value]
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
				Config.Servicios[host] = target
				db.SaveConfig(Config)
				Mu.Unlock()
				db.LogEvent(fmt.Sprintf("⎈ Puente añadido: %s -> %s", host, target), user.Username)
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
				delete(Config.Servicios, host)
				Config.Servicios[newHost] = target
				db.SaveConfig(Config)
				Mu.Unlock()
				db.LogEvent(fmt.Sprintf("⎈ Puente actualizado: %s -> %s", newHost, target), user.Username)
			}
		} else if accion == "delete_service" {
			host := r.FormValue("host")
			Mu.Lock()
			delete(Config.Servicios, host)
			db.SaveConfig(Config)
			Mu.Unlock()
			db.LogEvent(fmt.Sprintf("⎈ Puente eliminado: %s", host), user.Username)
		} else if accion == "add_user" {
			newUser := r.FormValue("new_user")
			if newUser != "" {
				totp := auth.GenerateTOTPSecret()
				db.DB.Exec("INSERT INTO users (username, password_hash, totp_secret, is_admin, totp_active) VALUES (?, '', ?, 0, 0)", newUser, totp)
				db.LogEvent(fmt.Sprintf("⚇ Usuario creado (Pendiente contraseña): %s", newUser), user.Username)
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
		} else if accion == "clear_events" {
			db.ClearEvents()
			db.LogEvent(fmt.Sprintf("⚠ Registro de eventos vaciado por: %s", user.Username), user.Username)
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
	rows, _ := db.DB.Query("SELECT id, username, totp_secret, is_admin, totp_active FROM users")
	defer rows.Close()
	for rows.Next() {
		var u models.User
		rows.Scan(&u.ID, &u.Username, &u.TotpSecret, &u.IsAdmin, &u.TotpActive)
		users = append(users, u)
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

	// 5. Generar sugerencias inteligentes basadas en lo configurado
	hostSuggestions := make(map[string]bool)
	targetSuggestions := make(map[string]bool)

	Mu.Lock()
	for host, target := range Config.Servicios {
		hostSuggestions[host] = true
		targetSuggestions[target] = true

		// Sugerir el dominio base (ej: si hay app.vercel.com, sugerir .vercel.com)
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			baseDomain := strings.Join(parts[len(parts)-2:], ".")
			hostSuggestions["."+baseDomain] = true
		}

		// Sugerir la base del target (ej: http://192.168.1.50:80 -> http://192.168.1.)
		if strings.HasPrefix(target, "http") {
			urlParts := strings.Split(target, "/")
			if len(urlParts) >= 3 {
				domainPart := urlParts[2] // el host:port
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

	// 6. Health Check concurrente
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

	// Ordenar resultados para que la tabla sea estable
	sort.Slice(healthResults, func(i, j int) bool {
		return healthResults[i].Host < healthResults[j].Host
	})

	// 7. Sesiones Globales
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
			IsCurrent:  token == cookie.Value,
		})
	}
	Mu.Unlock()

	data := struct {
		Config            models.Config
		Users             []models.User
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
	Mu.Lock()
	userSession, ok := ActiveSessions[cookie.Value]
	Mu.Unlock()
	if !ok {
		http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
		return
	}

	var u models.User
	db.DB.QueryRow("SELECT id, username, totp_secret, totp_active, is_admin FROM users WHERE id = ?", userSession.ID).Scan(&u.ID, &u.Username, &u.TotpSecret, &u.TotpActive, &u.IsAdmin)

	if u.TotpSecret == "" {
		u.TotpSecret = auth.GenerateTOTPSecret()
		db.DB.Exec("UPDATE users SET totp_secret = ? WHERE id = ?", u.TotpSecret, u.ID)
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
				newHash := auth.HashPassword(newPassword)
				db.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", newHash, u.ID)
				db.LogEvent(fmt.Sprintf("⚿ Contraseña actualizada por el usuario: %s", u.Username), u.Username)
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

	otpUrl := fmt.Sprintf("otpauth://totp/reGiO:%%20%s?secret=%s&issuer=reGiO", u.Username, u.TotpSecret)

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
				IsCurrent:  token == cookie.Value,
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
	if r.Method == "POST" {
		user := r.FormValue("user")
		pass := r.FormValue("pass")
		if user != "" && pass != "" {
			hash := auth.HashPassword(pass)
			secret := auth.GenerateTOTPSecret()
			_, err := db.DB.Exec("INSERT INTO users (username, password_hash, totp_secret, is_admin, totp_active) VALUES (?, ?, ?, 1, 0)", user, hash, secret)
			if err == nil {
				db.LogEvent("✓ Instalación completada. Administrador original creado.", "Sistema")
				Mu.Lock()
				NeedsSetup = false
				Mu.Unlock()
				http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
				return
			}
		}
	}
	Tmpls.ExecuteTemplate(w, "setup.html", nil)
}

// Auxiliares
func checkServiceHealth(target string) bool {
	client := http.Client{
		Timeout: 2 * time.Second,
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

	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return fmt.Errorf("no se permite apuntar a la interfaz de loopback")
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("IP privada o restringida")
		}
	}

	return nil
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

func CleanupSessions() {
	Mu.Lock()
	defer Mu.Unlock()
	ahora := time.Now()
	limite := ahora.Add(-7 * 24 * time.Hour)

	for token, user := range ActiveSessions {
		if user.LastActive.Before(limite) {
			delete(ActiveSessions, token)
		}
	}
	db.DB.Exec("DELETE FROM sessions WHERE last_active < ?", limite)
}
