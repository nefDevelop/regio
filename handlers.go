package main

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"time"
)

//go:embed templates/*.html
var templateFiles embed.FS

var tmpls = template.Must(template.ParseFS(templateFiles, "templates/*.html"))

func handleLogin(w http.ResponseWriter, r *http.Request, ip string) {
	if r.Method == "POST" {
		inputUser := r.FormValue("user")

		var hash, totp string
		var id int
		var isAdmin, totpActive bool
		err := db.QueryRow("SELECT id, password_hash, totp_secret, is_admin, totp_active FROM users WHERE username = ?", inputUser).Scan(&id, &hash, &totp, &isAdmin, &totpActive)

		// Si el usuario existe y aún no tiene contraseña
		if err == nil && hash == "" {
			step := r.FormValue("step")
			if step == "set_password" {
				newPass := r.FormValue("new_pass")
				if newPass != "" {
					newHash := hashPassword(newPass)
					db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", newHash, id)

					token := generateSessionToken()
					http.SetCookie(w, &http.Cookie{Name: sessionKey, Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 3600 * 24})

					mu.Lock()
					activeSessions[token] = &User{ID: id, Username: inputUser, IsAdmin: isAdmin, TotpActive: totpActive, CSRFToken: generateSessionToken()}
					delete(intentosDB, ip)
					subnet := getSubnet(ip)
					if subnet != "" {
						delete(intentosDB, subnet)
					}
					mu.Unlock()

					logEvent(fmt.Sprintf("⚿ Contraseña inicial creada y sesión iniciada: %s", inputUser))
					http.Redirect(w, r, "/", http.StatusSeeOther)
					return
				}
			}
			// Mostrar pantalla para crear la contraseña
			tmpls.ExecuteTemplate(w, "setpassword.html", inputUser)
			return
		}

		inputPass := r.FormValue("pass")
		input2fa := r.FormValue("2fa")

		loginValido := false
		if err == nil && verifyPassword(inputPass, hash) {
			// Si el 2FA está activo, validamos el código. Si no, le dejamos pasar.
			if !totpActive || input2fa == getTOTPCode(totp) {
				loginValido = true
			}
		}

		if loginValido {
			token := generateSessionToken()
			http.SetCookie(w, &http.Cookie{Name: sessionKey, Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 3600 * 24})

			mu.Lock()
			activeSessions[token] = &User{ID: id, Username: inputUser, IsAdmin: isAdmin, TotpActive: totpActive, CSRFToken: generateSessionToken()}
			delete(intentosDB, ip)
			subnet := getSubnet(ip)
			if subnet != "" {
				delete(intentosDB, subnet)
			}
			mu.Unlock()

			logEvent(fmt.Sprintf("✓ Inicio de sesión exitoso: %s (%s)", inputUser, ip))
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Login Fallido: Aumentar contador
		subnet := getSubnet(ip)
		mu.Lock()
		if _, ok := intentosDB[ip]; !ok {
			intentosDB[ip] = &Intento{fallos: 1}
		} else {
			intentosDB[ip].fallos++
			if intentosDB[ip].fallos >= 5 {
				intentosDB[ip].bloqueadoHasta = time.Now().Add(15 * time.Minute)
				logEvent(fmt.Sprintf("⊘ IP BLOQUEADA (Fuerza bruta): %s", ip))
			}
		}
		// Contador por subred
		if subnet != "" {
			if _, ok := intentosDB[subnet]; !ok {
				intentosDB[subnet] = &Intento{fallos: 1}
			} else {
				intentosDB[subnet].fallos++
				if intentosDB[subnet].fallos >= 15 {
					intentosDB[subnet].bloqueadoHasta = time.Now().Add(1 * time.Hour)
					logEvent(fmt.Sprintf("⊘ RANGO BLOQUEADO (Ataque múltiple): %s", subnet))
				}
			}
		}
		mu.Unlock()
		http.Redirect(w, r, "/REGIO-login?error=1", http.StatusSeeOther)
		return
	}

	tmpls.ExecuteTemplate(w, "login.html", r.URL.Query().Get("error") != "")
}

type BannedIP struct {
	Target string
	Hasta  string
}

type Event struct {
	Timestamp string
	Message   string
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(sessionKey)
	mu.Lock()
	user, ok := activeSessions[cookie.Value]
	mu.Unlock()
	if !ok {
		http.Error(w, "Sesión inválida", http.StatusUnauthorized)
		return
	}

	if r.Method == "POST" {
		// Validar token CSRF
		if r.FormValue("csrf_token") != user.CSRFToken {
			http.Error(w, "Error de validación CSRF: Petición inválida.", http.StatusForbidden)
			return
		}
		accion := r.FormValue("accion")

		// Acciones de Puentes (Servicios)
		if accion == "add_service" {
			host := r.FormValue("host")
			target := r.FormValue("target")
			if host != "" && target != "" {
				mu.Lock()
				config.Servicios[host] = target
				saveConfig()
				mu.Unlock()
				logEvent(fmt.Sprintf("⎈ Puente añadido: %s -> %s", host, target))
			}
		} else if accion == "delete_service" {
			host := r.FormValue("host")
			mu.Lock()
			delete(config.Servicios, host)
			saveConfig()
			mu.Unlock()
			logEvent(fmt.Sprintf("⎈ Puente eliminado: %s", host))
		} else if accion == "add_user" {
			// Acciones de Usuarios
			newUser := r.FormValue("new_user")
			newPass := r.FormValue("new_pass")
			if newUser != "" {
				hash := ""
				if newPass != "" {
					hash = hashPassword(newPass)
				}
				totp := generateTOTPSecret()
				db.Exec("INSERT INTO users (username, password_hash, totp_secret, is_admin, totp_active) VALUES (?, ?, ?, 0, 0)", newUser, hash, totp)
				logEvent(fmt.Sprintf("⚇ Usuario creado: %s", newUser))
			}
		} else if accion == "delete_user" {
			delUser := r.FormValue("del_user")

			// El usuario creador original (ID 1) está completamente protegido y no se puede borrar
			var idToDelete int
			db.QueryRow("SELECT id FROM users WHERE username = ?", delUser).Scan(&idToDelete)
			if idToDelete != 1 {
				db.Exec("DELETE FROM users WHERE username = ?", delUser)
				logEvent(fmt.Sprintf("⚇ Usuario eliminado: %s", delUser))
			}
		} else if accion == "ban_ip" {
			targetIP := r.FormValue("target_ip")
			if targetIP != "" {
				mu.Lock()
				intentosDB[targetIP] = &Intento{fallos: 99, bloqueadoHasta: time.Now().Add(365 * 24 * time.Hour)} // Ban de 1 año
				mu.Unlock()
				logEvent(fmt.Sprintf("⊘ IP/Rango bloqueado manualmente: %s", targetIP))
			}
		} else if accion == "unban_ip" {
			targetIP := r.FormValue("target_ip")
			mu.Lock()
			delete(intentosDB, targetIP)
			mu.Unlock()
			logEvent(fmt.Sprintf("✓ IP/Rango desbloqueado: %s", targetIP))
		}

		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	var users []User
	rows, _ := db.Query("SELECT id, username, totp_secret, is_admin, totp_active FROM users")
	defer rows.Close()
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.TotpSecret, &u.IsAdmin, &u.TotpActive)
		users = append(users, u)
	}

	var bannedList []BannedIP
	mu.Lock()
	for k, v := range intentosDB {
		if time.Now().Before(v.bloqueadoHasta) {
			bannedList = append(bannedList, BannedIP{Target: k, Hasta: v.bloqueadoHasta.Format("02/01/2006 15:04:05")})
		}
	}
	mu.Unlock()

	var events []Event
	rowsEvents, _ := db.Query("SELECT datetime(timestamp, 'localtime'), message FROM events ORDER BY id DESC LIMIT 50")
	defer rowsEvents.Close()
	for rowsEvents.Next() {
		var e Event
		rowsEvents.Scan(&e.Timestamp, &e.Message)
		events = append(events, e)
	}

	data := struct {
		Config    Config
		Users     []User
		CSRFToken string
		BannedIPs []BannedIP
		Events    []Event
	}{
		Config:    config,
		Users:     users,
		CSRFToken: user.CSRFToken,
		BannedIPs: bannedList,
		Events:    events,
	}

	tmpls.ExecuteTemplate(w, "admin.html", data)
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(sessionKey)
	mu.Lock()
	userSession, ok := activeSessions[cookie.Value]
	mu.Unlock()
	if !ok {
		http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
		return
	}

	var u User
	db.QueryRow("SELECT id, username, totp_secret, totp_active, is_admin FROM users WHERE id = ?", userSession.ID).Scan(&u.ID, &u.Username, &u.TotpSecret, &u.TotpActive, &u.IsAdmin)

	if u.TotpSecret == "" {
		u.TotpSecret = generateTOTPSecret()
		db.Exec("UPDATE users SET totp_secret = ? WHERE id = ?", u.TotpSecret, u.ID)
	}

	errorMsg := false
	if r.Method == "POST" {
		accion := r.FormValue("accion")
		if accion == "update_profile" {
			newUsername := r.FormValue("new_username")
			newPassword := r.FormValue("new_password")

			if newUsername != "" && newUsername != u.Username {
				_, err := db.Exec("UPDATE users SET username = ? WHERE id = ?", newUsername, u.ID)
				if err == nil {
					u.Username = newUsername
					mu.Lock()
					userSession.Username = newUsername
					mu.Unlock()
					logEvent(fmt.Sprintf("⚇ Nombre de usuario actualizado: %s", newUsername))
				}
			}
			if newPassword != "" {
				newHash := hashPassword(newPassword)
				db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", newHash, u.ID)
				logEvent(fmt.Sprintf("⚿ Contraseña actualizada por el usuario: %s", u.Username))
			}
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		} else if accion == "enable_2fa" {
			if r.FormValue("code") == getTOTPCode(u.TotpSecret) {
				db.Exec("UPDATE users SET totp_active = 1 WHERE id = ?", u.ID)
				logEvent(fmt.Sprintf("⚿ 2FA activado por el usuario: %s", u.Username))
				http.Redirect(w, r, "/profile", http.StatusSeeOther)
				return
			} else {
				errorMsg = true
			}
		} else if accion == "disable_2fa" {
			db.Exec("UPDATE users SET totp_active = 0 WHERE id = ?", u.ID)
			logEvent(fmt.Sprintf("⊘ 2FA desactivado por el usuario: %s", u.Username))
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		}
	}

	otpUrl := fmt.Sprintf("otpauth://totp/reGiO:%%20%s?secret=%s&issuer=reGiO", u.Username, u.TotpSecret)
	tmpls.ExecuteTemplate(w, "profile.html", struct {
		User   User
		OtpUrl string
		Error  bool
	}{u, otpUrl, errorMsg})
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		user := r.FormValue("user")
		pass := r.FormValue("pass")

		if user != "" && pass != "" {
			hash := hashPassword(pass)
			secret := generateTOTPSecret()
			_, err := db.Exec("INSERT INTO users (username, password_hash, totp_secret, is_admin, totp_active) VALUES (?, ?, ?, 1, 0)", user, hash, secret)
			if err == nil {
				logEvent("✓ Instalación completada. Administrador original creado.")
				mu.Lock()
				needsSetup = false
				mu.Unlock()
				http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
				return
			}
		}
	}

	tmpls.ExecuteTemplate(w, "setup.html", nil)
}
