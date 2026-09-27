package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"regio/internal/auth"
	"regio/internal/db"
	"regio/internal/models"
	"regio/internal/security"
)

// postLogin envía el formulario de login.
func postLogin(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/REGIO-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "admin.test"
	rr := httptest.NewRecorder()
	HandleLogin(rr, req, "1.2.3.4")
	return rr
}

// seedLoginUser crea un usuario con contraseña conocida (+opciones) y
// limpia sus intentos fallidos al terminar el test.
func seedLoginUser(t *testing.T, username, password string, totpActive bool) {
	t.Helper()
	t.Cleanup(func() { security.ResetearIntentosUsuario(username) })
	if _, err := db.DB.Exec(
		"INSERT INTO users (id, username, password_hash, totp_secret, is_admin, totp_active) VALUES (1, ?, ?, 'secretocifrado', 1, ?)",
		username, auth.HashPassword(password), totpActive,
	); err != nil {
		t.Fatalf("insert login user: %v", err)
	}
}

// TestLoginContract congela el contrato de HandleLogin (11,6% en el baseline):
// credenciales, 2FA, flujo de invitación y bloqueo por fuerza bruta.
func TestLoginContract(t *testing.T) {
	if testing.Short() {
		t.Skip("modo -short: test de integración (backend/Argon2)")
	}
	const pass = "contrasena-correcta-123"

	t.Run("contraseña incorrecta -> 303 error=1 sin sesión", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedLoginUser(t, "carlos", pass, false)

		rr := postLogin(t, url.Values{"user": {"carlos"}, "pass": {"incorrecta"}})
		if rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "error=1") {
			t.Errorf("status=%d Location=%q; want 303 con error=1", rr.Code, rr.Header().Get("Location"))
		}
		Mu.Lock()
		n := len(ActiveSessions)
		Mu.Unlock()
		if n != 0 {
			t.Errorf("no debe crearse sesión, hay %d", n)
		}
	})

	t.Run("usuario inexistente -> 303 error=1", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		t.Cleanup(func() { security.ResetearIntentosUsuario("nadie") })

		rr := postLogin(t, url.Values{"user": {"nadie"}, "pass": {"lo-que-sea-12345"}})
		if rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "error=1") {
			t.Errorf("status=%d Location=%q; want 303 con error=1", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("contraseña correcta sin 2FA -> sesión + cookie segura + fila en DB", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedLoginUser(t, "ana", pass, false)

		rr := postLogin(t, url.Values{"user": {"ana"}, "pass": {pass}})
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d; want 303", rr.Code)
		}
		if loc := rr.Header().Get("Location"); loc != "/" {
			t.Errorf("Location = %q; want /", loc)
		}

		cookie := rr.Result().Cookies()
		var sess *http.Cookie
		for _, c := range cookie {
			if c.Name == SessionKey {
				sess = c
			}
		}
		if sess == nil {
			t.Fatal("no se emitió cookie de sesión")
		}
		if !sess.HttpOnly || sess.SameSite != http.SameSiteStrictMode || sess.Path != "/" || sess.MaxAge != 86400 {
			t.Errorf("atributos de cookie inesperados: httpOnly=%v sameSite=%v path=%q maxAge=%d",
				sess.HttpOnly, sess.SameSite, sess.Path, sess.MaxAge)
		}

		Mu.Lock()
		_, enMemoria := ActiveSessions[sessionHash(sess.Value)]
		Mu.Unlock()
		if !enMemoria {
			t.Error("la sesión no está en ActiveSessions")
		}
		if !rowExists(t, "SELECT COUNT(*) FROM sessions WHERE user_id=1") {
			t.Error("la sesión no se persistió en la tabla sessions")
		}
	})

	t.Run("2FA activo: código incorrecto -> error; correcto -> sesión", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedLoginUser(t, "laura", pass, true)

		rr := postLogin(t, url.Values{"user": {"laura"}, "pass": {pass}, "2fa": {"000000"}})
		if rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "error=1") {
			t.Errorf("2FA inválido: status=%d Location=%q; want 303 error=1", rr.Code, rr.Header().Get("Location"))
		}

		// El secreto de prueba está guardado en claro como 'secretocifrado'
		// (así lo insertó el fixture); el handler lo descifra con auth.Decrypt,
		// que fallará con material no cifrado -> login denegado. Para el camino
		// feliz usamos un secreto cifrado de verdad.
		db.DB.Exec("UPDATE users SET totp_secret = ? WHERE id = 1", mustEncrypt(t, "SECRETOVALIDO"))
		rr = postLogin(t, url.Values{"user": {"laura"}, "pass": {pass}, "2fa": {auth.GetTOTPCode("SECRETOVALIDO")}})
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("2FA válido: status = %d; want 303", rr.Code)
		}
		if loc := rr.Header().Get("Location"); loc != "/" {
			t.Errorf("Location = %q; want / (login completo)", loc)
		}
	})

	t.Run("2FA: deriva de -30s aceptada (ventana ±1)", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedLoginUser(t, "reloj-desaflado", pass, true)
		db.DB.Exec("UPDATE users SET totp_secret = ? WHERE id = 1", mustEncrypt(t, "SECRETOVENTANA"))

		codigoDeriva := auth.GetTOTPCodeAt("SECRETOVENTANA", time.Now().Unix()/30-1)
		rr := postLogin(t, url.Values{"user": {"reloj-desaflado"}, "pass": {pass}, "2fa": {codigoDeriva}})
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/" {
			t.Errorf("código con -30s: status=%d Location=%q; want 303 /", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("2FA: el mismo código no se puede reutilizar (anti-replay)", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedLoginUser(t, "carla-replay", pass, true)
		db.DB.Exec("UPDATE users SET totp_secret = ? WHERE id = 1", mustEncrypt(t, "SECRETOREPLAY"))
		codigo := auth.GetTOTPCode("SECRETOREPLAY")

		// Primer login con el código -> OK
		rr := postLogin(t, url.Values{"user": {"carla-replay"}, "pass": {pass}, "2fa": {codigo}})
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/" {
			t.Fatalf("primer login: status=%d Location=%q; want 303 /", rr.Code, rr.Header().Get("Location"))
		}

		// Segundo intento con el MISMO código -> rechazado (replay)
		rr = postLogin(t, url.Values{"user": {"carla-replay"}, "pass": {pass}, "2fa": {codigo}})
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/REGIO-login?error=1" {
			t.Errorf("replay: status=%d Location=%q; want 303 error=1", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("invitación: sin paso -> render setpassword; pass corta -> aviso; válida -> sesión", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		t.Cleanup(func() { security.ResetearIntentosUsuario("invitado") })
		// Usuario sin contraseña (invitación)
		if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, invite_token, is_admin) VALUES (1, 'invitado', '', 'invite-secreto', 0)"); err != nil {
			t.Fatalf("insert invitado: %v", err)
		}

		// Sin step: renderiza el formulario
		rr := postLogin(t, url.Values{"user": {"invitado"}, "invite_token": {"invite-secreto"}})
		if rr.Code != 200 {
			t.Errorf("sin step: status = %d; want 200", rr.Code)
		}

		// Pass corta
		rr = postLogin(t, url.Values{
			"user": {"invitado"}, "invite_token": {"invite-secreto"}, "step": {"set_password"},
			"new_pass": {"corta"}, "confirm_pass": {"corta"},
		})
		if rr.Code != 200 {
			t.Errorf("pass corta: status = %d; want 200", rr.Code)
		}

		// Pass válida
		nueva := "contrasena-establecida-999"
		rr = postLogin(t, url.Values{
			"user": {"invitado"}, "invite_token": {"invite-secreto"}, "step": {"set_password"},
			"new_pass": {nueva}, "confirm_pass": {nueva},
		})
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("pass válida: status = %d; want 303 (body: %s)", rr.Code, rr.Body.String())
		}
		var hash, invite string
		db.DB.QueryRow("SELECT COALESCE(password_hash,''), COALESCE(invite_token,'') FROM users WHERE id=1").Scan(&hash, &invite)
		if !auth.VerifyPassword(nueva, hash) {
			t.Error("la contraseña inicial no se guardó")
		}
		if invite != "" {
			t.Error("el invite_token debe borrarse tras usarlo")
		}
		Mu.Lock()
		n := len(ActiveSessions)
		Mu.Unlock()
		if n != 1 {
			t.Errorf("debe crearse exactamente 1 sesión, hay %d", n)
		}
	})

	t.Run("invitación inválida -> 303 error=invalid_invite", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		t.Cleanup(func() { security.ResetearIntentosUsuario("invitado") })
		db.DB.Exec("INSERT INTO users (id, username, password_hash, invite_token, is_admin) VALUES (1, 'invitado', '', 'invite-secreto', 0)")

		rr := postLogin(t, url.Values{"user": {"invitado"}, "invite_token": {"otro-token"}})
		if rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "error=invalid_invite") {
			t.Errorf("status=%d Location=%q; want 303 invalid_invite", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("cuenta bloqueada por fuerza bruta -> 303 error=locked", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		// Username propio de este test (nunca "victima": lo usa TestRateLimitPerUser)
		const bloqueado = "usuario-fuerza-bruta-test"
		t.Cleanup(func() { security.ResetearIntentosUsuario(bloqueado) })
		seedLoginUser(t, bloqueado, pass, false)
		for i := 0; i < 10; i++ {
			security.RegistrarFalloUsuario(bloqueado)
		}

		rr := postLogin(t, url.Values{"user": {bloqueado}, "pass": {pass}})
		if rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "error=locked") {
			t.Errorf("status=%d Location=%q; want 303 error=locked", rr.Code, rr.Header().Get("Location"))
		}
	})
}

// TestOriginCheckFixS5: login y setup rechazan POST de otro origen
// (login-CSRF) y permiten los del propio host o sin cabeceras.
func TestOriginCheckFixS5(t *testing.T) {
	t.Run("login con Origin externo -> 403", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedLoginUser(t, "ana-origin", "contrasena-origin-larga-123", false)

		form := url.Values{"user": {"ana-origin"}, "pass": {"contrasena-origin-larga-123"}}
		req := httptest.NewRequest("POST", "/REGIO-login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://evil.test")
		req.Host = "admin.test"
		rr := httptest.NewRecorder()
		HandleLogin(rr, req, "1.2.3.4")

		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d; want 403 (login CSRF)", rr.Code)
		}
		Mu.Lock()
		n := len(ActiveSessions)
		Mu.Unlock()
		if n != 0 {
			t.Error("no debe crearse sesión con Origin externo")
		}
	})

	t.Run("login con Origin propio -> permitido", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedLoginUser(t, "ana-origin2", "contrasena-origin-larga-123", false)

		form := url.Values{"user": {"ana-origin2"}, "pass": {"contrasena-origin-larga-123"}}
		req := httptest.NewRequest("POST", "/REGIO-login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://admin.test")
		req.Host = "admin.test"
		rr := httptest.NewRecorder()
		HandleLogin(rr, req, "1.2.3.4")

		if rr.Code != http.StatusSeeOther {
			t.Errorf("status = %d; want 303 (login propio)", rr.Code)
		}
	})

	t.Run("setup con Origin externo -> 403 y sin instalar", func(t *testing.T) {
		isolateState(t)
		Mu.Lock()
		NeedsSetup = true
		Mu.Unlock()

		form := url.Values{"user": {"admin"}, "pass": {"contrasena-setup-larga-123"}}
		req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://evil.test")
		req.Host = "admin.test"
		rr := httptest.NewRecorder()
		HandleSetup(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d; want 403 (setup CSRF)", rr.Code)
		}
		if !db.CheckNeedsSetup() {
			t.Error("el setup no debe completarse con Origin externo")
		}
	})
}

// TestSessionLifecycleContract congela LoadSessions / UpdateSessionActivity /
// CleanupSessions (0%, 0% y 0% en el baseline).
func TestSessionLifecycleContract(t *testing.T) {
	t.Run("LoadSessions reconstruye desde DB y rellena CSRF faltante", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		db.DB.Exec("INSERT INTO users (id, username, is_admin) VALUES (1, 'persistido', 1)")

		rawToken := "raw-de-db-1234567890"
		tokenHash := sessionHash(rawToken)
		// Sesión persistida SIN csrf (caso de migración)
		db.DB.Exec("INSERT INTO sessions (token, user_id, csrf_token, ip, last_active) VALUES (?, 1, '', '9.9.9.9', ?)",
			tokenHash, time.Now().Add(-time.Hour))

		LoadSessions()

		Mu.Lock()
		s := ActiveSessions[tokenHash]
		Mu.Unlock()
		if s == nil {
			t.Fatal("LoadSessions no cargó la sesión")
		}
		if s.Username != "persistido" || s.RemoteIP != "9.9.9.9" || !s.IsAdmin {
			t.Errorf("datos de sesión incorrectos: %+v", s)
		}
		if s.CSRFToken == "" {
			t.Error("LoadSessions debe generar CSRF cuando falta")
		}
		var csrfDB string
		db.DB.QueryRow("SELECT csrf_token FROM sessions WHERE token=?", tokenHash).Scan(&csrfDB)
		if csrfDB == "" || csrfDB != s.CSRFToken {
			t.Error("el CSRF generado debe persistirse en sessions")
		}
	})

	t.Run("UpdateSessionActivity actualiza memoria y DB", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)

		tokenHash := sessionHash("raw-actividad")
		vieja := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		db.DB.Exec("INSERT INTO users (id, username) VALUES (1, 'u')")
		db.DB.Exec("INSERT INTO sessions (token, user_id, last_active) VALUES (?, 1, ?)", tokenHash, vieja)

		Mu.Lock()
		ActiveSessions[tokenHash] = &models.User{ID: 1, Username: "u", LastActive: vieja}
		Mu.Unlock()

		UpdateSessionActivity(tokenHash)

		Mu.Lock()
		ahora := ActiveSessions[tokenHash].LastActive
		Mu.Unlock()
		if !ahora.After(vieja) {
			t.Errorf("LastActive en memoria no avanzó: %v", ahora)
		}
		var dbTime time.Time
		db.DB.QueryRow("SELECT last_active FROM sessions WHERE token=?", tokenHash).Scan(&dbTime)
		if !dbTime.After(vieja.Add(time.Minute)) {
			t.Errorf("last_active en DB no avanzó: %v", dbTime)
		}
	})

	t.Run("CleanupSessions elimina sesiones de más de 7 días", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		Mu.Lock()
		ActiveSessions["vieja-7d"] = &models.User{ID: 1, LastActive: time.Now().Add(-8 * 24 * time.Hour)}
		ActiveSessions["reciente"] = &models.User{ID: 1, LastActive: time.Now()}
		Mu.Unlock()

		CleanupSessions()

		Mu.Lock()
		_, vieja := ActiveSessions["vieja-7d"]
		_, fresca := ActiveSessions["reciente"]
		Mu.Unlock()
		if vieja {
			t.Error("la sesión vieja debió limpiarse")
		}
		if !fresca {
			t.Error("la sesión reciente no debe limpiarse")
		}
	})
}

// mustEncrypt cifra un valor con la clave maestra del test.
func mustEncrypt(t *testing.T, plain string) string {
	t.Helper()
	enc, err := auth.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return enc
}

// TestLogoutEsPersistenteFixS3: tras logout, la sesión NO debe revivir con
// LoadSessions (simulación de reinicio). Sin el DELETE en DB, la fila quedaba
// en `sessions` y el próximo arranque la recargaba.
func TestLogoutEsPersistenteFixS3(t *testing.T) {
	const passLogout = "contrasena-logout-larga-123"
	isolateState(t)
	cleanUsers(t)
	seedLoginUser(t, "se-desconecta", passLogout, false)

	// 1) Login: crea cookie + fila en sessions
	rr := postLogin(t, url.Values{"user": {"se-desconecta"}, "pass": {passLogout}})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("login: status = %d; want 303", rr.Code)
	}
	var cookieValor string
	for _, c := range rr.Result().Cookies() {
		if c.Name == SessionKey {
			cookieValor = c.Value
		}
	}
	if cookieValor == "" {
		t.Fatal("login sin cookie")
	}
	hash := sessionHash(cookieValor)
	if !rowExists(t, "SELECT COUNT(*) FROM sessions WHERE token=?", hash) {
		t.Fatal("el login no persistió la sesión en DB")
	}

	// 2) Logout con el CSRF vigente de la sesión
	Mu.Lock()
	csrf := ActiveSessions[hash].CSRFToken
	Mu.Unlock()
	req := httptest.NewRequest("POST", "/logout", strings.NewReader(url.Values{"csrf_token": {csrf}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "admin.test"
	req.AddCookie(&http.Cookie{Name: SessionKey, Value: cookieValor})
	logoutRR := httptest.NewRecorder()
	MainHandler(logoutRR, req)
	if logoutRR.Code != http.StatusSeeOther {
		t.Fatalf("logout: status = %d; want 303 (body: %s)", logoutRR.Code, logoutRR.Body.String())
	}

	// 3) Fuera de memoria Y de DB
	Mu.Lock()
	_, enMemoria := ActiveSessions[hash]
	Mu.Unlock()
	if enMemoria {
		t.Error("la sesión sigue en memoria tras logout")
	}
	if rowExists(t, "SELECT COUNT(*) FROM sessions WHERE token=?", hash) {
		t.Error("la fila de sessions NO se borró (fix S3)")
	}

	// 4) Simulación de reinicio: LoadSessions no debe revivirla
	LoadSessions()
	Mu.Lock()
	_, revivida := ActiveSessions[hash]
	Mu.Unlock()
	if revivida {
		t.Error("LoadSessions revivió la sesión cerrada")
	}
}
