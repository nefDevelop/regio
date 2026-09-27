package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"regio/internal/auth"
	"regio/internal/db"
)

const (
	profileRaw  = "profile-raw-session"
	profilePass = "contrasena-larga-de-prueba-123"
)

// seedProfileUser crea el usuario id=1 con contraseña y secreto TOTP
// conocidos, más su sesión activa para /profile.
func seedProfileUser(t *testing.T) (secret string) {
	t.Helper()
	cleanUsers(t)

	secret = auth.GenerateTOTPSecret()
	enc, err := auth.Encrypt(secret)
	if err != nil {
		t.Fatalf("encrypt totp: %v", err)
	}
	hash := auth.HashPassword(profilePass)
	if _, err := db.DB.Exec(
		"INSERT INTO users (id, username, password_hash, totp_secret, is_admin, totp_active) VALUES (1, 'admin', ?, ?, 1, 0)",
		hash, enc,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	seedSession(t, profileRaw, adminUserFor("csrf-profile"))
	return secret
}

// postProfile envía un POST a /profile con el CSRF vigente de la sesión
// (HandleProfile lo rota en cada POST, incluso en rutas de error).
func postProfile(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	f := url.Values{}
	for k, vs := range form {
		for _, v := range vs {
			f.Add(k, v)
		}
	}
	Mu.Lock()
	csrf := ""
	if s, ok := ActiveSessions[sessionHash(profileRaw)]; ok && s != nil {
		csrf = s.CSRFToken
	}
	Mu.Unlock()
	f.Set("csrf_token", csrf)

	req := httptest.NewRequest("POST", "/profile", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "admin.test"
	req.AddCookie(&http.Cookie{Name: SessionKey, Value: profileRaw})
	rr := httptest.NewRecorder()
	HandleProfile(rr, req)
	return rr
}

// TestProfileContract congela el contrato de HandleProfile (2,3% de cobertura
// en el baseline): render, cambio de credenciales con verificación, 2FA y
// gestión de app tokens/sesiones.
func TestProfileContract(t *testing.T) {
	if testing.Short() {
		t.Skip("modo -short: test de integración (backend/Argon2)")
	}
	t.Run("GET renderiza el perfil con200", func(t *testing.T) {
		isolateState(t)
		seedProfileUser(t)

		req := httptest.NewRequest("GET", "/profile", nil)
		req.Host = "admin.test"
		req.AddCookie(&http.Cookie{Name: SessionKey, Value: profileRaw})
		rr := httptest.NewRecorder()
		HandleProfile(rr, req)

		if rr.Code != 200 {
			t.Fatalf("status = %d; want 200", rr.Code)
		}
	})

	t.Run("cambio de contraseña corta -> 400", func(t *testing.T) {
		isolateState(t)
		seedProfileUser(t)

		rr := postProfile(t, url.Values{
			"accion": {"update_profile"}, "current_password": {profilePass}, "new_password": {"corta"},
		})
		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d; want 400", rr.Code)
		}
	})

	t.Run("cambio de contraseña con actual incorrecta -> 403", func(t *testing.T) {
		isolateState(t)
		seedProfileUser(t)

		rr := postProfile(t, url.Values{
			"accion": {"update_profile"}, "current_password": {"equivocada"}, "new_password": {"otra-contrasena-larga-1"},
		})
		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d; want 403", rr.Code)
		}
	})

	t.Run("cambio de contraseña válido invalida otras sesiones y tokens", func(t *testing.T) {
		isolateState(t)
		seedProfileUser(t)

		// Otra sesión del mismo usuario + un app token
		otraHash := seedSession(t, "otra-sesion-raw", adminUserFor("csrf-otra"))
		if _, err := db.DB.Exec("INSERT INTO app_tokens (user_id, name, token_hash) VALUES (1, 'viejo', 'hash-viejo')"); err != nil {
			t.Fatalf("insert token: %v", err)
		}

		nueva := "nueva-contrasena-super-larga-1"
		rr := postProfile(t, url.Values{
			"accion": {"update_profile"}, "current_password": {profilePass}, "new_password": {nueva},
		})
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d; want 303 (body: %s)", rr.Code, rr.Body.String())
		}

		var hash string
		db.DB.QueryRow("SELECT password_hash FROM users WHERE id=1").Scan(&hash)
		if !auth.VerifyPassword(nueva, hash) {
			t.Error("la nueva contraseña no se persistió")
		}
		Mu.Lock()
		_, otraSigue := ActiveSessions[otraHash]
		_, actualSigue := ActiveSessions[sessionHash(profileRaw)]
		Mu.Unlock()
		if otraSigue {
			t.Error("la otra sesión debió invalidarse")
		}
		if !actualSigue {
			t.Error("la sesión actual no debe invalidarse")
		}
		if rowExists(t, "SELECT COUNT(*) FROM app_tokens WHERE user_id=1") {
			t.Error("los app tokens debieron borrarse tras cambiar contraseña")
		}
	})

	t.Run("renombrar usuario exige contraseña actual", func(t *testing.T) {
		isolateState(t)
		seedProfileUser(t)

		rr := postProfile(t, url.Values{
			"accion": {"update_profile"}, "current_password": {profilePass}, "new_username": {"nuevo-admin"},
		})
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d; want 303", rr.Code)
		}
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='nuevo-admin'").Scan(&count)
		if count != 1 {
			t.Error("username no actualizado en DB")
		}
		Mu.Lock()
		s := ActiveSessions[sessionHash(profileRaw)]
		Mu.Unlock()
		if s == nil || s.Username != "nuevo-admin" {
			t.Errorf("la sesión no refleja el nuevo username: %+v", s)
		}
	})

	t.Run("enable_2fa con código incorrecto no activa y renderiza error", func(t *testing.T) {
		isolateState(t)
		seedProfileUser(t)

		rr := postProfile(t, url.Values{"accion": {"enable_2fa"}, "code": {"000000"}})
		if rr.Code != 200 {
			t.Errorf("status = %d; want 200 (render con error)", rr.Code)
		}
		var totpActive bool
		db.DB.QueryRow("SELECT totp_active FROM users WHERE id=1").Scan(&totpActive)
		if totpActive {
			t.Error("2FA no debe activarse con código incorrecto")
		}
	})

	t.Run("enable_2fa con código TOTP correcto activa", func(t *testing.T) {
		isolateState(t)
		secret := seedProfileUser(t)

		rr := postProfile(t, url.Values{"accion": {"enable_2fa"}, "code": {auth.GetTOTPCode(secret)}})
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d; want 303 (body: %s)", rr.Code, rr.Body.String())
		}
		var totpActive bool
		db.DB.QueryRow("SELECT totp_active FROM users WHERE id=1").Scan(&totpActive)
		if !totpActive {
			t.Error("2FA no se activó con el código correcto")
		}
	})

	t.Run("enable_2fa no acepta el mismo código dos veces (anti-replay)", func(t *testing.T) {
		isolateState(t)
		secret := seedProfileUser(t)
		codigo := auth.GetTOTPCode(secret)

		rr := postProfile(t, url.Values{"accion": {"enable_2fa"}, "code": {codigo}})
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("primer enable: status = %d; want 303", rr.Code)
		}

		// Mismo código en la misma ventana -> rechazado (render con error)
		rr = postProfile(t, url.Values{"accion": {"enable_2fa"}, "code": {codigo}})
		if rr.Code != 200 {
			t.Errorf("segundo enable con el mismo código: status = %d; want 200 (rechazo)", rr.Code)
		}
	})

	t.Run("disable_2fa desactiva", func(t *testing.T) {
		isolateState(t)
		seedProfileUser(t)
		db.DB.Exec("UPDATE users SET totp_active = 1 WHERE id=1")

		rr := postProfile(t, url.Values{"accion": {"disable_2fa"}})
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d; want 303", rr.Code)
		}
		var totpActive bool
		db.DB.QueryRow("SELECT totp_active FROM users WHERE id=1").Scan(&totpActive)
		if totpActive {
			t.Error("2FA sigue activo")
		}
	})

	t.Run("create_token sin nombre -> 400", func(t *testing.T) {
		isolateState(t)
		seedProfileUser(t)

		rr := postProfile(t, url.Values{"accion": {"create_token"}, "token_name": {""}})
		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d; want 400", rr.Code)
		}
	})

	t.Run("create_token crea la fila y renderiza el token crudo", func(t *testing.T) {
		isolateState(t)
		seedProfileUser(t)

		rr := postProfile(t, url.Values{"accion": {"create_token"}, "token_name": {"ci-token"}})
		if rr.Code != 200 {
			t.Fatalf("status = %d; want 200 (render con token nuevo)", rr.Code)
		}
		if !rowExists(t, "SELECT COUNT(*) FROM app_tokens WHERE user_id=1 AND name='ci-token'") {
			t.Error("app token no persistido")
		}
	})

	t.Run("revoke_token solo afecta al usuario actual", func(t *testing.T) {
		isolateState(t)
		seedProfileUser(t)
		// Otro usuario con su propio token
		db.DB.Exec("INSERT INTO users (id, username, is_admin) VALUES (2, 'otro', 1)")
		db.DB.Exec("INSERT INTO app_tokens (id, user_id, name, token_hash) VALUES (10, 1, 'mio', 'h-mio')")
		db.DB.Exec("INSERT INTO app_tokens (id, user_id, name, token_hash) VALUES (11, 2, 'suyo', 'h-suyo')")

		rr := postProfile(t, url.Values{"accion": {"revoke_token"}, "token_id": {"10"}})
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d; want 303", rr.Code)
		}
		if rowExists(t, "SELECT COUNT(*) FROM app_tokens WHERE id=10") {
			t.Error("token propio no revocado")
		}
		if !rowExists(t, "SELECT COUNT(*) FROM app_tokens WHERE id=11") {
			t.Error("revocar no debe borrar tokens de OTRO usuario")
		}
	})

	t.Run("revoke_session del perfil elimina la sesión indicada", func(t *testing.T) {
		isolateState(t)
		seedProfileUser(t)
		victimHash := seedSession(t, "victim-profile-raw", adminUserFor("csrf-v"))

		rr := postProfile(t, url.Values{"accion": {"revoke_session"}, "token": {victimHash}})
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d; want 303", rr.Code)
		}
		Mu.Lock()
		_, queda := ActiveSessions[victimHash]
		Mu.Unlock()
		if queda {
			t.Error("sesión no revocada")
		}
	})

	t.Run("POST con CSRF inválido -> 403", func(t *testing.T) {
		isolateState(t)
		seedProfileUser(t)

		req := httptest.NewRequest("POST", "/profile", strings.NewReader(url.Values{
			"accion": {"disable_2fa"}, "csrf_token": {"malo"},
		}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = "admin.test"
		req.AddCookie(&http.Cookie{Name: SessionKey, Value: profileRaw})
		rr := httptest.NewRecorder()
		HandleProfile(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d; want 403", rr.Code)
		}
	})
}
