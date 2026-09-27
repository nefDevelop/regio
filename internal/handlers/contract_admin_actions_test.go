package handlers

import (
	"net/url"
	"testing"

	"regio/internal/db"
	"regio/internal/models"
	"regio/internal/security"
)

const (
	contractRawToken = "admin-contract-raw"
	contractCSRF     = "csrf-contract-ok"
)

// seedContractSession crea la sesión administrador usada por la matriz.
func seedContractSession(t *testing.T) {
	t.Helper()
	seedAdminUser(t, 1, "admin")
	seedSession(t, contractRawToken, adminUserFor(contractCSRF))
}

// postContract lanza una acción admin con el CSRF vigente. Cada POST exitoso
// rota el token (comportamiento bajo test), así que se lee de la sesión en
// cada llamada en lugar de usar una constante.
func postContract(t *testing.T, form url.Values) *contractResp {
	t.Helper()
	f := url.Values{}
	for k, vs := range form {
		for _, v := range vs {
			f.Add(k, v)
		}
	}
	Mu.Lock()
	csrf := ""
	if u, ok := ActiveSessions[sessionHash(contractRawToken)]; ok && u != nil {
		csrf = u.CSRFToken
	}
	Mu.Unlock()
	f.Set("csrf_token", csrf)
	rr := postAdmin(t, contractRawToken, f)
	return &contractResp{code: rr.Code, body: rr.Body.String(), loc: rr.Header().Get("Location")}
}

type contractResp struct {
	code int
	body string
	loc  string
}

func (r *contractResp) requireRedirect(t *testing.T, action string) {
	t.Helper()
	if r.code != 303 {
		t.Errorf("%s: status = %d; want 303 (body: %s)", action, r.code, r.body)
	}
}

// rowExists consulta una fila de la DB.
func rowExists(t *testing.T, query string, args ...interface{}) bool {
	t.Helper()
	var n int
	if err := db.DB.QueryRow(query, args...).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// TestAdminActionsContract congela el contrato de las 12 acciones del panel
// admin: con CSRF válido -> 303 + side-effect verificado. Es la red de
// seguridad del refactor R2 (extracción del switch a dispatch).
func TestAdminActionsContract(t *testing.T) {
	t.Run("add_service crea el puente en memoria y en DB", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedContractSession(t)

		resp := postContract(t, url.Values{
			"accion": {"add_service"}, "host": {"nuevo.test"},
			"target": {"http://192.168.5.5:80"}, "csp": {"default-src 'self'"}, "public": {"on"},
		})
		resp.requireRedirect(t, "add_service")

		Mu.Lock()
		target := Config.Servicios["nuevo.test"]
		pub := Config.Publicos["nuevo.test"]
		csp := Config.CSPs["nuevo.test"]
		Mu.Unlock()
		if target != "http://192.168.5.5:80" || !pub || csp != "default-src 'self'" {
			t.Errorf("Config = target:%q pub:%v csp:%q", target, pub, csp)
		}
		if !rowExists(t, "SELECT COUNT(*) FROM servicios WHERE host='nuevo.test' AND target='http://192.168.5.5:80'") {
			t.Error("servicio no persistido en DB")
		}
	})

	t.Run("add_service con target inválido (SSRF) -> 400 sin crear nada", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedContractSession(t)

		resp := postContract(t, url.Values{
			"accion": {"add_service"}, "host": {"evil.test"}, "target": {"http://localhost:8080"},
		})
		if resp.code != 400 {
			t.Errorf("status = %d; want 400", resp.code)
		}
		Mu.Lock()
		_, existe := Config.Servicios["evil.test"]
		Mu.Unlock()
		if existe {
			t.Error("servicio con target SSRF no debe crearse")
		}
	})

	t.Run("update_service renombra y conserva la política geo", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedContractSession(t)
		Mu.Lock()
		Config.Servicios["viejo.test"] = "http://192.168.6.6:80"
		Config.GeoModes["viejo.test"] = "deny"
		Config.GeoCountries["viejo.test"] = "IN"
		Mu.Unlock()

		resp := postContract(t, url.Values{
			"accion": {"update_service"}, "old_host": {"viejo.test"},
			"host": {"nuevo-nombre.test"}, "target": {"http://192.168.6.7:80"}, "csp": {"img-src 'self'"},
		})
		resp.requireRedirect(t, "update_service")

		Mu.Lock()
		_, viejo := Config.Servicios["viejo.test"]
		target := Config.Servicios["nuevo-nombre.test"]
		geoMode := Config.GeoModes["nuevo-nombre.test"]
		geoCtry := Config.GeoCountries["nuevo-nombre.test"]
		_, viejoGeo := Config.GeoModes["viejo.test"]
		Mu.Unlock()
		if viejo || target != "http://192.168.6.7:80" {
			t.Errorf("rename: viejoExiste=%v target=%q", viejo, target)
		}
		if geoMode != "deny" || geoCtry != "IN" || viejoGeo {
			t.Errorf("política geo no migrada con el rename: mode=%q ctry=%q viejo=%v", geoMode, geoCtry, viejoGeo)
		}
		if !rowExists(t, "SELECT COUNT(*) FROM servicios WHERE host='nuevo-nombre.test'") ||
			rowExists(t, "SELECT COUNT(*) FROM servicios WHERE host='viejo.test'") {
			t.Error("DB no refleja el rename")
		}
	})

	t.Run("delete_service borra en memoria y en DB", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedContractSession(t)
		Mu.Lock()
		Config.Servicios["borrar.test"] = "http://192.168.7.7:80"
		Config.GeoModes["borrar.test"] = "allow"
		Mu.Unlock()
		if err := db.SaveConfig(Config); err != nil {
			t.Fatalf("seed DB: %v", err)
		}

		resp := postContract(t, url.Values{"accion": {"delete_service"}, "host": {"borrar.test"}})
		resp.requireRedirect(t, "delete_service")

		Mu.Lock()
		_, queda := Config.Servicios["borrar.test"]
		_, quedaGeo := Config.GeoModes["borrar.test"]
		Mu.Unlock()
		if queda || quedaGeo {
			t.Error("servicio/geo no borrado de memoria")
		}
		if rowExists(t, "SELECT COUNT(*) FROM servicios WHERE host='borrar.test'") {
			t.Error("servicio no borrado de DB")
		}
	})

	t.Run("set_geo_policy guarda la política global en DB (source=db)", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedContractSession(t)
		prev := security.GetGlobalGeoPolicy()
		t.Cleanup(func() { _ = security.SetGlobalGeoPolicy(prev) })

		resp := postContract(t, url.Values{
			"accion": {"set_geo_policy"}, "geo_mode": {"deny"},
			"geo_countries": {"IN"}, "geo_fail_mode": {"closed"},
		})
		resp.requireRedirect(t, "set_geo_policy")

		view := security.GetGeoPolicyView()
		if view.Mode != "deny" || view.Countries != "IN" || view.FailMode != "closed" || view.Source != "db" {
			t.Errorf("vista = %+v; want deny/IN/closed/db", view)
		}
		if v, _ := db.GetSetting("geo_mode"); v != "deny" {
			t.Errorf("geo_mode en settings = %q; want deny", v)
		}
	})

	t.Run("set_geo_policy inválido -> 400 sin persistir", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedContractSession(t)

		resp := postContract(t, url.Values{
			"accion": {"set_geo_policy"}, "geo_mode": {"allow"},
			"geo_countries": {"España"}, "geo_fail_mode": {"open"},
		})
		if resp.code != 400 {
			t.Errorf("status = %d; want 400 (país inválido)", resp.code)
		}
	})

	t.Run("set_service_geo aplica override por servicio en Config y DB", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedContractSession(t)
		Mu.Lock()
		Config.Servicios["geo-svc.test"] = "http://192.168.8.8:80"
		Mu.Unlock()
		if err := db.SaveConfig(Config); err != nil {
			t.Fatalf("seed DB: %v", err)
		}

		resp := postContract(t, url.Values{
			"accion": {"set_service_geo"}, "host": {"geo-svc.test"},
			"geo_mode": {"allow"}, "geo_countries": {"ES, FR"},
		})
		resp.requireRedirect(t, "set_service_geo")

		Mu.Lock()
		mode := Config.GeoModes["geo-svc.test"]
		ctry := Config.GeoCountries["geo-svc.test"]
		Mu.Unlock()
		if mode != "allow" || ctry != "ES, FR" {
			t.Errorf("override = mode:%q ctry:%q", mode, ctry)
		}
		if !rowExists(t, "SELECT COUNT(*) FROM servicios WHERE host='geo-svc.test' AND geo_mode='allow' AND geo_countries='ES, FR'") {
			t.Error("override geo no persistido en columnas de servicios")
		}
	})

	t.Run("set_service_geo con host inexistente -> 404", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedContractSession(t)

		resp := postContract(t, url.Values{
			"accion": {"set_service_geo"}, "host": {"no-existe.test"},
			"geo_mode": {"allow"}, "geo_countries": {"ES"},
		})
		if resp.code != 404 {
			t.Errorf("status = %d; want 404", resp.code)
		}
	})

	t.Run("add_bypass_key guarda solo el hash y CheckBypass acepta el raw", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedContractSession(t)
		const raw = "bypass-raw-valor"
		t.Cleanup(func() { security.DeleteBypassKey(testBypassHash(raw)) })

		resp := postContract(t, url.Values{
			"accion": {"add_bypass_key"}, "token": {raw},
			"name": {"ci"}, "host": {"bypass-host.test"},
		})
		resp.requireRedirect(t, "add_bypass_key")

		hash := testBypassHash(raw)
		if !rowExists(t, "SELECT COUNT(*) FROM bypass_keys WHERE token=?", hash) {
			t.Error("hash no persistido en bypass_keys")
		}
		if rowExists(t, "SELECT COUNT(*) FROM bypass_keys WHERE token=?", raw) {
			t.Error("el token raw NO debe almacenarse en claro")
		}
		if ok, _ := security.CheckBypass(raw, "bypass-host.test"); !ok {
			t.Error("CheckBypass rechaza el token raw recién creado")
		}
	})

	t.Run("delete_bypass_key elimina por hash (la UI envía el hash)", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedContractSession(t)
		const raw = "bypass-a-borrar"
		security.AddBypassKey(raw, "temp", "h.test")
		hash := testBypassHash(raw)

		resp := postContract(t, url.Values{"accion": {"delete_bypass_key"}, "token": {hash}})
		resp.requireRedirect(t, "delete_bypass_key")

		if rowExists(t, "SELECT COUNT(*) FROM bypass_keys WHERE token=?", hash) {
			t.Error("bypass key no eliminada de DB")
		}
		if ok, _ := security.CheckBypass(raw, "h.test"); ok {
			t.Error("CheckBypass sigue aceptando la clave borrada")
		}
	})

	t.Run("add_user crea usuario con invitación y sin admin", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedContractSession(t)

		resp := postContract(t, url.Values{"accion": {"add_user"}, "new_user": {"carlos"}})
		resp.requireRedirect(t, "add_user")

		if !rowExists(t, "SELECT COUNT(*) FROM users WHERE username='carlos' AND is_admin=0 AND LENGTH(invite_token)>0") {
			t.Error("usuario carlos no creado con invite_token e is_admin=0")
		}
	})

	t.Run("delete_user elimina un admin cuando queda al menos otro", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedContractSession(t)
		seedAdminUser(t, 2, "bob")

		resp := postContract(t, url.Values{"accion": {"delete_user"}, "del_user": {"bob"}})
		resp.requireRedirect(t, "delete_user")

		if rowExists(t, "SELECT COUNT(*) FROM users WHERE username='bob'") {
			t.Error("bob no eliminado")
		}
		if !rowExists(t, "SELECT COUNT(*) FROM users WHERE username='admin'") {
			t.Error("el admin restante no debe verse afectado")
		}
	})

	t.Run("ban_ip / unban_ip", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedContractSession(t)
		t.Cleanup(func() { security.UnbanIP("203.0.113.77") })

		resp := postContract(t, url.Values{"accion": {"ban_ip"}, "target_ip": {"203.0.113.77"}})
		resp.requireRedirect(t, "ban_ip")
		if !bannedContains("203.0.113.77") {
			t.Error("IP no aparece en GetBannedIPs")
		}

		resp = postContract(t, url.Values{"accion": {"unban_ip"}, "target_ip": {"203.0.113.77"}})
		resp.requireRedirect(t, "unban_ip")
		if bannedContains("203.0.113.77") {
			t.Error("IP sigue baneada tras unban_ip")
		}
	})

	t.Run("revoke_session elimina las sesiones indicadas", func(t *testing.T) {
		isolateState(t)
		cleanUsers(t)
		seedContractSession(t)
		victim := "victim-raw-token"
		victimHash := seedSession(t, victim, adminUserFor("csrf-victim"))

		resp := postContract(t, url.Values{"accion": {"revoke_session"}, "tokens": {victimHash}})
		resp.requireRedirect(t, "revoke_session")

		Mu.Lock()
		_, quedaba := ActiveSessions[victimHash]
		Mu.Unlock()
		if quedaba {
			t.Error("sesión víctima no revocada")
		}
	})
}

// TestAdminActionsCSRFContract verifica que TODAS las acciones rechazan el
// CSRF inválido con 403 y sin efectos secundarios.
func TestAdminActionsCSRFContract(t *testing.T) {
	acciones := []url.Values{
		{"accion": {"add_service"}, "host": {"csrf.test"}, "target": {"http://192.168.9.9:80"}},
		{"accion": {"update_service"}, "old_host": {"csrf.test"}, "host": {"csrf2.test"}, "target": {"http://192.168.9.9:80"}},
		{"accion": {"delete_service"}, "host": {"csrf.test"}},
		{"accion": {"set_geo_policy"}, "geo_mode": {"deny"}, "geo_countries": {"IN"}, "geo_fail_mode": {"open"}},
		{"accion": {"set_service_geo"}, "host": {"csrf.test"}, "geo_mode": {"allow"}, "geo_countries": {"ES"}},
		{"accion": {"add_bypass_key"}, "token": {"t"}, "name": {"n"}, "host": {"h"}},
		{"accion": {"delete_bypass_key"}, "token": {"t"}},
		{"accion": {"add_user"}, "new_user": {"csrfuser"}},
		{"accion": {"delete_user"}, "del_user": {"admin"}},
		{"accion": {"ban_ip"}, "target_ip": {"203.0.113.99"}},
		{"accion": {"unban_ip"}, "target_ip": {"203.0.113.99"}},
		{"accion": {"revoke_session"}, "tokens": {"x"}},
	}

	isolateState(t)
	cleanUsers(t)
	seedContractSession(t)
	geoPrev := security.GetGlobalGeoPolicy()
	t.Cleanup(func() { _ = security.SetGlobalGeoPolicy(geoPrev) })

	for _, form := range acciones {
		accion := form.Get("accion")
		t.Run(accion, func(t *testing.T) {
			f := url.Values{}
			for k, vs := range form {
				for _, v := range vs {
					f.Add(k, v)
				}
			}
			f.Set("csrf_token", "token-incorrecto")

			rr := postAdmin(t, contractRawToken, f)
			if rr.Code != 403 {
				t.Errorf("%s con CSRF inválido: status = %d; want 403", accion, rr.Code)
			}
		})
	}

	// Efecto secundario comprobado: nada de lo anterior debe haberse aplicado
	Mu.Lock()
	_, creado := Config.Servicios["csrf.test"]
	Mu.Unlock()
	if creado {
		t.Error("add_service con CSRF inválido no debe crear el servicio")
	}
	if rowExists(t, "SELECT COUNT(*) FROM users WHERE username='csrfuser'") {
		t.Error("add_user con CSRF inválido no debe crear usuarios")
	}
	if security.GetGeoPolicyView().Mode == "deny" && security.GetGeoPolicyView().Countries == "IN" {
		t.Error("set_geo_policy con CSRF inválido no debe cambiar la política")
	}
}

func bannedContains(target string) bool {
	for _, b := range security.GetBannedIPs() {
		if b.Target == target {
			return true
		}
	}
	return false
}

// adminUserFor devuelve un usuario admin con el CSRF indicado.
func adminUserFor(csrf string) *models.User {
	return &models.User{ID: 1, Username: "admin", IsAdmin: true, CSRFToken: csrf}
}
