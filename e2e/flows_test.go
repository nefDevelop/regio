//go:build e2e

package e2e

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestE2ESmoke: flujo completo de usuario sobre el binario real —
// setup → login → panel → crear puente → proxy → logout.
func TestE2ESmoke(t *testing.T) {
	inst := startRegio(t)
	client := inst.client

	// Backend real al que proxyear. Se ata a una IP no-loopback porque
	// IsValidTarget prohíbe targets loopback (semántica de producción).
	ln, err := net.Listen("tcp", nonLoopbackIP(t)+":0")
	if err != nil {
		t.Fatalf("lanzando backend: %v", err)
	}
	backendSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend-Path", r.URL.Path)
		w.Header().Set("X-Backend-Forwarded-Host", r.Header.Get("X-Forwarded-Host"))
		// Mejora A1: si el backend recibiera la cookie de sesión de reGIO,
		// lo marca para que el test lo detecte.
		if strings.Contains(r.Header.Get("Cookie"), "REGIO_session") {
			w.Header().Set("X-Backend-ReGIO-Session", "filtrada")
		}
		w.Write([]byte("hola-desde-backend"))
	})}
	go backendSrv.Serve(ln)
	t.Cleanup(func() { backendSrv.Close() })
	backendURL := "http://" + ln.Addr().String()

	sesion := loginAdmin(t, client)

	// Panel accesible con sesión
	resp, body := do(t, client, "GET", "http://panel.e2e.test/admin", e2eAdminDomain, nil, sesion)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin: status = %d; want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "Puentes de Red") {
		t.Error("el panel no muestra la sección de puentes")
	}
	csrf := extraeCSRF(t, body)

	// Crear el puente hacia el backend
	resp, _ = do(t, client, "POST", "http://panel.e2e.test/admin", e2eAdminDomain, url.Values{
		"accion": {"add_service"}, "csrf_token": {csrf},
		"host": {e2eServiceHost}, "target": {backendURL},
	}, sesion)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("add_service: status = %d; want 303", resp.StatusCode)
	}

	// Proxy con sesión: llega al backend reescribiendo headers
	resp, body = do(t, client, "GET", "http://"+e2eServiceHost+"/ruta", e2eServiceHost, nil, sesion)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy con sesión: status = %d; want 200", resp.StatusCode)
	}
	if body != "hola-desde-backend" {
		t.Errorf("body = %q; want hola-desde-backend", body)
	}
	if resp.Header.Get("X-Backend-Path") != "/ruta" {
		t.Errorf("el backend recibió path %q; want /ruta", resp.Header.Get("X-Backend-Path"))
	}
	if resp.Header.Get("X-Backend-Forwarded-Host") != e2eServiceHost {
		t.Errorf("X-Forwarded-Host = %q; want %s", resp.Header.Get("X-Backend-Forwarded-Host"), e2eServiceHost)
	}
	// Mejora A1: el backend jamás ve la cookie de sesión de reGIO
	if resp.Header.Get("X-Backend-ReGIO-Session") != "" {
		t.Error("el backend recibió la cookie REGIO_session de reGIO (fuga de sesión)")
	}

	// Sin sesión -> 401
	resp, _ = do(t, client, "GET", "http://"+e2eServiceHost+"/ruta", e2eServiceHost, nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("proxy sin sesión: status = %d; want 401", resp.StatusCode)
	}

	// Logout: el CSRF rota en cada POST, así que se refresca del panel
	_, body = do(t, client, "GET", "http://panel.e2e.test/admin", e2eAdminDomain, nil, sesion)
	csrf = extraeCSRF(t, body)
	resp, _ = do(t, client, "POST", "http://panel.e2e.test/logout", e2eAdminDomain, url.Values{
		"csrf_token": {csrf},
	}, sesion)
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("logout: status = %d; want 303", resp.StatusCode)
	}
	resp, _ = do(t, client, "GET", "http://panel.e2e.test/admin", e2eAdminDomain, nil, sesion)
	if resp.StatusCode == http.StatusOK {
		t.Error("/admin sigue accesible tras logout")
	}
}

// TestE2EGeoBloqueo arranca con allow/ES + fail-closed y sin BD GeoIP:
// toda petición distinta de /health debe recibir 403 de región.
func TestE2EGeoBloqueo(t *testing.T) {
	// El cliente e2e conecta desde loopback (que el geo salta por diseño):
	// se declara 127.0.0.1 como proxy de confianza y se simula la IP pública
	// de origen con X-Forwarded-For, tal como haría Cloudflare/Nginx.
	inst := startRegio(t,
		"GEO_MODE=allow",
		"GEO_COUNTRIES=ES",
		"GEO_FAIL_MODE=closed",
		"TRUSTED_PROXIES=127.0.0.1",
	)
	client := inst.client
	xff := map[string]string{"X-Forwarded-For": "203.0.113.9"}

	resp, body := doHdr(t, client, "GET", "http://cualquiera.e2e.test/algo", "cualquiera.e2e.test", nil, nil, xff)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", resp.StatusCode)
	}
	if !strings.Contains(body, "región") {
		t.Errorf("body = %q; want mensaje genérico de región", body)
	}

	// /health nunca se geobloquea (readiness de Docker)
	resp, body = doHdr(t, client, "GET", "http://health.e2e.test/health", "health.e2e.test", nil, nil, xff)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "ok") {
		t.Errorf("/health = %d %q; want 200 ok", resp.StatusCode, body)
	}

	// Fix S2: /api/csp-report AHORA pasa por el engine -> geo lo bloquea
	resp, _ = doHdr(t, client, "POST", "http://csp.e2e.test/api/csp-report", "csp.e2e.test", nil, nil, xff)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("/api/csp-report: status = %d; want 403 (pasa por el engine desde S2)", resp.StatusCode)
	}
}

// TestE2ECLI valida el contrato del CLI del binario real: add/list/del.
func TestE2ECLI(t *testing.T) {
	dbPath := t.TempDir() + "/cli.db"
	env := append(os.Environ(),
		"ADMIN_DOMAIN="+e2eAdminDomain,
		"MASTER_KEY="+e2eMasterKey,
		"REGIO_DB_PATH="+dbPath,
	)

	run := func(args ...string) (string, int) {
		cmd := exec.Command(binPath, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			code = -1
		}
		return string(out), code
	}

	// list con DB vacía: sale limpio
	out, code := run("list")
	if code != 0 {
		t.Errorf("list (vacío): exit = %d, out = %s", code, out)
	}

	// add
	out, code = run("add", "--host", "cli.e2e.test", "--target", "http://10.0.0.9:8080")
	if code != 0 {
		t.Errorf("add: exit = %d, out = %s", code, out)
	}

	// list refleja el servicio
	out, _ = run("list")
	if !strings.Contains(out, "cli.e2e.test") || !strings.Contains(out, "10.0.0.9:8080") {
		t.Errorf("list no muestra el servicio añadido: %s", out)
	}

	// del
	out, code = run("del", "--host", "cli.e2e.test")
	if code != 0 {
		t.Errorf("del: exit = %d, out = %s", code, out)
	}
	out, _ = run("list")
	if strings.Contains(out, "cli.e2e.test") {
		t.Errorf("list aún muestra el servicio borrado: %s", out)
	}

	// add sin --host: error
	_, code = run("add", "--target", "http://10.0.0.9:8080")
	if code == 0 {
		t.Error("add sin --host debe fallar")
	}
}

// TestE2EHTTPSRedirectSoloHostsConocidos valida el fix deuda #3 (anti
// open-redirect): con FORCE_HTTPS solo se redirige a hosts que reGIO sirve.
func TestE2EHTTPSRedirectSoloHostsConocidos(t *testing.T) {
	inst := startRegio(t, "FORCE_HTTPS=true")
	client := inst.client

	// Host desconocido -> 400 (nunca se redirige hacia un Host arbitrario)
	resp, _ := do(t, client, "GET", "http://evil-not-known.test/x", "evil-not-known.test", nil, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("host desconocido: status = %d; want 400 (anti open-redirect)", resp.StatusCode)
	}

	// Host admin (conocido) -> 301 al mismo host bajo https
	resp, _ = do(t, client, "GET", "http://saludo.e2e.test/health", e2eAdminDomain, nil, nil)
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("host admin: status = %d; want 301", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://"+e2eAdminDomain+"/") {
		t.Errorf("Location = %q; want https://%s/...", loc, e2eAdminDomain)
	}
}

// TestE2EGracefulShutdown valida la mejora B1: SIGTERM (docker stop) drena
// las peticiones en vuelo y el proceso termina con código 0 (antes moría
// directamente por señal con las conexiones cortadas).
func TestE2EGracefulShutdown(t *testing.T) {
	inst := startRegio(t)
	client := inst.client

	// Backend lento (1,5 s) para tener una petición en vuelo al llegar SIGTERM
	ln, err := net.Listen("tcp", nonLoopbackIP(t)+":0")
	if err != nil {
		t.Fatalf("lanzando backend lento: %v", err)
	}
	backendLento := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		w.Write([]byte("lento-ok"))
	})}
	go backendLento.Serve(ln)
	t.Cleanup(func() { backendLento.Close() })
	backendURL := "http://" + ln.Addr().String()

	// Estado completo: setup + login + puente hacia el backend lento
	sesion := loginAdmin(t, client)
	resp, body := do(t, client, "GET", "http://panel.e2e.test/admin", e2eAdminDomain, nil, sesion)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin: %d", resp.StatusCode)
	}
	csrf := extraeCSRF(t, body)
	resp, _ = do(t, client, "POST", "http://panel.e2e.test/admin", e2eAdminDomain, url.Values{
		"accion": {"add_service"}, "csrf_token": {csrf},
		"host": {e2eServiceHost}, "target": {backendURL},
	}, sesion)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("add_service: %d", resp.StatusCode)
	}

	// Petición en vuelo (sin t: corre en goroutine)
	type resultado struct {
		codigo int
		err    error
	}
	resCh := make(chan resultado, 1)
	go func() {
		req, _ := http.NewRequest("GET", "http://"+e2eServiceHost+"/lento", nil)
		req.Host = e2eServiceHost
		req.AddCookie(&http.Cookie{Name: "REGIO_session", Value: sesion.Value})
		resp, err := client.Do(req)
		if err != nil {
			resCh <- resultado{0, err}
			return
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		resCh <- resultado{resp.StatusCode, nil}
	}()

	// Dar tiempo a que la petición entre y empiece a esperar al backend
	time.Sleep(500 * time.Millisecond)

	if err := inst.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("enviando SIGTERM: %v", err)
	}

	// 1) El proceso termina con código 0 (apagado ordenado, no muere por señal)
	salida := make(chan error, 1)
	go func() {
		_, err := inst.cmd.Process.Wait()
		salida <- err
	}()
	select {
	case err := <-salida:
		if err != nil {
			t.Errorf("exit = %v; want código 0 (apagado ordenado)", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("el proceso no terminó en 15s tras SIGTERM")
	}

	// 2) La petición en vuelo se completó con 200 (fue drenada, no cortada)
	select {
	case r := <-resCh:
		if r.err != nil {
			t.Errorf("petición en vuelo cortada: %v", r.err)
		} else if r.codigo != http.StatusOK {
			t.Errorf("petición en vuelo: status = %d; want 200", r.codigo)
		}
	case <-time.After(5 * time.Second):
		t.Error("la petición en vuelo nunca completó")
	}
}
