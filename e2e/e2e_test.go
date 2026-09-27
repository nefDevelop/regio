//go:build e2e

// Package e2e arranca el binario real de reGIO (cmd/regio) y valida flujos
// completos: setup → login → admin → proxy, geobloqueo y CLI.
//
// Se ejecuta SOLO con:  make test-e2e   (go test -tags e2e ./e2e/)
package e2e

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var regexCSRF = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

const (
	e2eAdminDomain = "admin.e2e.test"
	e2eServiceHost = "app.e2e.test"
	e2eMasterKey   = "test-master-key-32-bytes-length-!!!"
	e2eAdminPass   = "contrasena-admin-e2e-1234"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "regio-e2e-*")
	if err != nil {
		println("mkdtemp:", err.Error())
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	bin := filepath.Join(dir, "REGIO-e2e")
	build := exec.Command("go", "build", "-o", bin, "./cmd/regio")
	build.Dir = ".."
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		println("build del binario e2e:", err.Error())
		os.Exit(1)
	}
	binPath = bin

	os.Exit(m.Run())
}

var binPath string

// freePort devuelve un puerto local efímero recién liberado.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reservando puerto: %v", err)
	}
	defer l.Close()
	_, puerto, _ := net.SplitHostPort(l.Addr().String())
	return puerto
}

// regioInstance es una instancia e2e del binario real (mejora B1: expone el
// proceso para poder enviarle señales de apagado ordenado).
type regioInstance struct {
	client *http.Client
	base   string
	cmd    *exec.Cmd
}

// startRegio arranca el binario real con DB temporal y devuelve la instancia:
// un client que resuelve cualquier Host hacia la instancia (Host virtuales sin
// DNS), su dirección base y el proceso.
func startRegio(t *testing.T, extraEnv ...string) *regioInstance {
	t.Helper()
	puerto := freePort(t)
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "e2e.db")

	env := append(os.Environ(),
		"ADMIN_DOMAIN="+e2eAdminDomain,
		"MASTER_KEY="+e2eMasterKey,
		"REGIO_DB_PATH="+dbPath,
		"PORT="+puerto,
		"TRUSTED_PROXIES=",
		"FORCE_HTTPS=",
		"GEOIP_DB_PATH="+filepath.Join(tmp, "no-existe.mmdb"),
	)
	env = append(env, extraEnv...)

	cmd := exec.Command(binPath)
	cmd.Env = env
	logFile, _ := os.Create(filepath.Join(tmp, "server.log"))
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("arrancando binario: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if logFile != nil {
			logFile.Close()
		}
	})

	base := "127.0.0.1:" + puerto
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			// Resuelve cualquier host (admin.e2e.test, app.e2e.test...)
			// directamente hacia la instancia local, sin DNS.
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, base)
			},
		},
		// No seguir redirects: los tests verifican los 303.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Readiness por /health (salta el SecurityEngine, siempre responde)
	deadline := time.Now().Add(20 * time.Second)
	for {
		req, _ := http.NewRequest("GET", "http://health.e2e.test/health", nil)
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			// Cualquier respuesta HTTP significa que el servidor está vivo
			// (con FORCE_HTTPS el /health responde 301/400, no 200).
			if resp.StatusCode > 0 {
				return &regioInstance{client: client, base: base, cmd: cmd}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("/health no respondió en 20s: %v", err)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// do ejecuta una petición contra la instancia con Host virtual.
func do(t *testing.T, client *http.Client, method, rawURL, host string, form url.Values, cookie *http.Cookie) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = host
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, string(data)
}

// doHdr es do() con cabeceras adicionales (p.ej. X-Forwarded-For tras
// declarar TRUSTED_PROXIES, para simular tráfico desde una IP pública).
func doHdr(t *testing.T, client *http.Client, method, rawURL, host string, form url.Values, cookie *http.Cookie, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = host
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, string(data)
}

// nonLoopbackIP devuelve una IP local no-loopback para el backend del e2e
// (IsValidTarget prohíbe targets loopback: la semántica de producción).
func nonLoopbackIP(t *testing.T) string {
	t.Helper()
	// 1) Truco UDP: la kernel resuelve la ruta de salida sin enviar paquetes
	//    (no requiere netlink, bloqueado en algunos entornos como Termux).
	if conn, err := net.Dial("udp", "8.8.8.8:53"); err == nil {
		defer conn.Close()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil && !addr.IP.IsLoopback() {
			if ip4 := addr.IP.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	// 2) Fallback: enumerar interfaces (Linux/CI clásico)
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				ipnet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				if ip4 := ipnet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
					return ip4.String()
				}
			}
		}
	}
	t.Skip("sin IP no-loopback disponible para el backend e2e")
	return ""
}

// extraeCSRF obtiene el token CSRF vigente del panel admin.
func extraeCSRF(t *testing.T, html string) string {
	t.Helper()
	m := regexCSRF.FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("no se encontró csrf_token en el HTML (len=%d)", len(html))
	}
	return m[1]
}

// loginAdmin ejecuta setup + login y devuelve la cookie de sesión.
func loginAdmin(t *testing.T, client *http.Client) *http.Cookie {
	t.Helper()

	// 1. Setup inicial
	resp, _ := do(t, client, "POST", "http://setup.e2e.test/setup", e2eAdminDomain, url.Values{
		"user": {"admin-e2e"}, "pass": {e2eAdminPass},
	}, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("setup: status = %d; want 303", resp.StatusCode)
	}

	// 2. Login
	resp, _ = do(t, client, "POST", "http://login.e2e.test/REGIO-login", e2eAdminDomain, url.Values{
		"user": {"admin-e2e"}, "pass": {e2eAdminPass},
	}, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: status = %d; want 303", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "REGIO_session" && c.Value != "" {
			return c
		}
	}
	t.Fatal("login no emitió cookie de sesión")
	return nil
}
