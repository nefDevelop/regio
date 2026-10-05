//go:build ignore

// loadgen — generador de carga y medidor de RSS para reGIO.
//
// reGIO es un proxy inverso: no tiene endpoints propios que golpear. La carga
// se hace pasar *a través* del proxy hacia un upstream dummy, de modo que se
// mide el stack real (WAF + rate limit + proxy + dial anti-SSRF + logging).
//
// IP virtual por petición vía X-Forwarded-For, porque TRUSTED_PROXIES=127.0.0.1
// hace que regio confíe en ese header. Es obligatorio: CheckRateLimit limita a
// 100 peticiones/minuto POR IP, así que sin IPs virtuales el 99,9 % de la carga
// devolvería 429 y estaríamos midiendo el rate limiter en vez del proxy.
//
// RSS se lee de /proc/<pid>/status: VmRSS (actual) y VmHWM (pico). Sin
// dependencias externas: el toolchain del repo no necesita nada nuevo.
//
// Uso:
//
//	go run scripts/perf/loadgen.go [flags]
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

var (
	binary    = flag.String("binary", "./REGIO", "Binario de reGIO a medir")
	dbPath    = flag.String("db", "./data/perf/regio_perf.db", "Base de datos de perf")
	port      = flag.Int("port", 19090, "Puerto HTTP de reGIO")
	adminDom  = flag.String("admin-domain", "admin.local", "ADMIN_DOMAIN del servidor")
	masterKey = flag.String("master-key", "seed-master-key-for-testing-only-123",
		"MASTER_KEY; debe coincidir con el usado por `make seed`")
	profiles = flag.String("profiles", "health,proxy,auth",
		"Perfiles separados por coma: health (camino mínimo), proxy (proxy completo), auth (login+Argon2)")
	levels   = flag.String("levels", "10,50,100,200", "Niveles de concurrencia, separados por coma")
	duration = flag.Duration("duration", 10*time.Second, "Duración medida por fase")
	warmup   = flag.Duration("warmup", 3*time.Second, "Calentamiento por fase (no se contabiliza)")
	ipPool   = flag.Int("ip-pool", 8192, "IPs virtuales totales, en bloques disjuntos por fase")
	outJSON  = flag.String("out", "", "Fichero JSON de resultados (por defecto perf/load-<ts>.json)")
)

// ---------------------------------------------------------------------------
// Modelos de resultados
// ---------------------------------------------------------------------------

type sample struct {
	ts  time.Time
	rss int64
	hwm int64
}

type phaseResult struct {
	Profile       string           `json:"profile"`
	Level         int              `json:"concurrency"`
	Duration      string           `json:"duration"`
	Requests      int64            `json:"requests"`
	Errors        int64            `json:"errors"`
	Status429     int64            `json:"status_429_rate_limit"`
	Status5xx     int64            `json:"status_5xx"`
	Status4xx     int64            `json:"status_4xx"`
	Codes         map[string]int64 `json:"status_codes"`
	RPS           float64          `json:"rps"`
	LatP50Ms      float64          `json:"lat_p50_ms"`
	LatP95Ms      float64          `json:"lat_p95_ms"`
	LatP99Ms      float64          `json:"lat_p99_ms"`
	LatMaxMs      float64          `json:"lat_max_ms"`
	RSSStartBytes int64            `json:"rss_start_bytes"`
	RSSEndBytes   int64            `json:"rss_end_bytes"`
	RSSPeakBytes  int64            `json:"rss_peak_bytes"`
	RSSDeltaBytes int64            `json:"rss_delta_bytes"`
}

type report struct {
	Timestamp  string         `json:"timestamp"`
	GoVersion  string         `json:"go_version"`
	GOOS       string         `json:"goos"`
	NumCPU     int            `json:"num_cpu"`
	GOMAXPROCS int            `json:"gomaxprocs"`
	DBPath     string         `json:"db_path"`
	DBBytes    int64          `json:"db_bytes"`
	DBBytesEnd int64          `json:"db_bytes_after_load"`
	ServerPID  int            `json:"server_pid"`
	Upstream   string         `json:"upstream"`
	IdleRSS    int64          `json:"idle_rss_bytes"`
	IdleHWM    int64          `json:"idle_hwm_bytes"`
	SeedNote   string         `json:"seed_note"`
	Profiles   map[string]any `json:"profiles_measured"`
	Phases     []phaseResult  `json:"phases"`
}

type phase struct {
	profile string
	level   int
	ips     []string
}

// ---------------------------------------------------------------------------

func main() {
	flag.Parse()

	upstreamSrv, upstreamURL, err := startUpstream()
	if err != nil {
		fatal("arrancando upstream dummy: %v", err)
	}
	defer upstreamSrv.Close()
	fmt.Printf("  upstream dummy  %s\n", upstreamURL)

	if err := prepareDB(*dbPath, upstreamURL); err != nil {
		fatal("preparando %s: %v", *dbPath, err)
	}
	dbBefore := fileSize(*dbPath)
	fmt.Printf("  base de datos   %.1f MiB\n", mib(dbBefore))

	srv, err := startServer()
	if err != nil {
		fatal("arrancando %s: %v", *binary, err)
	}
	pid := srv.Process.Pid
	defer stopServer(srv)

	base := fmt.Sprintf("http://127.0.0.1:%d", *port)
	if err := waitHealthy(base, 20*time.Second); err != nil {
		fatal("reGIO no respondió /health: %v", err)
	}
	fmt.Printf("  reGIO           pid=%d  :%d  admin=%s\n", pid, *port, *adminDom)

	// RSS en reposo: referencia obligatoria. Sin ella, "RSS 180 MiB" no dice
	// nada, porque incluye lo que el proceso ya tenía antes de la carga.
	time.Sleep(2 * time.Second)
	idleRSS, idleHWM := readRSS(pid)
	fmt.Printf("  RSS en reposo   %.1f MiB (VmHWM %.1f MiB)\n", mib(idleRSS), mib(idleHWM))

	phases := buildPhases()
	results := make([]phaseResult, 0, len(phases))

	for _, ph := range phases {
		res := runPhase(base, pid, ph)
		results = append(results, res)
		printPhase(res)
		time.Sleep(500 * time.Millisecond) // deja decantar la DB entre fases
	}

	rep := report{
		Timestamp:  time.Now().Format(time.RFC3339),
		GoVersion:  runtime.Version(),
		GOOS:       runtime.GOOS,
		NumCPU:     runtime.NumCPU(),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
		DBPath:     *dbPath,
		DBBytes:    dbBefore,
		DBBytesEnd: fileSize(*dbPath),
		ServerPID:  pid,
		Upstream:   upstreamURL,
		IdleRSS:    idleRSS,
		IdleHWM:    idleHWM,
		SeedNote: "Las tablas escalables del dataset son rate_limits y events, que están en el " +
			"camino caliente de cada petición (CheckRateLimit y LogEvent). Usuarios y sesiones " +
			"se quedan en 3 a propósito: un proxy inverso real no tiene un millón de usuarios, " +
			"el volumen de clientes se representa con IPs virtuales.",
		Profiles: map[string]any{
			"health": "GET /health. MainHandler responde antes del SecurityEngine: acota el " +
				"coste de la capa de seguridad por diferencia respecto al perfil proxy.",
			"proxy": "GET / con Host perf.local (servicio is_public=1): SecurityEngine " +
				"completo (geo + fail2ban + rate limit + WAF) más el proxy real hacia el upstream.",
			"auth": "POST /REGIO-login con user/pass válidos: mide Argon2 (VerifyPassword) más " +
				"la escritura en events y sessions de cada intento. No se usa como medida de throughput.",
		},
		Phases: results,
	}

	out := *outJSON
	if out == "" {
		if err := os.MkdirAll("perf", 0o755); err != nil {
			fatal("creando perf/: %v", err)
		}
		out = filepath.Join("perf", "load-"+time.Now().Format("20060102-150405")+".json")
	}
	blob, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fatal("serializando: %v", err)
	}
	if err := os.WriteFile(out, blob, 0o644); err != nil {
		fatal("escribiendo %s: %v", out, err)
	}
	fmt.Printf("\n  DB tras carga   %.1f MiB (+%.1f MiB)\n",
		mib(rep.DBBytesEnd), mib(rep.DBBytesEnd-rep.DBBytes))
	fmt.Printf("  resultados      %s\n", out)
}

// ---------------------------------------------------------------------------
// Upstream dummy: destino real de las peticiones proxificadas.
// ---------------------------------------------------------------------------

func startUpstream() (*http.Server, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true,"items":[]}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "upstream ok\n")
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln) //nolint:errcheck // el error de Serve solo importa al apagar
	return srv, "http://" + ln.Addr().String(), nil
}

// ---------------------------------------------------------------------------
// Base de datos: registra un servicio público que apunta al upstream dummy.
//
// is_public=1 para que el perfil `proxy` mida el proxy y no el login: el KDF se
// mide aparte en el perfil `auth`. RefreshAllowedNetworks mete la IP del target
// en la lista blanca, así que 127.0.0.1 pasa el dial anti-SSRF sin tocar env.
// ---------------------------------------------------------------------------

func prepareDB(path, upstreamURL string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no existe (ejecuta `make seed` antes): %w", err)
	}
	DB, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer DB.Close()

	_, err = DB.Exec(
		`INSERT OR REPLACE INTO servicios
		 (host, target, is_public, bypass_header, csp, geo_mode, geo_countries)
		 VALUES ('perf.local', ?, 1, '', '', '', '')`,
		upstreamURL)
	return err
}

// ---------------------------------------------------------------------------
// Servidor bajo prueba
// ---------------------------------------------------------------------------

func startServer() (*exec.Cmd, error) {
	cmd := exec.Command(*binary)
	cmd.Env = append(os.Environ(),
		"REGIO_DB_PATH="+*dbPath,
		"MASTER_KEY="+*masterKey,
		"ADMIN_DOMAIN="+*adminDom,
		fmt.Sprintf("PORT=%d", *port),
		// Necesario para que getRealIP acepte X-Forwarded-For y el generador
		// pueda repartir la carga entre IPs virtuales.
		"TRUSTED_PROXIES=127.0.0.1",
		"GEO_MODE=off",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func stopServer(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	// Grupo de procesos propio: si regio lanza hijos, se.signalizan juntos.
	syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }() //nolint:errcheck
	select {
	case <-done:
	case <-time.After(12 * time.Second):
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

func waitHealthy(base string, timeout time.Duration) error {
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequest("GET", base+"/health", nil)
		if err != nil {
			last = err
		} else {
			req.Host = *adminDom
			resp, err := client.Do(req)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
				last = fmt.Errorf("status %d", resp.StatusCode)
			} else {
				last = err
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	if last == nil {
		last = fmt.Errorf("timeout")
	}
	return last
}

// ---------------------------------------------------------------------------
// RSS: VmRSS actual y VmHWM pico desde el arranque del proceso.
// ---------------------------------------------------------------------------

func sampleRSS(pid int, stop <-chan struct{}, out chan<- sample) {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			rss, hwm := readRSS(pid)
			if rss == 0 {
				continue
			}
			select {
			case out <- sample{ts: time.Now(), rss: rss, hwm: hwm}:
			default: // el consumidor va lento: se descarta, no se bloquea el sampler
			}
		}
	}
}

func readRSS(pid int) (rss, hwm int64) {
	blob, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(blob), "\n") {
		switch {
		case strings.HasPrefix(line, "VmRSS:"):
			rss = parseKB(line)
		case strings.HasPrefix(line, "VmHWM:"):
			hwm = parseKB(line)
		}
	}
	return rss, hwm
}

func parseKB(line string) int64 {
	f := strings.Fields(line)
	if len(f) < 2 {
		return 0
	}
	v, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return 0
	}
	return v * 1024 // kB → bytes
}

func peakOf(samples []sample) int64 {
	var peak int64
	for _, s := range samples {
		if s.rss > peak {
			peak = s.rss
		}
		if s.hwm > peak {
			peak = s.hwm
		}
	}
	return peak
}

// ---------------------------------------------------------------------------
// Fases
// ---------------------------------------------------------------------------

func buildPhases() []phase {
	profs := splitList(*profiles)
	lvls := splitInts(*levels)

	total := len(profs) * len(lvls)
	perPhase := *ipPool / total
	if perPhase < 64 {
		perPhase = 64
	}
	// CheckRateLimit aborta con "demasiadas peticiones" si más de 10.000 IPs
	// quedan registradas sin limpiar, y la limpieza solo borra IPs con 10 min
	// de inactividad. Es un techo duro del diseño, no del generador.
	if total*perPhase > 9500 {
		fmt.Printf("  ⚠ %d IPs/fase × %d fases = %d, sobre el techo de 10.000 de "+
			"CheckRateLimit: aparecerán 429 espurios. Baja -ip-pool.\n",
			perPhase, total, total*perPhase)
	}

	phases := make([]phase, 0, total)
	idx := 0
	for _, p := range profs {
		for _, l := range lvls {
			phases = append(phases, phase{
				profile: p,
				level:   l,
				ips:     makeIPBlock(idx*perPhase, perPhase),
			})
			idx++
		}
	}
	return phases
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitInts(s string) []int {
	var out []int
	for _, l := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(l)); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	return out
}

// makeIPBlock genera IPs de 198.18.0.0/15 (RFC 2544): global unicast para
// regio, nunca enrutable de verdad y ausente de banned_ips. Cada fase recibe un
// bloque DISJOJO para que la ventana de 60 s del rate limiter no arrastre el
// consumo de la fase anterior.
func makeIPBlock(base, n int) []string {
	ips := make([]string, n)
	for i := 0; i < n; i++ {
		v := base + i
		ips[i] = fmt.Sprintf("198.18.%d.%d", (v/254)%256, v%254+1)
	}
	return ips
}

// ---------------------------------------------------------------------------
// Ejecución de una fase
// ---------------------------------------------------------------------------

type stats struct {
	reqs  atomic.Int64
	errs  atomic.Int64
	s429  atomic.Int64
	s5xx  atomic.Int64
	s4xx  atomic.Int64
	codes sync.Map // status code (string) -> *atomic.Int64
	mu    sync.Mutex
	lat   []time.Duration
}

// noteCode registra el código de estado. Sin el desglose por código, un 4xx
// global no dice si es el WAF, el rate limiter o la validación de la sesión.
func (s *stats) noteCode(code int) {
	key := strconv.Itoa(code)
	v, _ := s.codes.LoadOrStore(key, new(atomic.Int64))
	v.(*atomic.Int64).Add(1)
}

// codeBreakdown devuelve los códigos no 2xx más frecuentes, para el informe.
func (s *stats) codeBreakdown() map[string]int64 {
	out := map[string]int64{}
	s.codes.Range(func(k, v any) bool {
		key := k.(string)
		if strings.HasPrefix(key, "2") {
			return true
		}
		out[key] = v.(*atomic.Int64).Load()
		return true
	})
	return out
}

func runPhase(base string, pid int, ph phase) phaseResult {
	stop := make(chan struct{})
	samplesCh := make(chan sample, 8192)
	go sampleRSS(pid, stop, samplesCh)

	if *warmup > 0 {
		s := &stats{}
		runWorkers(base, ph, s, *warmup)
		time.Sleep(250 * time.Millisecond)
	}

	c := &stats{}
	res := phaseResult{Profile: ph.profile, Level: ph.level}
	res.RSSStartBytes, _ = readRSS(pid)

	t0 := time.Now()
	runWorkers(base, ph, c, *duration)
	elapsed := time.Since(t0)

	res.RSSEndBytes, _ = readRSS(pid)
	time.Sleep(120 * time.Millisecond) // última muestra antes de cortar el sampler
	close(stop)
	res.RSSPeakBytes = peakOf(drain(samplesCh))

	res.Requests = c.reqs.Load()
	res.Errors = c.errs.Load()
	res.Status429 = c.s429.Load()
	res.Status5xx = c.s5xx.Load()
	res.Status4xx = c.s4xx.Load()
	res.Codes = c.codeBreakdown()
	res.RPS = float64(res.Requests) / elapsed.Seconds()
	res.Duration = elapsed.Round(time.Millisecond).String()
	res.RSSDeltaBytes = res.RSSEndBytes - res.RSSStartBytes

	c.mu.Lock()
	sort.Slice(c.lat, func(i, j int) bool { return c.lat[i] < c.lat[j] })
	res.LatP50Ms = pctMs(c.lat, 0.50)
	res.LatP95Ms = pctMs(c.lat, 0.95)
	res.LatP99Ms = pctMs(c.lat, 0.99)
	if n := len(c.lat); n > 0 {
		res.LatMaxMs = float64(c.lat[n-1].Microseconds()) / 1000
	}
	c.mu.Unlock()

	return res
}

func runWorkers(base string, ph phase, c *stats, d time.Duration) {
	var wg sync.WaitGroup
	deadline := time.Now().Add(d)
	for w := 0; w < ph.level; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			client := newClient()
			i := 0
			for time.Now().Before(deadline) {
				i++
				ip := ph.ips[(worker*7+i)%len(ph.ips)]
				status, dur, err := fire(client, base, ph.profile, ip)
				if err != nil {
					c.errs.Add(1)
					continue
				}
				c.reqs.Add(1)
				c.noteCode(status)
				switch {
				case status == http.StatusTooManyRequests:
					c.s429.Add(1)
					c.errs.Add(1)
				case status >= 500:
					c.s5xx.Add(1)
					c.errs.Add(1)
				case status >= 400:
					c.s4xx.Add(1)
					c.errs.Add(1)
				}
				c.mu.Lock()
				c.lat = append(c.lat, dur)
				c.mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
}

// fire ejecuta una petición del perfil indicado y devuelve status y latencia.
func fire(client *http.Client, base, profile, ip string) (int, time.Duration, error) {
	var (
		req *http.Request
		err error
	)

	switch profile {
	case "health":
		req, err = http.NewRequest("GET", base+"/health", nil)
		if err == nil {
			req.Host = *adminDom
		}
	case "auth":
		form := url.Values{"user": {"admin"}, "pass": {"SeedPass123!"}}
		req, err = http.NewRequest("POST", base+"/REGIO-login", strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Host = *adminDom
		}
	default: // "proxy"
		req, err = http.NewRequest("GET", base+"/", nil)
		if err == nil {
			req.Host = "perf.local"
		}
	}
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", "regio-loadgen/1.0")

	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, time.Since(t0), err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, time.Since(t0), nil
}

func newClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		// Sin seguir redirecciones: un login válido responde 303 hacia "/", y si
		// el cliente lo siguiera acabaría pidiendo el panel de administración sin
		// cookie (el generador no gestiona cookies) y mediría un 401 falso en
		// lugar del Argon2 que interesta.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			MaxIdleConns:        8192,
			MaxIdleConnsPerHost: 8192,
			MaxConnsPerHost:     8192,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

func pctMs(sorted []time.Duration, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return float64(sorted[idx].Microseconds()) / 1000
}

// formatCodes ordena el desglose por frecuencia para que la primera línea sea
// siempre el error dominante.
func formatCodes(codes map[string]int64) string {
	type kv struct {
		code string
		n    int64
	}
	list := make([]kv, 0, len(codes))
	for c, n := range codes {
		list = append(list, kv{c, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].code < list[j].code
	})
	parts := make([]string, 0, len(list))
	for _, e := range list {
		parts = append(parts, fmt.Sprintf("%s×%d", e.code, e.n))
	}
	return strings.Join(parts, " ")
}

func drain(ch chan sample) []sample {
	var out []sample
	for {
		select {
		case s := <-ch:
			out = append(out, s)
		default:
			return out
		}
	}
}

// ---------------------------------------------------------------------------
// Salida
// ---------------------------------------------------------------------------

func printPhase(r phaseResult) {
	fmt.Printf("\n  [%s] concurrencia=%-4d ventana=%s\n", r.Profile, r.Level, r.Duration)
	fmt.Printf("    req/s %-9.0f  p50 %-7.2fms  p95 %-7.2fms  p99 %-7.2fms  max %-7.2fms\n",
		r.RPS, r.LatP50Ms, r.LatP95Ms, r.LatP99Ms, r.LatMaxMs)
	fmt.Printf("    req %-10d err %-8d (429 %d, 5xx %d, 4xx %d)\n",
		r.Requests, r.Errors, r.Status429, r.Status5xx, r.Status4xx)
	if len(r.Codes) > 0 {
		fmt.Printf("    códigos       %s\n", formatCodes(r.Codes))
	}
	fmt.Printf("    RSS inicio %.1f MiB → fin %.1f MiB (pico %.1f MiB, delta %+.1f MiB)\n",
		mib(r.RSSStartBytes), mib(r.RSSEndBytes), mib(r.RSSPeakBytes), mib(r.RSSDeltaBytes))
}

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func mib(b int64) float64 { return float64(b) / (1024 * 1024) }

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "loadgen: "+format+"\n", args...)
	os.Exit(1)
}
