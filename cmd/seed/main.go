package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"regio/internal/auth"

	_ "modernc.org/sqlite"
)

var dbPath = "./data/REGIO_TEST.db"

// Flags de volumen. Los valores por defecto reproducen exactamente el seed
// original (70 rate_limits, 20 eventos) para no alterar `make run-dbtest`.
// `make seed SEED_N=100000` escala las tablas del camino caliente de cada petición:
// rate_limits (lectura/escritura en CheckRateLimit) y events (LogEvent por request).
var (
	flagForce      = flag.Bool("force", false, "Sobrescribe la base de datos si ya existe")
	flagRateLimits = flag.Int("rate-limits", 70, "Filas totales en rate_limits (hot path del rate limiter)")
	flagEvents     = flag.Int("events", 20, "Filas totales en events (log de auditoría)")
)

func init() {
	if p := os.Getenv("REGIO_DB_PATH"); p != "" {
		dbPath = p
	}
}

func main() {
	flag.Parse()

	if _, err := os.Stat(dbPath); err == nil && !*flagForce {
		fmt.Printf("[WARN] %s ya existe. Usa --force para sobrescribir.\n", dbPath)
		return
	}
	os.Remove(dbPath)
	os.MkdirAll("./data", 0750)

	DB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatalf("Error abriendo DB: %v", err)
	}
	defer DB.Close()

	DB.Exec("PRAGMA journal_mode=WAL")
	DB.Exec("PRAGMA busy_timeout=5000")
	DB.Exec("PRAGMA foreign_keys=ON")

	createTables(DB)
	t0 := time.Now()
	seedData(DB)
	elapsed := time.Since(t0)

	fmt.Printf("\n[OK] Base de datos de prueba creada: %s (%.1fs)\n", dbPath, elapsed.Seconds())
	printDatasetSummary(DB)
	fmt.Println("[INFO] Ejecuta: make run-dbtest")
	fmt.Println()
}

// printDatasetSummary informa del volumen real y del tamaño en disco: sin esto no
// se puede atribuir un resultado de carga al tamaño del dataset que lo produjo.
func printDatasetSummary(DB *sql.DB) {
	for _, t := range []string{"users", "sessions", "servicios", "rate_limits", "events", "csp_reports"} {
		var n int
		if err := DB.QueryRow("SELECT COUNT(*) FROM " + t).Scan(&n); err != nil {
			continue
		}
		fmt.Printf("    %-12s %d filas\n", t, n)
	}
	if fi, err := os.Stat(dbPath); err == nil {
		fmt.Printf("    %-12s %.1f MiB\n", "db", float64(fi.Size())/(1024*1024))
	}
}

func createTables(DB *sql.DB) {
	ddl := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE,
			password_hash TEXT,
			totp_secret TEXT,
			invite_token TEXT,
			is_admin BOOLEAN DEFAULT 0,
			totp_active BOOLEAN DEFAULT 0,
			totp_last_epoch INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			message TEXT,
			performer TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS banned_ips (
			ip TEXT PRIMARY KEY,
			hasta DATETIME,
			razon TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			user_id INTEGER,
			csrf_token TEXT,
			ip TEXT,
			user_agent TEXT,
			last_active DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS app_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			name TEXT,
			token_hash TEXT UNIQUE,
			scopes TEXT,
			last_used DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS servicios (
			host TEXT PRIMARY KEY,
			target TEXT NOT NULL,
			is_public BOOLEAN DEFAULT 0,
			bypass_header TEXT DEFAULT '',
			csp TEXT DEFAULT '',
			geo_mode TEXT DEFAULT '',
			geo_countries TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS csp_reports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			host TEXT,
			blocked_uri TEXT,
			violated_directive TEXT,
			original_policy TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS bypass_keys (
			token TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			host TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			migrated INTEGER DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS rate_limits (
			ip TEXT NOT NULL,
			host TEXT NOT NULL DEFAULT '',
			timestamp DATETIME NOT NULL
		)`,
	}
	for _, d := range ddl {
		if _, err := DB.Exec(d); err != nil {
			log.Fatalf("Error creando tabla: %v\nSQL: %s", err, d)
		}
	}
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip, host, timestamp)")
	DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_rate_limits_unique ON rate_limits(ip, host, timestamp)")
}

func seedData(DB *sql.DB) {
	now := time.Now()

	services := []struct {
		host, target string
		public       bool
		bypass       string
		csp          string
	}{
		{"app.midominio.com", "http://10.0.0.10:3000", false, "", ""},
		{"grafana.midominio.com", "http://10.0.0.11:3000", false, "", ""},
		{"blog.midominio.com", "http://10.0.0.12:8080", true, "", "default-src 'self'; img-src 'self' https://images.example.com"},
		{"status.midominio.com", "http://10.0.0.13:80", true, "", ""},
		{"api.externa.com", "http://192.168.1.50:9000", false, "X-Internal:secret123", ""},
	}
	for _, s := range services {
		DB.Exec("INSERT OR IGNORE INTO servicios (host, target, is_public, bypass_header, csp) VALUES (?, ?, ?, ?, ?)",
			s.host, s.target, s.public, s.bypass, s.csp)
	}
	fmt.Println("  • 5 servicios configurados")

	users := []struct {
		id         int
		username   string
		password   string
		isAdmin    bool
		totpActive bool
	}{
		{1, "admin", "SeedPass123!", true, false},
		{2, "devops", "SeedPass456!", true, false},
		{3, "lector", "SeedPass789!", false, false},
	}
	for _, u := range users {
		pwHash := auth.HashPassword(u.password)
		totpRaw := auth.GenerateTOTPSecret()
		totpEnc, _ := auth.Encrypt(totpRaw)
		totpActive := boolInt(u.totpActive)
		isAdmin := boolInt(u.isAdmin)
		DB.Exec("INSERT OR IGNORE INTO users (id, username, password_hash, totp_secret, is_admin, totp_active) VALUES (?, ?, ?, ?, ?, ?)",
			u.id, u.username, pwHash, totpEnc, isAdmin, totpActive)
	}
	fmt.Println("  • 3 usuarios (admin/devops/lector, pass: SeedPassXXX!)")

	sessions := []struct {
		userID   int
		ip       string
		agent    string
		minutesAgo int
	}{
		{1, "192.168.1.100", "Mozilla/5.0 Chrome/120", 5},
		{2, "10.0.0.50", "Mozilla/5.0 Firefox/121", 45},
		{3, "172.16.0.10", "curl/8.4", 120},
	}
	for _, s := range sessions {
		raw := randomToken(32)
		hash := sha256Hex(raw)
		csrf := randomToken(32)
		lastActive := now.Add(-time.Duration(s.minutesAgo) * time.Minute)
		DB.Exec("INSERT OR IGNORE INTO sessions (token, user_id, csrf_token, ip, user_agent, last_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			hash, s.userID, csrf, s.ip, s.agent, lastActive, lastActive.Add(-30*time.Minute))
	}
	fmt.Println("  • 3 sesiones activas")

	appTokenData := []struct {
		userID int
		name   string
		daysAgo int
	}{
		{1, "CI/CD Deploy", 60},
		{2, "Monitor API", 30},
		{1, "Mobile App", 90},
	}
	for _, t := range appTokenData {
		raw := randomToken(32)
		hash := sha256Hex(raw)
		lastUsed := now.Add(-time.Duration(t.daysAgo) * 24 * time.Hour)
		DB.Exec("INSERT OR IGNORE INTO app_tokens (user_id, name, token_hash, last_used, created_at) VALUES (?, ?, ?, ?, ?)",
			t.userID, t.name, hash, lastUsed, lastUsed)
	}
	fmt.Println("  • 3 app tokens")

	bypassData := []struct{ token, name, host string }{
		{randomToken(32), "Webhook GitHub", "api.externa.com"},
		{randomToken(32), "Health Check", "status.midominio.com"},
	}
	for _, b := range bypassData {
		tokenHash := sha256Hex(b.token)
		DB.Exec("INSERT OR IGNORE INTO bypass_keys (token, name, host, created_at, migrated) VALUES (?, ?, ?, ?, 1)",
			tokenHash, b.name, b.host, now)
	}
	fmt.Println("  • 2 bypass keys")

	bannedData := []struct {
		ip       string
		minutes int
		reason   string
	}{
		{"45.33.32.156", 10, "Fuerza bruta SSH"},
		{"185.220.101.0/24", 55, "Ataque múltiple desde rango"},
		{"91.121.89.12", 2, "Fuerza bruta individual"},
		{"10.0.0.99", 30, "Bloqueo manual del administrador"},
		{"203.0.113.42", 5, "Escaneo de puertos"},
	}
	for _, b := range bannedData {
		hasta := now.Add(time.Duration(b.minutes) * time.Minute)
		DB.Exec("INSERT OR REPLACE INTO banned_ips (ip, hasta, razon) VALUES (?, ?, ?)",
			b.ip, hasta, b.reason)
	}
	fmt.Println("  • 5 IPs/rangos bloqueados")

	eventos := []struct {
		msg, performer string
		minutesAgo     int
	}{
		{"[OK] Inicio de sesión exitoso: admin (192.168.1.100)", "admin", 5},
		{"[OK] Inicio de sesión exitoso: devops (10.0.0.50)", "devops", 45},
		{"[OK] Inicio de sesión exitoso: lector (172.16.0.10)", "lector", 120},
		{"[SCAN] Intento de login para usuario: admin desde 45.33.32.156", "Sistema", 12},
		{"[BLOCK] IP BLOQUEADA (Fuerza bruta): 45.33.32.156", "Sistema", 11},
		{"[BLOCK] RANGO BLOQUEADO (Ataque múltiple): 185.220.101.0/24", "Sistema", 56},
		{"[WARN] Intento de acceso a usuario sin contraseña sin token válido: unknown", "Sistema", 8},
		{"[PASS] Puente añadido: app.midominio.com -> http://10.0.0.10:3000 (Público: false)", "admin", 180},
		{"[PASS] Puente añadido: grafana.midominio.com -> http://10.0.0.11:3000 (Público: false)", "admin", 175},
		{"[PASS] Puente añadido: blog.midominio.com -> http://10.0.0.12:8080 (Público: true)", "admin", 170},
		{"[PASS] Puente añadido: status.midominio.com -> http://10.0.0.13:80 (Público: true)", "admin", 165},
		{"[PASS] Puente añadido: api.externa.com -> http://192.168.1.50:9000 (Público: false)", "admin", 160},
		{"[USER] Usuario creado: devops", "admin", 150},
		{"[USER] Usuario creado: lector", "admin", 145},
		{"[KEY] Bypass key creada: Webhook GitHub para host api.externa.com", "admin", 140},
		{"[KEY] Bypass key creada: Health Check para host status.midominio.com", "admin", 135},
		{"[KEY] App Token creado: CI/CD Deploy para el usuario: admin", "admin", 130},
		{"[KEY] App Token creado: Monitor API para el usuario: devops", "devops", 125},
		{"[BLOCK] IP/Rango bloqueado manualmente: 10.0.0.99", "admin", 31},
		{"[WARN] Bloqueo CSP en app.midominio.com: https://tracker.example.com/pixel.gif (Directiva: img-src)", "Sistema", 20},
	}
	// Los 21 eventos curados cubren los escenarios que lee el panel. Si se pide
	// un volumen mayor, se completa con plantillas rotadas para que el índice de
	// `events` tenga la misma profundidad que en producción.
	bulk := *flagEvents - len(eventos)
	if bulk < 0 {
		bulk = 0
	}
	for _, e := range eventos {
		ts := now.Add(-time.Duration(e.minutesAgo) * time.Minute)
		DB.Exec("INSERT INTO events (timestamp, message, performer) VALUES (?, ?, ?)",
			ts, e.msg, e.performer)
	}
	if bulk > 0 {
		n, err := insertBulkEvents(DB, now, len(eventos), bulk)
		if err != nil {
			log.Fatalf("Error sembrando eventos: %v", err)
		}
		fmt.Printf("  • %d eventos curados + %d generados\n", len(eventos), n)
	} else {
		fmt.Printf("  • %d eventos\n", len(eventos))
	}

	cspData := []struct {
		host, blocked, directive, policy string
		daysAgo                          int
	}{
		{"app.midominio.com", "https://tracker.example.com/pixel.gif", "img-src", "default-src 'self'; img-src 'self'", 2},
		{"app.midominio.com", "https://fonts.unknown.com/roboto.woff2", "font-src", "default-src 'self'", 5},
		{"blog.midominio.com", "https://analytics.evil.com/collect", "connect-src", "default-src 'self'", 1},
	}
	for _, c := range cspData {
		ts := now.Add(-time.Duration(c.daysAgo) * 24 * time.Hour)
		DB.Exec("INSERT INTO csp_reports (host, blocked_uri, violated_directive, original_policy, created_at) VALUES (?, ?, ?, ?, ?)",
			c.host, c.blocked, c.directive, c.policy, ts)
	}
	fmt.Println("  • 3 CSP reports")

	// Rate limits: los 70 históricos (50 + 20) sobre las dos IPs conocidas se
	// conservan tal cual para no alterar el seed original. El resto del volumen
	// se reparte sobre un pool sintético para que CheckRateLimit no mida siempre
	// las mismas dos claves. Todo con columna host: el limiter agrupa por
	// (IP, servicio) y sin host las filas solo alimentarían el techo global.
	legacy := []struct {
		ip   string
		host string
		n    int
		off  int
	}{
		{"45.33.32.156", "blog.midominio.com", 50, 30},
		{"91.121.89.12", "app.midominio.com", 20, 60},
	}
	inserted := 0
	for _, l := range legacy {
		if inserted >= *flagRateLimits {
			break
		}
		for i := 0; i < l.n && inserted < *flagRateLimits; i++ {
			DB.Exec("INSERT INTO rate_limits (ip, host, timestamp) VALUES (?, ?, ?)",
				l.ip, l.host, now.Add(-time.Duration(l.off+i)*time.Second))
			inserted++
		}
	}
	if rest := *flagRateLimits - inserted; rest > 0 {
		n, err := insertBulkRateLimits(DB, now, inserted, rest)
		if err != nil {
			log.Fatalf("Error sembrando rate limits: %v", err)
		}
		inserted += n
	}
	fmt.Printf("  • %d rate limits\n", inserted)
}

// insertBulkEvents genera `count` filas de auditoría adicionales. Se hace con
// transacción y statement preparado porque a escala 1M el_exec por fila domina
// el tiempo total del seed.
func insertBulkEvents(DB *sql.DB, now time.Time, offset, count int) (int, error) {
	templates := []string{
		"[OK] Inicio de sesión exitoso: %s desde 10.%d.%d.%d",
		"[PASS] Puente consultado: app.midominio.com -> http://10.0.0.10:3000",
		"[OUT] GET /static/css/style.css (Host: app.midominio.com)",
		"[OUT] GET /api/health (Host: api.externa.com)",
		"[OK] Token de app verificado: Monitor API",
		"[WARN] CSP aplicado con report-uri en blog.midominio.com",
	}
	users := []string{"admin", "devops", "lector", "sistema"}

	tx, err := DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO events (timestamp, message, performer) VALUES (?, ?, ?)")
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for i := 0; i < count; i++ {
		n := offset + i
		ts := now.Add(-time.Duration(n) * time.Second)
		tpl := templates[n%len(templates)]
		performer := users[n%len(users)]
		var msg string
		if n%len(templates) == 0 {
			msg = fmt.Sprintf(tpl, performer, n%250, (n/250)%250, n%254)
		} else {
			msg = tpl
		}
		if _, err := stmt.Exec(ts, msg, performer); err != nil {
			return i, err
		}
	}
	return count, tx.Commit()
}

// insertBulkRateLimits reparte `count` filas sobre el rango de benchmark
// 198.18.0.0/15 (RFC 2544): público y enrutable en apariencia, nunca enrutable de
// verdad, y ausente de banned_ips.
func insertBulkRateLimits(DB *sql.DB, now time.Time, offset, count int) (int, error) {
	tx, err := DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO rate_limits (ip, host, timestamp) VALUES (?, ?, ?)")
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	// El pool sintético rota servicios para que las cargas por (IP, servicio)
	// encuentren filas, no solo el techo global.
	hosts := []string{"blog.midominio.com", "app.midominio.com"}
	for i := 0; i < count; i++ {
		n := offset + i
		ip := fmt.Sprintf("198.18.%d.%d", (n/64)%256, n%64+1)
		ts := now.Add(-time.Duration(n%3600) * time.Second)
		if _, err := stmt.Exec(ip, hosts[n%len(hosts)], ts); err != nil {
			return i, err
		}
	}
	return count, tx.Commit()
}

func randomToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256Hex(data string) string {
	h := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(h[:])
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
