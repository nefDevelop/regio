package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"time"

	"regio/internal/auth"

	_ "modernc.org/sqlite"
)

var dbPath = "./data/REGIO_TEST.db"

func init() {
	if p := os.Getenv("REGIO_DB_PATH"); p != "" {
		dbPath = p
	}
}

func main() {
	if _, err := os.Stat(dbPath); err == nil {
		fmt.Printf("[WARN] %s ya existe. Usa --force para sobrescribir.\n", dbPath)
		for _, a := range os.Args[1:] {
			if a == "--force" {
				goto proceed
			}
		}
		fmt.Println("Omitiendo. Ejecuta: go run ./cmd/seed --force")
		return
	}
proceed:
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
	seedData(DB)

	fmt.Printf("\n[OK] Base de datos de prueba creada: %s\n", dbPath)
	fmt.Println("[INFO] Ejecuta: make run-dbtest")
	fmt.Println()
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
			timestamp DATETIME NOT NULL
		)`,
	}
	for _, d := range ddl {
		if _, err := DB.Exec(d); err != nil {
			log.Fatalf("Error creando tabla: %v\nSQL: %s", err, d)
		}
	}
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip, timestamp)")
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
	for _, e := range eventos {
		ts := now.Add(-time.Duration(e.minutesAgo) * time.Minute)
		DB.Exec("INSERT INTO events (timestamp, message, performer) VALUES (?, ?, ?)",
			ts, e.msg, e.performer)
	}
	fmt.Printf("  • %d eventos\n", len(eventos))

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

	for i := 0; i < 50; i++ {
		DB.Exec("INSERT INTO rate_limits (ip, timestamp) VALUES ('45.33.32.156', ?)",
			now.Add(-time.Duration(30+i)*time.Second))
	}
	for i := 0; i < 20; i++ {
		DB.Exec("INSERT INTO rate_limits (ip, timestamp) VALUES ('91.121.89.12', ?)",
			now.Add(-time.Duration(60+i)*time.Second))
	}
	fmt.Println("  • Rate limits históricos")
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
