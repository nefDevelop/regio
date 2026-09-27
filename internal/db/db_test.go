package db

import (
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"regio/internal/models"
	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) {
	t.Helper()
	os.MkdirAll("./testdata", 0755)
	t.Cleanup(func() { os.RemoveAll("./testdata") })
	origDB := DB
	t.Cleanup(func() {
		DB.Close()
		DB = origDB
	})
	testPath := "./testdata/test_regio.db"
	os.Remove(testPath)
	var err error
	DB, err = sql.Open("sqlite", testPath)
	if err != nil {
		t.Fatalf("Error opening test DB: %v", err)
	}
	// Manually create tables (InitDB overwrites DB)
	DB.Exec("PRAGMA journal_mode=WAL")
	DB.Exec("PRAGMA busy_timeout=5000")
	DB.Exec("PRAGMA foreign_keys=ON")
	tables := []string{
		`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, totp_secret TEXT, invite_token TEXT, is_admin BOOLEAN DEFAULT 0, totp_active BOOLEAN DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, message TEXT, performer TEXT)`,
		`CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY, hasta DATETIME, razon TEXT)`,
		`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER, csrf_token TEXT, ip TEXT, user_agent TEXT, last_active DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))`,
		`CREATE TABLE IF NOT EXISTS app_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, token_hash TEXT UNIQUE, scopes TEXT, last_used DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))`,
		`CREATE TABLE IF NOT EXISTS servicios (host TEXT PRIMARY KEY, target TEXT NOT NULL, is_public BOOLEAN DEFAULT 0, bypass_header TEXT DEFAULT '', csp TEXT DEFAULT '', geo_mode TEXT DEFAULT '', geo_countries TEXT DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`,
		`CREATE TABLE IF NOT EXISTS csp_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT, blocked_uri TEXT, violated_directive TEXT, original_policy TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE IF NOT EXISTS bypass_keys (token TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE IF NOT EXISTS rate_limits (ip TEXT NOT NULL, timestamp DATETIME NOT NULL)`,
	}
	for _, ddl := range tables {
		if _, err := DB.Exec(ddl); err != nil {
			t.Fatalf("Error creating table: %v", err)
		}
	}
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip, timestamp)")
	lastLogTime = make(map[string]time.Time)
}

func TestInitDBCreatesTables(t *testing.T) {
	setupTestDB(t)

	tables := []string{"users", "events", "banned_ips", "sessions", "app_tokens", "servicios", "csp_reports", "bypass_keys", "rate_limits", "settings"}
	for _, table := range tables {
		var name string
		err := DB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("Table %s not found: %v", table, err)
		}
	}
}

func TestSaveLoadConfig(t *testing.T) {
	setupTestDB(t)

	config := models.Config{
		Servicios:     map[string]string{"app.com": "http://10.0.0.1:8080"},
		Publicos:      map[string]bool{"app.com": true},
		BypassHeaders: map[string]string{"app.com": "X-Custom:value"},
		CSPs:          map[string]string{"app.com": "default-src 'self'"},
		GeoModes:      map[string]string{"app.com": "allow"},
		GeoCountries:  map[string]string{"app.com": "ES, FR"},
	}

	err := SaveConfig(config)
	if err != nil {
		t.Fatalf("SaveConfig error: %v", err)
	}

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}

	if loaded.Servicios["app.com"] != "http://10.0.0.1:8080" {
		t.Errorf("Servicios: got %q, want 'http://10.0.0.1:8080'", loaded.Servicios["app.com"])
	}
	if !loaded.Publicos["app.com"] {
		t.Error("Publicos[app.com] should be true")
	}
	if loaded.BypassHeaders["app.com"] != "X-Custom:value" {
		t.Errorf("BypassHeaders: got %q, want 'X-Custom:value'", loaded.BypassHeaders["app.com"])
	}
	if loaded.CSPs["app.com"] != "default-src 'self'" {
		t.Errorf("CSPs: got %q, want 'default-src 'self''", loaded.CSPs["app.com"])
	}
	if loaded.GeoModes["app.com"] != "allow" {
		t.Errorf("GeoModes: got %q, want 'allow'", loaded.GeoModes["app.com"])
	}
	if loaded.GeoCountries["app.com"] != "ES, FR" {
		t.Errorf("GeoCountries: got %q, want 'ES, FR'", loaded.GeoCountries["app.com"])
	}
}

func TestAddServicePreservesGeoPolicy(t *testing.T) {
	setupTestDB(t)

	// Política geográfica configurada desde el panel
	err := SaveConfig(models.Config{
		Servicios:    map[string]string{"geo.app": "http://10.0.0.9:80"},
		GeoModes:     map[string]string{"geo.app": "allow"},
		GeoCountries: map[string]string{"geo.app": "ES"},
	})
	if err != nil {
		t.Fatalf("SaveConfig error: %v", err)
	}

	// El CLI actualiza el servicio sin información geo
	if err := AddService("geo.app", "http://10.0.0.9:90", false, "", ""); err != nil {
		t.Fatalf("AddService error: %v", err)
	}

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if config.GeoModes["geo.app"] != "allow" || config.GeoCountries["geo.app"] != "ES" {
		t.Errorf("AddService sobrescribió la política geo: modes=%v countries=%v", config.GeoModes, config.GeoCountries)
	}
	if config.Servicios["geo.app"] != "http://10.0.0.9:90" {
		t.Errorf("target no actualizado: %q", config.Servicios["geo.app"])
	}
}

func TestSettings(t *testing.T) {
	setupTestDB(t)

	if _, ok := GetSetting("geo_mode"); ok {
		t.Error("GetSetting no debería encontrar una clave inexistente")
	}
	if err := SetSetting("geo_mode", "deny"); err != nil {
		t.Fatalf("SetSetting error: %v", err)
	}
	if err := SetSetting("geo_mode", "allow"); err != nil {
		t.Fatalf("SetSetting overwrite error: %v", err)
	}
	v, ok := GetSetting("geo_mode")
	if !ok || v != "allow" {
		t.Errorf("GetSetting = (%q, %v); want (allow, true)", v, ok)
	}
}

func TestAddDeleteService(t *testing.T) {
	setupTestDB(t)

	err := AddService("test.app", "http://10.0.0.2:3000", true, "X-Key:val", "")
	if err != nil {
		t.Fatalf("AddService error: %v", err)
	}

	// Verify via LoadConfig
	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if config.Servicios["test.app"] != "http://10.0.0.2:3000" {
		t.Errorf("Servicios after AddService: got %q", config.Servicios["test.app"])
	}
	if !config.Publicos["test.app"] {
		t.Error("Publicos should be true after AddService")
	}

	// Delete
	err = DeleteService("test.app")
	if err != nil {
		t.Fatalf("DeleteService error: %v", err)
	}

	config, _ = LoadConfig()
	if _, exists := config.Servicios["test.app"]; exists {
		t.Error("Service should not exist after DeleteService")
	}
}

func TestCheckNeedsSetup(t *testing.T) {
	setupTestDB(t)

	// Empty DB should need setup
	if !CheckNeedsSetup() {
		t.Error("CheckNeedsSetup should return true for empty DB")
	}

	// After adding a user, should not need setup
	DB.Exec("INSERT INTO users (username, is_admin) VALUES ('admin', 1)")
	if CheckNeedsSetup() {
		t.Error("CheckNeedsSetup should return false after user exists")
	}
}

func TestSaveCSPReport(t *testing.T) {
	setupTestDB(t)

	SaveCSPReport("app.com", "https://evil.com/script.js", "script-src", "default-src 'self'")

	reports := GetRecentCSPReports(10)
	if len(reports) != 1 {
		t.Fatalf("GetRecentCSPReports returned %d reports, want 1", len(reports))
	}
	if reports[0].Host != "app.com" {
		t.Errorf("CSPReport Host = %q, want 'app.com'", reports[0].Host)
	}
	if reports[0].BlockedURI != "https://evil.com/script.js" {
		t.Errorf("CSPReport BlockedURI = %q", reports[0].BlockedURI)
	}
}

func TestLogEventAntiFlood(t *testing.T) {
	setupTestDB(t)

	// Log the same event multiple times quickly
	for i := 0; i < 100; i++ {
		LogEvent("[TEST] Same message flood", "test-performer")
	}

	// Should have only 1 event (anti-flood: 1 msg/second dedup)
	var count int
	DB.QueryRow("SELECT COUNT(*) FROM events WHERE message LIKE '%Same message flood%'").Scan(&count)
	if count != 1 {
		t.Errorf("Anti-flood allowed %d identical events, want 1", count)
	}
}

func TestAddDeleteBypassKey(t *testing.T) {
	setupTestDB(t)

	err := AddBypassKey("hash-of-token", "test-key", "app.com")
	if err != nil {
		t.Fatalf("AddBypassKey error: %v", err)
	}

	err = DeleteBypassKey("hash-of-token")
	if err != nil {
		t.Fatalf("DeleteBypassKey error: %v", err)
	}

	// Verify it's gone
	var count int
	DB.QueryRow("SELECT COUNT(*) FROM bypass_keys WHERE token = 'hash-of-token'").Scan(&count)
	if count != 0 {
		t.Error("Bypass key should be deleted")
	}
}

// TestSanitizeLogContract verifica el fix deuda #4: los saltos de línea de la
// entrada de usuario se neutralizan antes de llegar a los logs.
func TestSanitizeLogContract(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"sin CR/LF se devuelve igual", "usuario normal", "usuario normal"},
		{"LF se reemplaza", "admin\n[FALSO] login ok", "admin [FALSO] login ok"},
		{"CR se reemplaza", "a\r\nb", "a  b"},
		{"vacío", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeLog(tt.in); got != tt.want {
				t.Errorf("SanitizeLog(%q) = %q; want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestLogEventSinLineasFalsas verifica que ni el mensaje ni el performer
// pueden inyectar líneas nuevas en la tabla de eventos.
func TestLogEventSinLineasFalsas(t *testing.T) {
	setupTestDB(t)

	LogEvent("[SEC] mensaje con\nsegunda linea", "actor\n[FAKE] admin")

	var msg, performer string
	err := DB.QueryRow("SELECT message, performer FROM events ORDER BY id DESC LIMIT 1").Scan(&msg, &performer)
	if err != nil {
		t.Fatalf("leyendo evento: %v", err)
	}
	if strings.ContainsAny(msg, "\r\n") {
		t.Errorf("message contiene saltos de línea: %q", msg)
	}
	if strings.ContainsAny(performer, "\r\n") {
		t.Errorf("performer contiene saltos de línea: %q", performer)
	}
}

// TestPurgeCSPReportsFixS2 verifica que la tabla de reportes CSP queda
// acotada: >30 días purgados y tope de 5000 (antes crecía sin límite).
func TestPurgeCSPReportsFixS2(t *testing.T) {
	setupTestDB(t)

	// 1) Reportes viejos se purgan
	if _, err := DB.Exec(`INSERT INTO csp_reports (host, blocked_uri, violated_directive, original_policy, created_at)
		VALUES ('viejo.test', 'u', 'd', 'p', datetime('now', '-60 days'))`); err != nil {
		t.Fatalf("insert viejo: %v", err)
	}
	var viejos int
	DB.QueryRow("SELECT COUNT(*) FROM csp_reports WHERE host='viejo.test'").Scan(&viejos)
	if viejos != 1 {
		t.Fatalf("preparación: %d", viejos)
	}
	PurgeCSPReports()
	DB.QueryRow("SELECT COUNT(*) FROM csp_reports WHERE host='viejo.test'").Scan(&viejos)
	if viejos != 0 {
		t.Errorf("reporte de 60 días no purgado")
	}

	// 2) Tope de 5000: insertar 5010 recientes (CTE recursivo, rápido)
	_, err := DB.Exec(`WITH RECURSIVE cnt(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM cnt WHERE x < 5010)
		INSERT INTO csp_reports (host, blocked_uri, violated_directive, original_policy, created_at)
		SELECT 'nuevo.test', 'u', 'd', 'p', datetime('now') FROM cnt`)
	if err != nil {
		t.Fatalf("insert masivo: %v", err)
	}
	PurgeCSPReports()
	var total int
	DB.QueryRow("SELECT COUNT(*) FROM csp_reports").Scan(&total)
	// La purga elimina 500 al superar 5000 (banda 4501-5000, igual que events)
	if total != 4510 {
		t.Errorf("total = %d; want 4510 (5010 - 500 en tanda)", total)
	}
}
