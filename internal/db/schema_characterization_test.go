package db

import (
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// columnas de tabla vía pragma_table_info
func columnsOf(t *testing.T, table string) []string {
	t.Helper()
	rows, err := DB.Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		t.Fatalf("pragma_table_info(%s): %v", table, err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var name string
		rows.Scan(&name)
		cols = append(cols, name)
	}
	sort.Strings(cols)
	return cols
}

func requireColumns(t *testing.T, table string, want ...string) {
	t.Helper()
	cols := columnsOf(t, table)
	have := map[string]bool{}
	for _, c := range cols {
		have[c] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("tabla %s: falta la columna %q (tiene: %v)", table, w, cols)
		}
	}
}

func tableExists(t *testing.T, name string) bool {
	t.Helper()
	var n int
	DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n)
	return n > 0
}

// withTempDB apunta REGIO_DB_PATH a un fichero temporal, ejecuta InitDB y
// restaura el handle de DB anterior al final del test.
func withTempDB(t *testing.T) string {
	t.Helper()
	orig := DB
	t.Cleanup(func() {
		if DB != nil {
			DB.Close()
		}
		DB = orig
	})
	dbPath := filepath.Join(t.TempDir(), "schema_test.db")
	t.Setenv("REGIO_DB_PATH", dbPath)
	InitDB()
	return dbPath
}

// TestInitDBSchemaCharacterization congela el esquema actual que produce
// InitDB: es la referencia de integridad para R4 (split Open/Migrate) y para
// cualquier futuro cambio de migración.
func TestInitDBSchemaCharacterization(t *testing.T) {
	withTempDB(t)

	tablas := []string{
		"users", "events", "banned_ips", "sessions", "app_tokens",
		"servicios", "csp_reports", "bypass_keys", "rate_limits", "settings",
	}
	for _, tabla := range tablas {
		if !tableExists(t, tabla) {
			t.Errorf("InitDB no crea la tabla %q", tabla)
		}
	}

	requireColumns(t, "users",
		"id", "username", "password_hash", "totp_secret",
		"invite_token", "is_admin", "totp_active", "totp_last_epoch")
	requireColumns(t, "servicios",
		"host", "target", "is_public", "bypass_header", "csp",
		"geo_mode", "geo_countries")
	requireColumns(t, "settings", "key", "value")
	// performer solo lo añade safeAlter sobre el CREATE (si safeAlter se
	// rompe, esta columna desaparece) — la exige también la mutación.
	requireColumns(t, "events", "id", "message", "performer")
	requireColumns(t, "sessions",
		"token", "user_id", "csrf_token", "ip", "user_agent",
		"last_active", "created_at")
	requireColumns(t, "app_tokens",
		"id", "user_id", "name", "token_hash", "scopes", "last_used", "created_at")

	// FK de app_tokens -> users(id): es la causa de que "DELETE FROM users"
	// falle si no se limpian antes las hijas (regresión conocida en tests).
	var fkCount int
	DB.QueryRow("SELECT COUNT(*) FROM pragma_foreign_key_list('app_tokens') WHERE \"table\"='users'").Scan(&fkCount)
	if fkCount == 0 {
		t.Error("app_tokens debe tener FK a users(id)")
	}

	// Índice de rate limiting
	var idxCount int
	DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_rate_limits_ip'").Scan(&idxCount)
	if idxCount == 0 {
		t.Error("falta el índice idx_rate_limits_ip")
	}

	// Índice único (ip,timestamp): base del fix de persistencia sin duplicados
	var uniqCount int
	DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_rate_limits_unique'").Scan(&uniqCount)
	if uniqCount == 0 {
		t.Error("falta el índice único idx_rate_limits_unique (fix deuda #5)")
	}
}

// TestMigrationOldSchemaToCurrent verifica que InitDB migra un esquema
// antiguo (previo a geo/settings) sin perder datos — integridad de migración.
func TestMigrationOldSchemaToCurrent(t *testing.T) {
	orig := DB
	t.Cleanup(func() {
		if DB != nil {
			DB.Close()
		}
		DB = orig
	})

	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	t.Setenv("REGIO_DB_PATH", dbPath)

	// Construir A MANO el esquema antiguo (antes de csp/geo/settings)
	legacy, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("abriendo DB legacy: %v", err)
	}
	legacyDDL := []string{
		`CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE,
			password_hash TEXT,
			totp_secret TEXT
		)`,
		`CREATE TABLE servicios (
			host TEXT PRIMARY KEY,
			target TEXT NOT NULL,
			is_public BOOLEAN DEFAULT 0,
			bypass_header TEXT DEFAULT ''
		)`,
		`INSERT INTO users (username, password_hash, totp_secret) VALUES ('legacy', 'hash', 'secret')`,
		`INSERT INTO servicios (host, target, is_public, bypass_header)
			VALUES ('app.legacy.com', 'http://10.0.0.2:80', 1, 'X-Key:valor')`,
		`CREATE TABLE rate_limits (ip TEXT NOT NULL, timestamp DATETIME NOT NULL)`,
		// Histórico con duplicados exactos (ip,timestamp): la migración debe deduplicar
		`INSERT INTO rate_limits (ip, timestamp) VALUES ('1.2.3.4', '2026-01-01 00:00:00'),
			('1.2.3.4', '2026-01-01 00:00:00'), ('5.6.7.8', '2026-01-01 00:00:01')`,
	}
	for _, ddl := range legacyDDL {
		if _, err := legacy.Exec(ddl); err != nil {
			legacy.Close()
			t.Fatalf("DDL legacy: %v", err)
		}
	}
	legacy.Close()

	// Migrar con InitDB real
	InitDB()

	// Columnas nuevas añadidas por safeAlter
	requireColumns(t, "servicios", "csp", "geo_mode", "geo_countries")
	requireColumns(t, "users", "invite_token", "is_admin", "totp_active")

	// Tablas nuevas
	for _, tabla := range []string{"settings", "events", "banned_ips", "sessions", "app_tokens"} {
		if !tableExists(t, tabla) {
			t.Errorf("la migración no crea la tabla %q", tabla)
		}
	}

	// Los datos preexistentes deben sobrevivir con sus valores
	var target string
	var isPublic bool
	var bypass string
	err = DB.QueryRow("SELECT target, is_public, bypass_header FROM servicios WHERE host='app.legacy.com'").
		Scan(&target, &isPublic, &bypass)
	if err != nil {
		t.Fatalf("fila legacy de servicios no conservada: %v", err)
	}
	if target != "http://10.0.0.2:80" || !isPublic || bypass != "X-Key:valor" {
		t.Errorf("datos legacy alterados: target=%q public=%v bypass=%q", target, isPublic, bypass)
	}

	var count int
	DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='legacy'").Scan(&count)
	if count != 1 {
		t.Error("usuario legacy perdido en la migración")
	}

	// Los duplicados históricos de rate_limits deben haberse deduplicado
	var dups, totalRatelimits int
	DB.QueryRow("SELECT COUNT(*) FROM rate_limits").Scan(&totalRatelimits)
	DB.QueryRow("SELECT COUNT(*) FROM (SELECT ip, timestamp FROM rate_limits GROUP BY ip, timestamp HAVING COUNT(*) > 1)").Scan(&dups)
	if dups != 0 || totalRatelimits != 2 {
		t.Errorf("rate_limits tras migrar: total=%d duplicados=%d; want total=2 duplicados=0", totalRatelimits, dups)
	}

	// La migración debe hacer idempotente: segunda pasada sin error
	InitDB()
	DB.QueryRow("SELECT COUNT(*) FROM servicios WHERE host='app.legacy.com'").Scan(&count)
	if count != 1 {
		t.Error("segunda pasada de InitDB duplicó/perdió datos")
	}
}

// TestOpenYMigrateRutasDeError valida las costuras creadas en R4: Open crea
// el fichero con permisos 0600 y Migrate devuelve error (no aborta) ante un
// handle inválido.
func TestOpenYMigrateRutasDeError(t *testing.T) {
	// Open: crea el fichero con permisos restringidos
	dbPath := filepath.Join(t.TempDir(), "abierto.db")
	handle, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer handle.Close()
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("el fichero no fue creado: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("permisos = %o; want 600", perm)
	}

	// Migrate sobre handle válido e idempotente
	if err := Migrate(handle); err != nil {
		t.Errorf("Migrate: %v", err)
	}
	if err := Migrate(handle); err != nil {
		t.Errorf("Migrate idempotente: %v", err)
	}

	// Migrate sobre handle cerrado devuelve error (antes log.Fatal)
	closed, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "cerrado.db"))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	closed.Close()
	if err := Migrate(closed); err == nil {
		t.Error("Migrate sobre handle cerrado debería devolver error, no nil")
	}
}
