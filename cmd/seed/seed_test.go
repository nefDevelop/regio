package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"regio/internal/auth"

	_ "modernc.org/sqlite"
)

func TestMain(m *testing.M) {
	// seedData usa auth.HashPassword/auth.Encrypt: fijar clave si el runner
	// no la trae (los targets make ya la exportan).
	if os.Getenv("MASTER_KEY") == "" {
		os.Setenv("MASTER_KEY", "test-master-key-32-bytes-length-!!!")
	}
	os.Exit(m.Run())
}

// newSeedDB crea una DB temporal para probar createTables/seedData sin tocar
// el fichero de datos real ni el estado de otros paquetes.
func newSeedDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "seed.db"))
	if err != nil {
		t.Fatalf("abriendo DB de test: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func seedCount(t *testing.T, db *sql.DB, query string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("consulta %q: %v", query, err)
	}
	return n
}

func hasColumn(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	var n int
	db.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?", table, column).Scan(&n)
	return n > 0
}

// TestCreateTablesEsquemaCompleto verifica el DDL del seed y, como guarda de
// sincronización, que mantenga las columnas nuevas que crea db.Migrate
// (geo/settings/totp_last_epoch): si alguien añade una migración y olvida el
// seed, este test revienta.
func TestCreateTablesEsquemaCompleto(t *testing.T) {
	db := newSeedDB(t)
	createTables(db)

	tablas := []string{
		"users", "events", "banned_ips", "sessions", "app_tokens",
		"servicios", "csp_reports", "bypass_keys", "rate_limits", "settings",
	}
	for _, tabla := range tablas {
		var n int
		db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", tabla).Scan(&n)
		if n != 1 {
			t.Errorf("la tabla %q no fue creada por el seed", tabla)
		}
	}

	// Paridad con db.Migrate (migraciones de las fases geo/2FA)
	paridad := []struct{ tabla, col string }{
		{"servicios", "csp"},
		{"servicios", "geo_mode"},
		{"servicios", "geo_countries"},
		{"users", "invite_token"},
		{"users", "is_admin"},
		{"users", "totp_last_epoch"},
		{"settings", "value"},
		{"bypass_keys", "migrated"},
	}
	for _, p := range paridad {
		if !hasColumn(t, db, p.tabla, p.col) {
			t.Errorf("el DDL del seed no está sincronizado: falta %s.%s", p.tabla, p.col)
		}
	}
}

// TestSeedDataPueblaLaDB valida el contenido del seed de desarrollo.
func TestSeedDataPueblaLaDB(t *testing.T) {
	db := newSeedDB(t)
	createTables(db)
	seedData(db)

	// Servicios
	if n := seedCount(t, db, "SELECT COUNT(*) FROM servicios"); n != 5 {
		t.Errorf("servicios = %d; want 5", n)
	}
	if n := seedCount(t, db, "SELECT COUNT(*) FROM servicios WHERE host='blog.midominio.com' AND is_public=1"); n != 1 {
		t.Error("blog.midominio.com debe existir y ser público")
	}

	// Usuarios: credenciales reales verificables con auth.VerifyPassword
	if n := seedCount(t, db, "SELECT COUNT(*) FROM users"); n != 3 {
		t.Fatalf("usuarios = %d; want 3", n)
	}
	var hash string
	var isAdmin int
	if err := db.QueryRow("SELECT password_hash, is_admin FROM users WHERE username='admin'").Scan(&hash, &isAdmin); err != nil {
		t.Fatalf("usuario admin: %v", err)
	}
	if !auth.VerifyPassword("SeedPass123!", hash) {
		t.Error("la contraseña del admin sembrado no verifica")
	}
	if isAdmin != 1 {
		t.Error("admin debe tener is_admin=1")
	}
	var lectorAdmin int
	db.QueryRow("SELECT is_admin FROM users WHERE username='lector'").Scan(&lectorAdmin)
	if lectorAdmin != 0 {
		t.Error("lector no debe ser admin")
	}

	// Resto de entidades de demo
	for tabla, want := range map[string]int{
		"sessions": 3, "app_tokens": 3, "bypass_keys": 2,
		"banned_ips": 5, "events": 20, "csp_reports": 3,
	} {
		if n := seedCount(t, db, "SELECT COUNT(*) FROM "+tabla); n != want {
			t.Errorf("%s = %d; want %d", tabla, n, want)
		}
	}

	// Rate limits históricos: 70 timestamps DISTINTOS (compatibles con el
	// índice único (ip,timestamp) de db.Migrate)
	if n := seedCount(t, db, "SELECT COUNT(DISTINCT timestamp) FROM rate_limits WHERE ip='45.33.32.156'"); n != 50 {
		t.Errorf("timestamps distintos de rate_limits = %d; want 50 (colisionarian con el índice único)", n)
	}
}

// TestRandomTokenContrato congela el comportamiento real de randomToken:
// codificación RawURL de `length` bytes (la salida NO mide `length` chars).
func TestRandomTokenContrato(t *testing.T) {
	tok := randomToken(32)
	if len(tok) != 43 { // ceil(32*4/3) sin padding
		t.Errorf("len(randomToken(32)) = %d; want 43", len(tok))
	}
	for _, c := range tok {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", c) {
			t.Errorf("carácter fuera del alfabeto RawURL: %q", c)
		}
	}
	if randomToken(32) == tok {
		t.Error("dos randomToken(32) no deben coincidir")
	}
}

// TestSha256HexVector conocido: sha256("abc") en base64 ESTÁNDAR.
func TestSha256HexVector(t *testing.T) {
	const want = "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
	if got := sha256Hex("abc"); got != want {
		t.Errorf("sha256Hex(abc) = %q; want %q", got, want)
	}
	if sha256Hex("abc") == sha256Hex("abd") {
		t.Error("entradas distintas deben producir salidas distintas")
	}
}

func TestBoolInt(t *testing.T) {
	if boolInt(true) != 1 || boolInt(false) != 0 {
		t.Error("boolInt debe mapear true->1 y false->0")
	}
}
