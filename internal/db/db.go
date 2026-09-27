package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"regio/internal/models"

	_ "modernc.org/sqlite"
)

var (
	DB    *sql.DB
	logMu sync.Mutex
	// lastLogTime ayuda a evitar el flooding de logs idénticos en poco tiempo.
	lastLogTime = make(map[string]time.Time)
)

// safeAlter ejecuta ALTER TABLE solo si la columna no existe, sobre el handle indicado.
func safeAlter(database *sql.DB, ddl, table, column string) {
	var found int
	database.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?", table, column).Scan(&found)
	if found == 0 {
		database.Exec(ddl)
	}
}

// resolveDBPath devuelve la ruta de la base de datos (REGIO_DB_PATH o el
// default ./data/REGIO.db) creando su directorio si hace falta.
func resolveDBPath() string {
	dbPath := os.Getenv("REGIO_DB_PATH")
	if dbPath == "" {
		dbPath = "./data/REGIO.db"
		_ = os.MkdirAll("./data", 0700)
	} else if dir := filepath.Dir(dbPath); dir != "." {
		_ = os.MkdirAll(dir, 0700) // #nosec G703 — REGIO_DB_PATH es configuración del operador (env)
	}
	return dbPath
}

// Open crea si hace falta el fichero de la BD (permisos 0600), abre la
// conexión SQLite y aplica los pragmas de seguridad/rendimiento.
func Open(dbPath string) (*sql.DB, error) {
	// Si el archivo no existe, lo creamos vacío para establecer permisos antes de abrirlo
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		f, _ := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0600) // #nosec G304 — REGIO_DB_PATH es configuración del operador (env)
		if f != nil {
			f.Close()
		}
	} else {
		// Si existe, forzar permisos 0600 por seguridad
		_ = os.Chmod(dbPath, 0600)
	}

	database, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// Pragmas de seguridad y rendimiento
	database.Exec("PRAGMA journal_mode=WAL")
	database.Exec("PRAGMA busy_timeout=5000")
	database.Exec("PRAGMA foreign_keys=ON")
	return database, nil
}

// Migrate crea el esquema completo (tablas, columnas e índices) de forma
// idempotente. Devuelve error en lugar de abortar, para poder testear las
// rutas de fallo sin matar el proceso (extracción R4 de InitDB).
func Migrate(database *sql.DB) error {
	usersDDL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE,
		password_hash TEXT,
		totp_secret TEXT,
		invite_token TEXT,
		is_admin BOOLEAN DEFAULT 0,
		totp_active BOOLEAN DEFAULT 0,
		totp_last_epoch INTEGER
	);`
	if _, err := database.Exec(usersDDL); err != nil {
		return fmt.Errorf("creando tabla users: %w", err)
	}

	// Migraciones: añadir columnas faltantes sin errores si ya existen
	safeAlter(database, "ALTER TABLE users ADD COLUMN invite_token TEXT;", "users", "invite_token")
	safeAlter(database, "ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0;", "users", "is_admin")
	safeAlter(database, "ALTER TABLE users ADD COLUMN totp_active BOOLEAN DEFAULT 0;", "users", "totp_active")
	// Mejora A2: último epoch TOTP aceptado (anti-replay); NULL = sin límite
	safeAlter(database, "ALTER TABLE users ADD COLUMN totp_last_epoch INTEGER;", "users", "totp_last_epoch")
	database.Exec("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, message TEXT, performer TEXT);")
	safeAlter(database, "ALTER TABLE events ADD COLUMN performer TEXT;", "events", "performer")

	bannedDDL := `
	CREATE TABLE IF NOT EXISTS banned_ips (
		ip TEXT PRIMARY KEY,
		hasta DATETIME,
		razon TEXT
	);`
	if _, err := database.Exec(bannedDDL); err != nil {
		return fmt.Errorf("creando tabla banned_ips: %w", err)
	}

	sessionsDDL := `
	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		user_id INTEGER,
		csrf_token TEXT,
		ip TEXT,
		user_agent TEXT,
		last_active DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`
	if _, err := database.Exec(sessionsDDL); err != nil {
		return fmt.Errorf("creando tabla sessions: %w", err)
	}
	safeAlter(database, "ALTER TABLE sessions ADD COLUMN csrf_token TEXT;", "sessions", "csrf_token")

	// #nosec G101 — FP: DDL de SQL (columnas tipo token_hash), no credenciales
	tokensDDL := `
	CREATE TABLE IF NOT EXISTS app_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		name TEXT,
		token_hash TEXT UNIQUE,
		scopes TEXT,
		last_used DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`
	if _, err := database.Exec(tokensDDL); err != nil {
		return fmt.Errorf("creando tabla app_tokens: %w", err)
	}

	// Nueva tabla de servicios (Configuración en DB)
	servicesDDL := `
	CREATE TABLE IF NOT EXISTS servicios (
		host TEXT PRIMARY KEY,
		target TEXT NOT NULL,
		is_public BOOLEAN DEFAULT 0,
		bypass_header TEXT DEFAULT '',
		csp TEXT DEFAULT '',
		geo_mode TEXT DEFAULT '',
		geo_countries TEXT DEFAULT ''
	);`
	if _, err := database.Exec(servicesDDL); err != nil {
		return fmt.Errorf("creando tabla servicios: %w", err)
	}
	safeAlter(database, "ALTER TABLE servicios ADD COLUMN csp TEXT DEFAULT '';", "servicios", "csp")
	safeAlter(database, "ALTER TABLE servicios ADD COLUMN geo_mode TEXT DEFAULT '';", "servicios", "geo_mode")
	safeAlter(database, "ALTER TABLE servicios ADD COLUMN geo_countries TEXT DEFAULT '';", "servicios", "geo_countries")

	// Ajustes globales (política geográfica, etc.) con override sobre variables de entorno
	database.Exec("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);")

	// Nueva tabla de reportes CSP
	cspDDL := `
	CREATE TABLE IF NOT EXISTS csp_reports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host TEXT,
		blocked_uri TEXT,
		violated_directive TEXT,
		original_policy TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := database.Exec(cspDDL); err != nil {
		return fmt.Errorf("creando tabla csp_reports: %w", err)
	}

	// Nueva tabla de API Keys para Bypass
	// #nosec G101 — FP: DDL de SQL (columnas tipo token), no credenciales
	bypassDDL := `
	CREATE TABLE IF NOT EXISTS bypass_keys (
		token TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		host TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := database.Exec(bypassDDL); err != nil {
		return fmt.Errorf("creando tabla bypass_keys: %w", err)
	}
	safeAlter(database, "ALTER TABLE bypass_keys ADD COLUMN migrated INTEGER DEFAULT 0", "bypass_keys", "migrated")

	// Tabla para rate limiting persistente
	rateDDL := `
	CREATE TABLE IF NOT EXISTS rate_limits (
		ip TEXT NOT NULL,
		timestamp DATETIME NOT NULL
	);`
	if _, err := database.Exec(rateDDL); err != nil {
		return fmt.Errorf("creando tabla rate_limits: %w", err)
	}
	database.Exec("CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip, timestamp)")

	// Fix deuda #5: el histórico permitía filas duplicadas (ip,timestamp) —
	// INSERT OR IGNORE no deduplicaba sin restricción única, lo que inflaba el
	// recuento tras un reinicio (bloqueos prematuros) y hacía la persistencia
	// O(n²). Se deduplica y se garantiza unicidad para que OR IGNORE surta efecto.
	database.Exec("DELETE FROM rate_limits WHERE rowid NOT IN (SELECT MIN(rowid) FROM rate_limits GROUP BY ip, timestamp)")
	database.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_rate_limits_unique ON rate_limits(ip, timestamp)")
	return nil
}

// InitDB orquesta resolveDBPath + Open + Migrate sobre la variable global DB.
// Conserva la semántica original: aborta el proceso (log.Fatal) ante fallos.
func InitDB() {
	dbPath := resolveDBPath()
	database, err := Open(dbPath)
	if err != nil {
		log.Fatal("Error abriendo DB:", err)
	}
	DB = database
	if err := Migrate(DB); err != nil {
		log.Fatal("Error migrando DB:", err)
	}
}

func CheckNeedsSetup() bool {
	var count int
	DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count == 0
}

// SaveConfig guarda la configuración completa en la DB.
// Nota: En DB los servicios se guardan individualmente, pero mantenemos esta función por compatibilidad.
func SaveConfig(config models.Config) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Limpiar tabla actual para reemplazo total (como hacía el JSON)
	_, _ = tx.Exec("DELETE FROM servicios")

	stmt, err := tx.Prepare("INSERT INTO servicios (host, target, is_public, bypass_header, csp, geo_mode, geo_countries) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for host, target := range config.Servicios {
		isPublic := config.Publicos[host]
		bypass := config.BypassHeaders[host]
		csp := config.CSPs[host]
		geoMode := config.GeoModes[host]
		geoCountries := config.GeoCountries[host]
		_, err = stmt.Exec(host, target, isPublic, bypass, csp, geoMode, geoCountries)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// LoadConfig lee la configuración desde la DB. Implementa migración desde JSON si existe.
func LoadConfig() (models.Config, error) {
	config := models.Config{
		Servicios:     make(map[string]string),
		Publicos:      make(map[string]bool),
		BypassHeaders: make(map[string]string),
		CSPs:          make(map[string]string),
		GeoModes:      make(map[string]string),
		GeoCountries:  make(map[string]string),
	}

	// 1. Verificar si existe config.json para migración
	jsonPath := "./data/config.json"
	if _, err := os.Stat(jsonPath); err == nil {
		log.Println("[INFO] Detectado config.json antiguo. Migrando a Base de Datos...")
		data, _ := os.ReadFile(jsonPath)
		var oldConfig models.Config
		if err := json.Unmarshal(data, &oldConfig); err == nil {
			err = SaveConfig(oldConfig)
			if err == nil {
				log.Println("[OK] Migración completada exitosamente.")
				os.Rename(jsonPath, jsonPath+".bak")
			} else {
				log.Printf("[ERR] Error migrando datos: %v", err)
			}
		}
	}

	// 2. Cargar desde DB
	rows, err := DB.Query("SELECT host, target, is_public, bypass_header, COALESCE(csp, ''), COALESCE(geo_mode, ''), COALESCE(geo_countries, '') FROM servicios")
	if err != nil {
		return config, err
	}
	defer rows.Close()

	for rows.Next() {
		var host, target, bypass, csp, geoMode, geoCountries string
		var isPublic bool
		if err := rows.Scan(&host, &target, &isPublic, &bypass, &csp, &geoMode, &geoCountries); err == nil {
			config.Servicios[host] = target
			config.Publicos[host] = isPublic
			if bypass != "" {
				config.BypassHeaders[host] = bypass
			}
			config.CSPs[host] = csp
			if geoMode != "" {
				config.GeoModes[host] = geoMode
			}
			if geoCountries != "" {
				config.GeoCountries[host] = geoCountries
			}
		}
	}

	return config, nil
}

// GetSetting lee un ajuste global de la tabla settings. Devuelve false si no existe.
func GetSetting(key string) (string, bool) {
	if DB == nil {
		return "", false
	}
	var value string
	if err := DB.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value); err != nil {
		return "", false
	}
	return value, true
}

// SetSetting guarda (o sobrescribe) un ajuste global en la tabla settings.
func SetSetting(key, value string) error {
	if DB == nil {
		return fmt.Errorf("base de datos no inicializada")
	}
	_, err := DB.Exec("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
	return err
}

// Métodos individuales para el CLI
func AddService(host, target string, isPublic bool, bypass string, csp string) error {
	// ON CONFLICT conserva las columnas geo (política por país) ya configuradas desde el panel
	_, err := DB.Exec(`INSERT INTO servicios (host, target, is_public, bypass_header, csp) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(host) DO UPDATE SET
			target = excluded.target,
			is_public = excluded.is_public,
			bypass_header = excluded.bypass_header,
			csp = excluded.csp`, host, target, isPublic, bypass, csp)
	return err
}

func DeleteService(host string) error {
	_, err := DB.Exec("DELETE FROM servicios WHERE host = ?", host)
	return err
}

func SaveCSPReport(host, blocked, directive, policy string) {
	_, err := DB.Exec("INSERT INTO csp_reports (host, blocked_uri, violated_directive, original_policy) VALUES (?, ?, ?, ?)", host, blocked, directive, policy)
	if err != nil {
		log.Printf("[ERR] Error guardando reporte CSP: %v", err)
	}
}

func GetRecentCSPReports(limit int) []models.CSPReport {
	var reports []models.CSPReport
	rows, err := DB.Query("SELECT id, host, blocked_uri, violated_directive, original_policy, datetime(created_at, 'localtime') FROM csp_reports ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return reports
	}
	defer rows.Close()

	for rows.Next() {
		var r models.CSPReport
		rows.Scan(&r.ID, &r.Host, &r.BlockedURI, &r.ViolatedDirective, &r.OriginalPolicy, &r.CreatedAt)
		reports = append(reports, r)
	}
	return reports
}

// PurgeCSPReports limita la tabla de reportes CSP: borra entradas de más de
// 30 días y mantiene como tope las 5000 más recientes (eliminando 500).
// Fix S2: la tabla no tenía NINGÚN límite y el endpoint de ingesta era
// (antes) un endpoint sin autenticar ni rate limit → agotamiento de disco.
func PurgeCSPReports() {
	if DB == nil {
		return
	}
	DB.Exec("DELETE FROM csp_reports WHERE created_at < datetime('now', '-30 days')")
	var count int
	DB.QueryRow("SELECT COUNT(*) FROM csp_reports").Scan(&count)
	if count > 5000 {
		DB.Exec("DELETE FROM csp_reports WHERE id IN (SELECT id FROM csp_reports ORDER BY id ASC LIMIT 500)")
	}
}

// Funciones para Gestión de Bypass Keys
func AddBypassKey(tokenHash, name, host string) error {
	_, err := DB.Exec("INSERT INTO bypass_keys (token, name, host) VALUES (?, ?, ?)", tokenHash, name, host)
	return err
}

func DeleteBypassKey(tokenHash string) error {
	_, err := DB.Exec("DELETE FROM bypass_keys WHERE token = ?", tokenHash)
	return err
}

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"

	// Prefijos con estilo para logs
	PrefixOK    = ColorGreen + "[OK]" + ColorReset
	PrefixERR   = ColorRed + "[ERR]" + ColorReset
	PrefixWARN  = ColorYellow + "[WARN]" + ColorReset
	PrefixINFO  = ColorBlue + "[INFO]" + ColorReset
	PrefixSEC   = ColorPurple + "[SEC]" + ColorReset
	PrefixSCAN  = ColorCyan + "[SCAN]" + ColorReset
	PrefixBLOCK = ColorRed + "[BLOCK]" + ColorReset
	PrefixKEY   = ColorYellow + "[KEY]" + ColorReset
	PrefixPASS  = ColorCyan + "[PASS]" + ColorReset
	PrefixUSER  = ColorGreen + "[USER]" + ColorReset
	PrefixIN    = ColorBlue + "<-" + ColorReset
	PrefixOUT   = ColorBlue + "->" + ColorReset
	PrefixREGIO = ColorPurple + "[reGIO]" + ColorReset
)

// newlineReplacer neutraliza saltos de línea en logs (log injection).
var newlineReplacer = strings.NewReplacer("\r", " ", "\n", " ")

// SanitizeLog elimina los saltos de línea (CR/LF) de un string procedente de
// la entrada de usuario para impedir que inyecte líneas falsas en los logs
// (fix deuda #4). Solo hace trabajo si hay CR/LF: apto por petición.
func SanitizeLog(str string) string {
	if strings.ContainsAny(str, "\r\n") {
		return newlineReplacer.Replace(str)
	}
	return str
}

func stripANSI(str string) string {
	const ansi = "[\u001B\u009B][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]"
	re := regexp.MustCompile(ansi)
	return SanitizeLog(re.ReplaceAllString(str, ""))
}

func LogEvent(message string, performer string) {
	cleanMessage := stripANSI(message)
	
	// Sanitizar el performer (puede ser un username con saltos de línea)
	performer = SanitizeLog(performer)

	// Protección contra log-flooding: no registrar el mismo mensaje del mismo actor más de una vez por segundo.
	logKey := performer + ":" + cleanMessage
	logMu.Lock()
	if last, ok := lastLogTime[logKey]; ok && time.Since(last) < 1*time.Second {
		logMu.Unlock()
		return
	}
	lastLogTime[logKey] = time.Now()
	
	// Limpieza periódica del mapa de tiempos para evitar memory leak
	if len(lastLogTime) > 1000 {
		for k, v := range lastLogTime {
			if time.Since(v) > 1*time.Minute {
				delete(lastLogTime, k)
			}
		}
	}
	logMu.Unlock()

	if DB != nil {
		DB.Exec("INSERT INTO events (message, performer) VALUES (?, ?)", cleanMessage, performer)
		
		// Auto-limpieza de la tabla de eventos para prevenir agotamiento de disco (Max 5000 eventos)
		var count int
		DB.QueryRow("SELECT COUNT(*) FROM events").Scan(&count)
		if count > 5000 {
			DB.Exec("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT 500)")
		}
	}
	log.Printf("[%s] %s", performer, cleanMessage)
}

