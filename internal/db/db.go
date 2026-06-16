package db

import (
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"regexp"
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

// safeAlter ejecuta ALTER TABLE solo si la columna no existe.
func safeAlter(sql, table, column string) {
	var found int
	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?", table, column).Scan(&found)
	if found == 0 {
		DB.Exec(sql)
	}
}

func InitDB() {
	var err error
	dbPath := os.Getenv("REGIO_DB_PATH")
	if dbPath == "" {
		dbPath = "./data/REGIO.db"
		_ = os.MkdirAll("./data", 0700)
	} else if dir := filepath.Dir(dbPath); dir != "." {
		_ = os.MkdirAll(dir, 0700)
	}
	// Si el archivo no existe, lo creamos vacío para establecer permisos antes de abrirlo
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		f, _ := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0600)
		if f != nil {
			f.Close()
		}
	} else {
		// Si existe, forzar permisos 0600 por seguridad
		_ = os.Chmod(dbPath, 0600)
	}

	DB, err = sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal("Error abriendo DB:", err)
	}

	// Pragmas de seguridad y rendimiento
	DB.Exec("PRAGMA journal_mode=WAL")
	DB.Exec("PRAGMA busy_timeout=5000")
	DB.Exec("PRAGMA foreign_keys=ON")

	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE,
		password_hash TEXT,
		totp_secret TEXT,
		invite_token TEXT,
		is_admin BOOLEAN DEFAULT 0,
		totp_active BOOLEAN DEFAULT 0
	);`
	_, err = DB.Exec(createTable)
	if err != nil {
		log.Fatal("Error creando tabla users:", err)
	}

	// Migraciones: añadir columnas faltantes sin errores si ya existen
	safeAlter("ALTER TABLE users ADD COLUMN invite_token TEXT;", "users", "invite_token")
	safeAlter("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0;", "users", "is_admin")
	safeAlter("ALTER TABLE users ADD COLUMN totp_active BOOLEAN DEFAULT 0;", "users", "totp_active")
	DB.Exec("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, message TEXT, performer TEXT);")
	safeAlter("ALTER TABLE events ADD COLUMN performer TEXT;", "events", "performer")

	createBannedTable := `
	CREATE TABLE IF NOT EXISTS banned_ips (
		ip TEXT PRIMARY KEY,
		hasta DATETIME,
		razon TEXT
	);`
	_, err = DB.Exec(createBannedTable)
	if err != nil {
		log.Fatal("Error creando tabla banned_ips:", err)
	}

	createSessionsTable := `
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
	_, err = DB.Exec(createSessionsTable)
	if err != nil {
		log.Fatal("Error creando tabla sessions:", err)
	}
	safeAlter("ALTER TABLE sessions ADD COLUMN csrf_token TEXT;", "sessions", "csrf_token")

	createTokensTable := `
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
	_, err = DB.Exec(createTokensTable)
	if err != nil {
		log.Fatal("Error creando tabla app_tokens:", err)
	}

	// Nueva tabla de servicios (Configuración en DB)
	createServicesTable := `
	CREATE TABLE IF NOT EXISTS servicios (
		host TEXT PRIMARY KEY,
		target TEXT NOT NULL,
		is_public BOOLEAN DEFAULT 0,
		bypass_header TEXT DEFAULT '',
		csp TEXT DEFAULT ''
	);`
	_, err = DB.Exec(createServicesTable)
	if err != nil {
		log.Fatal("Error creando tabla servicios:", err)
	}
	safeAlter("ALTER TABLE servicios ADD COLUMN csp TEXT DEFAULT '';", "servicios", "csp")

	// Nueva tabla de reportes CSP
	createCSPReportsTable := `
	CREATE TABLE IF NOT EXISTS csp_reports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host TEXT,
		blocked_uri TEXT,
		violated_directive TEXT,
		original_policy TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	_, err = DB.Exec(createCSPReportsTable)
	if err != nil {
		log.Fatal("Error creando tabla csp_reports:", err)
	}

	// Nueva tabla de API Keys para Bypass
	createBypassKeysTable := `
	CREATE TABLE IF NOT EXISTS bypass_keys (
		token TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		host TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	_, err = DB.Exec(createBypassKeysTable)
	if err != nil {
		log.Fatal("Error creando tabla bypass_keys:", err)
	}
	safeAlter("ALTER TABLE bypass_keys ADD COLUMN migrated INTEGER DEFAULT 0", "bypass_keys", "migrated")

	// Tabla para rate limiting persistente
	createRateLimitsTable := `
	CREATE TABLE IF NOT EXISTS rate_limits (
		ip TEXT NOT NULL,
		timestamp DATETIME NOT NULL
	);`
	_, err = DB.Exec(createRateLimitsTable)
	if err != nil {
		log.Fatal("Error creando tabla rate_limits:", err)
	}
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip, timestamp)")
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

	stmt, _ := tx.Prepare("INSERT INTO servicios (host, target, is_public, bypass_header, csp) VALUES (?, ?, ?, ?, ?)")
	defer stmt.Close()

	for host, target := range config.Servicios {
		isPublic := config.Publicos[host]
		bypass := config.BypassHeaders[host]
		csp := config.CSPs[host]
		_, err = stmt.Exec(host, target, isPublic, bypass, csp)
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
	rows, err := DB.Query("SELECT host, target, is_public, bypass_header, COALESCE(csp, '') FROM servicios")
	if err != nil {
		return config, err
	}
	defer rows.Close()

	for rows.Next() {
		var host, target, bypass, csp string
		var isPublic bool
		if err := rows.Scan(&host, &target, &isPublic, &bypass, &csp); err == nil {
			config.Servicios[host] = target
			config.Publicos[host] = isPublic
			if bypass != "" {
				config.BypassHeaders[host] = bypass
			}
			config.CSPs[host] = csp
		}
	}

	return config, nil
}

// Métodos individuales para el CLI
func AddService(host, target string, isPublic bool, bypass string, csp string) error {
	_, err := DB.Exec("INSERT OR REPLACE INTO servicios (host, target, is_public, bypass_header, csp) VALUES (?, ?, ?, ?, ?)", host, target, isPublic, bypass, csp)
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

func stripANSI(str string) string {
	const ansi = "[\u001B\u009B][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]"
	re := regexp.MustCompile(ansi)
	return re.ReplaceAllString(str, "")
}

func LogEvent(message string, performer string) {
	cleanMessage := stripANSI(message)
	
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

