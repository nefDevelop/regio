package db

import (
	"database/sql"
	"encoding/json"
	"log"
	"os"

	"regio/internal/models"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func InitDB() {
	var err error
	DB, err = sql.Open("sqlite", "./data/REGIO.db")
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

	DB.Exec("ALTER TABLE users ADD COLUMN invite_token TEXT;")
	DB.Exec("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0;")
	DB.Exec("ALTER TABLE users ADD COLUMN totp_active BOOLEAN DEFAULT 0;")
	DB.Exec("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, message TEXT, performer TEXT);")
	DB.Exec("ALTER TABLE events ADD COLUMN performer TEXT;") // Por si la tabla ya existía

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
	DB.Exec("ALTER TABLE sessions ADD COLUMN csrf_token TEXT;") // Asegurar que existe si la tabla ya estaba creada

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
	DB.Exec("ALTER TABLE servicios ADD COLUMN csp TEXT DEFAULT '';")

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
func AddBypassKey(token, name, host string) error {
	_, err := DB.Exec("INSERT INTO bypass_keys (token, name, host) VALUES (?, ?, ?)", token, name, host)
	return err
}

func DeleteBypassKey(token string) error {
	_, err := DB.Exec("DELETE FROM bypass_keys WHERE token = ?", token)
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

func LogEvent(message string, performer string) {
	if DB != nil {
		DB.Exec("INSERT INTO events (message, performer) VALUES (?, ?)", message, performer)
	}
	log.Printf("[%s] %s", performer, message)
}

