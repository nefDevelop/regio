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
		bypass_header TEXT DEFAULT ''
	);`
	_, err = DB.Exec(createServicesTable)
	if err != nil {
		log.Fatal("Error creando tabla servicios:", err)
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

	stmt, _ := tx.Prepare("INSERT INTO servicios (host, target, is_public, bypass_header) VALUES (?, ?, ?, ?)")
	defer stmt.Close()

	for host, target := range config.Servicios {
		isPublic := config.Publicos[host]
		bypass := config.BypassHeaders[host]
		_, err = stmt.Exec(host, target, isPublic, bypass)
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
	}

	// 1. Verificar si existe config.json para migración
	jsonPath := "./data/config.json"
	if _, err := os.Stat(jsonPath); err == nil {
		log.Println("ℹ️ Detectado config.json antiguo. Migrando a Base de Datos...")
		data, _ := os.ReadFile(jsonPath)
		var oldConfig models.Config
		if err := json.Unmarshal(data, &oldConfig); err == nil {
			err = SaveConfig(oldConfig)
			if err == nil {
				log.Println("✅ Migración completada exitosamente.")
				os.Rename(jsonPath, jsonPath+".bak")
			} else {
				log.Printf("✕ Error migrando datos: %v", err)
			}
		}
	}

	// 2. Cargar desde DB
	rows, err := DB.Query("SELECT host, target, is_public, bypass_header FROM servicios")
	if err != nil {
		return config, err
	}
	defer rows.Close()

	for rows.Next() {
		var host, target, bypass string
		var isPublic bool
		if err := rows.Scan(&host, &target, &isPublic, &bypass); err == nil {
			config.Servicios[host] = target
			config.Publicos[host] = isPublic
			if bypass != "" {
				config.BypassHeaders[host] = bypass
			}
		}
	}

	return config, nil
}

// Métodos individuales para el CLI
func AddService(host, target string, isPublic bool, bypass string) error {
	_, err := DB.Exec("INSERT OR REPLACE INTO servicios (host, target, is_public, bypass_header) VALUES (?, ?, ?, ?)", host, target, isPublic, bypass)
	return err
}

func DeleteService(host string) error {
	_, err := DB.Exec("DELETE FROM servicios WHERE host = ?", host)
	return err
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

func LogEvent(message string, performer string) {
	if DB != nil {
		DB.Exec("INSERT INTO events (message, performer) VALUES (?, ?)", message, performer)
	}
	log.Printf("[%s] %s", performer, message)
}

