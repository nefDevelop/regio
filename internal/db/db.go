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

	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE,
		password_hash TEXT,
		totp_secret TEXT,
		is_admin BOOLEAN DEFAULT 0,
		totp_active BOOLEAN DEFAULT 0
	);`
	_, err = DB.Exec(createTable)
	if err != nil {
		log.Fatal("Error creando tabla users:", err)
	}

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
}

func CheckNeedsSetup() bool {
	var count int
	DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count == 0
}

func SaveConfig(config models.Config) error {
	data, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile("./data/config.json", data, 0644)
}

func LogEvent(message string, performer string) {
	if DB != nil {
		DB.Exec("INSERT INTO events (message, performer) VALUES (?, ?)", message, performer)
	}
	log.Printf("[%s] %s", performer, message)
}

func ClearEvents() error {
	if DB != nil {
		_, err := DB.Exec("DELETE FROM events")
		return err
	}
	return nil
}
