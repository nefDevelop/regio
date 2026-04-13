package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"os"

	_ "modernc.org/sqlite"
)

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "./data/REGIO.db")
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
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal("Error creando tabla users:", err)
	}

	// Migración automática: Si la tabla ya existía sin la columna is_admin, se la añadimos.
	db.Exec("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0;")
	db.Exec("ALTER TABLE users ADD COLUMN totp_active BOOLEAN DEFAULT 0;")
	// Activar 2FA para los usuarios antiguos que ya lo tenían configurado a la fuerza
	db.Exec("UPDATE users SET totp_active = 1 WHERE totp_secret IS NOT NULL AND totp_secret != '' AND totp_active = 0;")

	// Tabla de registro de eventos (Logs)
	db.Exec("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, message TEXT);")
}

func checkNeedsSetup() bool {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count == 0
}

func saveConfig() error {
	data, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile("config.json", data, 0644)
}

func logEvent(message string) {
	if db != nil {
		db.Exec("INSERT INTO events (message) VALUES (?)", message)
	}
	log.Println(message) // También lo imprimimos en la consola de Docker
}
