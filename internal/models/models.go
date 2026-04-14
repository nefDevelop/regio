package models

import (
	"database/sql"
	"time"
)

type Config struct {
	Servicios map[string]string `json:"servicios"`
}

type Intento struct {
	Fallos         int
	BloqueadoHasta time.Time
}

type User struct {
	ID           int
	Username     string
	PasswordHash string
	TotpSecret   string
	IsAdmin      bool
	CSRFToken    string
	TotpActive   bool
	LastActive   time.Time
	RemoteIP     string
}

type AppToken struct {
	ID        int
	Name      string
	LastUsed  sql.NullTime
	CreatedAt string
}

type BannedIP struct {
	Target string
	Hasta  string
}

type Event struct {
	Timestamp string
	Message   string
}
