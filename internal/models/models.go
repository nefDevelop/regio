package models

import (
	"database/sql"
	"time"
)

type Config struct {
	Servicios     map[string]string `json:"servicios"`
	Publicos      map[string]bool   `json:"publicos"`
	BypassHeaders map[string]string `json:"bypass_headers"` // Host -> "HeaderName:Value"
	CSPs          map[string]string `json:"csps"`           // Host -> "CSP String"
	GeoModes      map[string]string `json:"geo_modes"`      // Host -> "" (hereda global) | off | allow | deny
	GeoCountries  map[string]string `json:"geo_countries"`  // Host -> "ES, FR"
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
	Performer string
}

type BypassKey struct {
	Token     string
	Name      string
	Host      string
	CreatedAt string
}



type CSPReport struct {
	ID                int
	Host              string
	BlockedURI        string
	ViolatedDirective string
	OriginalPolicy    string
	CreatedAt         string
}

type CSPReportPayload struct {
	CSPReport struct {
		DocumentURI        string `json:"document-uri"`
		Referrer           string `json:"referrer"`
		ViolatedDirective  string `json:"violated-directive"`
		EffectiveDirective string `json:"effective-directive"`
		OriginalPolicy     string `json:"original-policy"`
		Disposition        string `json:"disposition"`
		BlockedURI         string `json:"blocked-uri"`
		StatusCode         int    `json:"status-code"`
		ScriptSample       string `json:"script-sample"`
	} `json:"csp-report"`
}
