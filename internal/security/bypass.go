package security

import (
	"regio/internal/db"
	"regio/internal/models"
	"sync"
)

var (
	// BypassKeys almacena los tokens que permiten saltarse la autenticación para un host.
	BypassKeys = make(map[string]models.BypassKey)
	bpMu       sync.Mutex
)

// LoadBypassKeys carga las claves de bypass desde la base de datos.
func LoadBypassKeys() {
	rows, err := db.DB.Query("SELECT token, name, host, created_at FROM bypass_keys")
	if err != nil {
		return
	}
	defer rows.Close()

	bpMu.Lock()
	defer bpMu.Unlock()
	// Limpiar mapa actual antes de recargar
	BypassKeys = make(map[string]models.BypassKey)
	for rows.Next() {
		var k models.BypassKey
		if err := rows.Scan(&k.Token, &k.Name, &k.Host, &k.CreatedAt); err == nil {
			BypassKeys[k.Token] = k
		}
	}
}

// GetBypassKeys devuelve todas las claves de bypass registradas.
func GetBypassKeys() []models.BypassKey {
	bpMu.Lock()
	defer bpMu.Unlock()
	var keys []models.BypassKey
	for _, k := range BypassKeys {
		keys = append(keys, k)
	}
	return keys
}

// CheckBypass verifica si un token es válido para un host específico.
func CheckBypass(token string, host string) (bool, string) {
	bpMu.Lock()
	defer bpMu.Unlock()
	key, exists := BypassKeys[token]
	if exists && key.Host == host {
		return true, key.Name
	}
	return false, ""
}

// AddBypassKey registra una nueva clave de bypass.
func AddBypassKey(token, name, host string) {
	db.DB.Exec("INSERT OR REPLACE INTO bypass_keys (token, name, host) VALUES (?, ?, ?)", token, name, host)
	LoadBypassKeys()
}

// DeleteBypassKey elimina una clave de bypass.
func DeleteBypassKey(token string) {
	db.DB.Exec("DELETE FROM bypass_keys WHERE token = ?", token)
	LoadBypassKeys()
}
