package security

import (
	"crypto/sha256"
	"encoding/base64"
	"regio/internal/db"
	"regio/internal/models"
	"sync"
)

var (
	// BypassKeys almacena los tokens que permiten saltarse la autenticación para un host.
	// Key: SHA-256 hash del token.
	BypassKeys = make(map[string]models.BypassKey)
	bpMu       sync.Mutex
)

func bypassHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// LoadBypassKeys carga las claves de bypass desde la base de datos.
func LoadBypassKeys() {
	rows, err := db.DB.Query("SELECT token, name, host, created_at, COALESCE(migrated, 0) FROM bypass_keys")
	if err != nil {
		return
	}
	defer rows.Close()

	bpMu.Lock()
	defer bpMu.Unlock()
	BypassKeys = make(map[string]models.BypassKey)
	for rows.Next() {
		var k models.BypassKey
		var migrated int
		if err := rows.Scan(&k.Token, &k.Name, &k.Host, &k.CreatedAt, &migrated); err == nil {
			if migrated == 0 {
				tokenHash := bypassHash(k.Token)
				db.DB.Exec("UPDATE bypass_keys SET token = ?, migrated = 1 WHERE token = ?", tokenHash, k.Token)
				k.Token = tokenHash
			}
			BypassKeys[k.Token] = k
		}
	}
}

// GetBypassKeys devuelve todas las claves de bypass registradas.
// El campo Token contiene el hash SHA-256 del token original.
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
	tokenHash := bypassHash(token)
	bpMu.Lock()
	defer bpMu.Unlock()
	key, exists := BypassKeys[tokenHash]
	if exists && key.Host == host {
		return true, key.Name
	}
	return false, ""
}

// AddBypassKey registra una nueva clave de bypass.
// El token se almacena como SHA-256 hash.
func AddBypassKey(token, name, host string) {
	tokenHash := bypassHash(token)
	db.DB.Exec("INSERT OR REPLACE INTO bypass_keys (token, name, host, migrated) VALUES (?, ?, ?, 1)", tokenHash, name, host)
	LoadBypassKeys()
}

// DeleteBypassKey elimina una clave de bypass por su hash.
func DeleteBypassKey(tokenHash string) {
	db.DB.Exec("DELETE FROM bypass_keys WHERE token = ?", tokenHash)
	LoadBypassKeys()
}
