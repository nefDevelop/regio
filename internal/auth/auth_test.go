package auth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"os"
	"testing"

	"regio/internal/db"
	_ "modernc.org/sqlite"
)

func TestVerifyAppToken(t *testing.T) {
	// Setup: Crear base de datos temporal
	os.MkdirAll("./testdata", 0755)
	testDBPath := "./testdata/test_regio.db"
	defer os.RemoveAll("./testdata")

	var err error
	db.DB, err = sql.Open("sqlite", testDBPath)
	if err != nil {
		t.Fatalf("Error abriendo DB de test: %v", err)
	}
	defer db.DB.Close()

	// Crear tablas necesarias
	db.DB.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, is_admin BOOLEAN)`)
	db.DB.Exec(`CREATE TABLE app_tokens (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, token_hash TEXT, last_used DATETIME)`)

	// Insertar datos de prueba
	testUserID := 1
	testUsername := "testuser"
	db.DB.Exec("INSERT INTO users (id, username, is_admin) VALUES (?, ?, ?)", testUserID, testUsername, 1)

	rawToken := "Wrtav3ig2FNmdwNlf5qJWVq1X7lLfu3Y4105oL5n3gQ"
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := base64.StdEncoding.EncodeToString(hash[:])
	db.DB.Exec("INSERT INTO app_tokens (user_id, name, token_hash) VALUES (?, ?, ?)", testUserID, "test-token", tokenHash)

	// Ejecutar Test
	user, tokenName, valid := VerifyAppToken(rawToken)

	// Verificaciones
	if !valid {
		t.Errorf("VerifyAppToken falló: se esperaba que el token fuera válido")
	}
	if user == nil || user.Username != testUsername {
		t.Errorf("VerifyAppToken devolvió usuario incorrecto: esperado %s, obtenido %v", testUsername, user)
	}
	if tokenName != "test-token" {
		t.Errorf("VerifyAppToken devolvió nombre de token incorrecto: esperado 'test-token', obtenido '%s'", tokenName)
	}

	// Probar con token inválido
	_, _, validInvalid := VerifyAppToken("token-falso")
	if validInvalid {
		t.Errorf("VerifyAppToken aceptó un token inválido")
	}
}
