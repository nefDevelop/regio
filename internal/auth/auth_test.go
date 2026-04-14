package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"database/sql"
	"regio/internal/db"
	"testing"

	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) {
	var err error
	db.DB, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Error abriendo DB en memoria: %v", err)
	}

	// Crear esquema mínimo para tests
	db.DB.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, is_admin BOOLEAN);`)
	db.DB.Exec(`CREATE TABLE app_tokens (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, token_hash TEXT UNIQUE, last_used DATETIME);`)
}

func TestVerifyAppToken(t *testing.T) {
	setupTestDB(t)
	defer db.DB.Close()

	// 1. Crear usuario de prueba
	db.DB.Exec("INSERT INTO users (id, username, is_admin) VALUES (1, 'testuser', 1)")

	// 2. Generar un token real para el test
	rawToken := "ABC-TOKEN-SECRETO-123"
	tokenName := "Test Device"
	
	// Calcular el hash exactamente como lo hace la lógica de producción
	h := sha256.Sum256([]byte(rawToken))
	encodedHash := base64.StdEncoding.EncodeToString(h[:])
	
	db.DB.Exec("INSERT INTO app_tokens (user_id, name, token_hash) VALUES (1, ?, ?)", tokenName, encodedHash)

	// --- TEST 1: Validación Exitosa ---
	user, name, ok := VerifyAppToken(rawToken)
	if !ok {
		t.Errorf("VerifyAppToken falló con un token válido")
	}
	if user.Username != "testuser" || !user.IsAdmin {
		t.Errorf("Usuario recuperado incorrecto: %+v", user)
	}
	if name != tokenName {
		t.Errorf("Nombre del token incorrecto: %s", name)
	}

	// --- TEST 2: Token Incorrecto ---
	_, _, ok = VerifyAppToken("TOKEN-FALSO")
	if ok {
		t.Errorf("VerifyAppToken aceptó un token falso")
	}

	// --- TEST 3: Intento de Inyección / Token Vacío ---
	_, _, ok = VerifyAppToken("")
	if ok {
		t.Errorf("VerifyAppToken aceptó un token vacío")
	}
}

func TestPasswordSecurity(t *testing.T) {
	pass := "mi-password-segura"
	hash := HashPassword(pass)

	// Verificar que el hash no contiene la contraseña en texto plano
	if strings.Contains(hash, pass) {
		t.Errorf("El hash contiene la contraseña en texto plano!")
	}

	// Verificar validación correcta
	if !VerifyPassword(pass, hash) {
		t.Errorf("Fallo al verificar contraseña correcta")
	}

	// Verificar rechazo de contraseña incorrecta
	if VerifyPassword("otra-cosa", hash) {
		t.Errorf("Aceptó una contraseña incorrecta")
	}
}
