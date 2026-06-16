package auth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"regio/internal/db"
	_ "modernc.org/sqlite"
)

func testDB(t *testing.T) {
	t.Helper()
	os.MkdirAll("./testdata", 0755)
	t.Cleanup(func() { os.RemoveAll("./testdata") })

	var err error
	db.DB, err = sql.Open("sqlite", "./testdata/test_regio.db")
	if err != nil {
		t.Fatalf("Error abriendo DB de test: %v", err)
	}
	t.Cleanup(func() { db.DB.Close() })

	db.DB.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, is_admin BOOLEAN)`)
	db.DB.Exec(`CREATE TABLE app_tokens (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, token_hash TEXT, last_used DATETIME)`)
}

func TestEncryptDecrypt(t *testing.T) {
	// Encrypt/Decrypt no necesita DB, solo MASTER_KEY en entorno
	tests := []string{
		"secreto-123",
		"JBSWY3DPEHPK3PXP",
		"a-really-long-secret-that-exceeds-32-bytes-for-testing-purposes",
		"",
	}
	for _, plain := range tests {
		enc, err := Encrypt(plain)
		if err != nil {
			t.Fatalf("Encrypt(%q) error: %v", plain, err)
		}
		if enc == "" {
			t.Errorf("Encrypt(%q) returned empty", plain)
		}
		dec, err := Decrypt(enc)
		if err != nil {
			t.Fatalf("Decrypt(%q) error: %v", enc, err)
		}
		if dec != plain {
			t.Errorf("roundtrip: got %q, want %q", dec, plain)
		}
	}
}

func TestDecryptInvalidInput(t *testing.T) {
	if _, err := Decrypt(""); err == nil {
		t.Error("Decrypt('') should error")
	}
	if _, err := Decrypt("invalid-base64!!"); err == nil {
		t.Error("Decrypt('invalid') should error")
	}
	if _, err := Decrypt(base64.StdEncoding.EncodeToString([]byte("too-short"))); err == nil {
		t.Error("Decrypt('too-short') should error (no nonce)")
	}
}

func TestHashPasswordVerify(t *testing.T) {
	passwords := []string{
		"this-is-a-long-password-123",
		"corta",
		"contraseña con ñ y espacios",
		"",
	}
	for _, pw := range passwords {
		hash := HashPassword(pw)
		if hash == "" {
			t.Errorf("HashPassword(%q) returned empty", pw)
		}
		if !strings.HasPrefix(hash, "$argon2id$v=19$") {
			t.Errorf("HashPassword(%q) = %q, want argon2id prefix", pw, hash)
		}
		if !VerifyPassword(pw, hash) {
			t.Errorf("VerifyPassword(%q, %q) = false, want true", pw, hash)
		}
	}
}

func TestVerifyPasswordWrong(t *testing.T) {
	hash := HashPassword("correct-password")
	if VerifyPassword("wrong-password", hash) {
		t.Error("VerifyPassword should return false for wrong password")
	}
	if VerifyPassword("", hash) {
		t.Error("VerifyPassword should return false for empty password")
	}
}

func TestVerifyPasswordInvalidHash(t *testing.T) {
	if VerifyPassword("pass", "") {
		t.Error("VerifyPassword('', '') should return false")
	}
	if VerifyPassword("pass", "not-a-valid-format") {
		t.Error("VerifyPassword('pass', 'not-a-valid-format') should return false")
	}
	if VerifyPassword("pass", "$argon2id$v=19$m=65536,t=1,p=4$badsalt") {
		t.Error("VerifyPassword should return false for truncated hash")
	}
}

func TestGenerateTOTPSecret(t *testing.T) {
	secret := GenerateTOTPSecret()
	if secret == "" {
		t.Fatal("GenerateTOTPSecret returned empty")
	}
	data, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("GenerateTOTPSecret = %q, not valid base32: %v", secret, err)
	}
	if len(data) != 10 {
		t.Errorf("GenerateTOTPSecret len = %d, want 10 bytes", len(data))
	}
	// Verify determinism is not the case (random)
	secret2 := GenerateTOTPSecret()
	if secret == secret2 {
		t.Error("Two GenerateTOTPSecret calls returned the same value")
	}
}

func TestGetTOTPCode(t *testing.T) {
	secret := GenerateTOTPSecret()
	code := GetTOTPCode(secret)
	if len(code) != 6 {
		t.Errorf("GetTOTPCode = %q, want 6 digits", code)
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("GetTOTPCode = %q, contains non-digit", code)
		}
	}
}

func TestGetTOTPCodeInvalidSecret(t *testing.T) {
	if code := GetTOTPCode("!!!!invalid!!!!"); code != "" {
		t.Errorf("GetTOTPCode('invalid') = %q, want empty", code)
	}
}

func TestGenerateSessionToken(t *testing.T) {
	token := GenerateSessionToken()
	if token == "" {
		t.Fatal("GenerateSessionToken returned empty")
	}
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("GenerateSessionToken = %q, not valid base64url: %v", token, err)
	}
	if len(data) != 32 {
		t.Errorf("GenerateSessionToken len = %d, want 32 bytes", len(data))
	}
	// Verify uniqueness
	token2 := GenerateSessionToken()
	if token == token2 {
		t.Error("Two GenerateSessionToken calls returned the same value")
	}
}

func TestVerifyAppToken(t *testing.T) {
	testDB(t)

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
