package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"regio/internal/db"
	"regio/internal/models"
	"golang.org/x/crypto/argon2"
)

var encryptionKey []byte

func init() {
	key := os.Getenv("MASTER_KEY")
	if key == "" {
		log.Println("[WARN] MASTER_KEY no configurada. El cifrado se inicializará cuando se llame a InitEncryption().")
		return
	}
	hash := sha256.Sum256([]byte(key))
	encryptionKey = hash[:]
}

// InitEncryption verifica que la clave de cifrado esté lista. Debe llamarse al arrancar.
func InitEncryption() {
	if encryptionKey == nil {
		key := os.Getenv("MASTER_KEY")
		if key != "" {
			hash := sha256.Sum256([]byte(key))
			encryptionKey = hash[:]
			return
		}
		log.Fatal("FATAL: La variable de entorno MASTER_KEY es obligatoria. El cifrado de secretos TOTP no puede funcionar sin ella.")
	}
}

func Encrypt(text string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(text), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(cryptoText string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext demasiado corto")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func HashPassword(password string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=1,p=4$%s$%s", b64Salt, b64Hash)
}

func VerifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return hmac.Equal(decodedHash, hash)
}

func GetTOTPCode(secret string) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	epoch := time.Now().Unix() / 30
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(epoch))

	h := hmac.New(sha1.New, key)
	h.Write(buf)
	sum := h.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3] & 0xff)))

	return fmt.Sprintf("%06d", value%1000000)
}

func GenerateTOTPSecret() string {
	b := make([]byte, 10)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func GenerateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func VerifyAppToken(token string) (*models.User, string, bool) {
	hash := sha256.Sum256([]byte(token))
	tokenHash := base64.StdEncoding.EncodeToString(hash[:])

	var user models.User
	var tokenName string
	err := db.DB.QueryRow(`
		SELECT u.id, u.username, u.is_admin, t.name
		FROM users u 
		JOIN app_tokens t ON u.id = t.user_id 
		WHERE t.token_hash = ?`, tokenHash).Scan(&user.ID, &user.Username, &user.IsAdmin, &tokenName)

	if err != nil {
		return nil, "", false
	}

	db.DB.Exec("UPDATE app_tokens SET last_used = ? WHERE token_hash = ?", time.Now(), tokenHash)

	return &user, tokenName, true
}

// UpdateEncryptionKey actualiza la clave de cifrado en memoria (para rotación).
func UpdateEncryptionKey(newKeyRaw string) {
	hash := sha256.Sum256([]byte(newKeyRaw))
	encryptionKey = hash[:]
}

// RotateMasterKey re-cifra todos los secretos TOTP con una nueva clave maestra.
// Debe llamarse con la clave antigua activa en encryptionKey.
// RotateMasterKey re-cifra todos los secretos TOTP usando una nueva clave maestra.
func RotateMasterKey(oldKeyRaw, newKeyRaw string) (int, error) {
	// 1. Validar la clave antigua configurándola temporalmente
	UpdateEncryptionKey(oldKeyRaw)

	// 2. Leer todos los secretos y probar a descifrarlos
	rows, err := db.DB.Query("SELECT id, COALESCE(totp_secret, '') FROM users WHERE totp_secret IS NOT NULL AND totp_secret != ''")
	if err != nil {
		return 0, fmt.Errorf("error leyendo usuarios: %v", err)
	}
	defer rows.Close()

	type secretPair struct {
		id        int
		plaintext string
	}
	var secrets []secretPair

	for rows.Next() {
		var id int
		var encrypted string
		rows.Scan(&id, &encrypted)
		if encrypted == "" {
			continue
		}
		plaintext, err := Decrypt(encrypted)
		if err != nil {
			return 0, fmt.Errorf("error descifrando secreto del usuario %d (¿clave antigua incorrecta?): %v", id, err)
		}
		secrets = append(secrets, secretPair{id: id, plaintext: plaintext})
	}

	// 3. Cambiar a la nueva clave
	UpdateEncryptionKey(newKeyRaw)

	// 4. Re-cifrar todos los secretos con la nueva clave
	count := 0
	for _, s := range secrets {
		newEncrypted, err := Encrypt(s.plaintext)
		if err != nil {
			return count, fmt.Errorf("error re-cifrando secreto del usuario %d: %v", s.id, err)
		}
		_, err = db.DB.Exec("UPDATE users SET totp_secret = ? WHERE id = ?", newEncrypted, s.id)
		if err != nil {
			// Intento desesperado de volver a la clave vieja si falla la DB? 
			// No, mejor loguear el fallo crítico.
			return count, fmt.Errorf("error guardando secreto re-cifrado del usuario %d: %v", s.id, err)
		}
		count++
	}

	db.LogEvent(fmt.Sprintf("[PASS] MASTER_KEY rotada exitosamente. %d secretos TOTP re-cifrados.", count), "Sistema")
	return count, nil
}
