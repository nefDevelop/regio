package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 — required by TOTP (RFC 6238)
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"regio/internal/db"
	"regio/internal/models"
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
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		log.Fatal("Error crítico de entropía:", err)
	}
	// Parámetros Argon2id (mejora A3): t=2, m=32MiB, p=4.
	// Cumple el mínimo OWASP (m>=19MiB, t>=2) y REDUCE la memoria por intento
	// de 64 a 32 MB (menor amplificación de DoS en floods de login), con un
	// coste de CPU equivalente (t=2 x m/2). Los hashes antiguos conservan sus
	// propios params codificados y VerifyPassword los respeta.
	const (
		argonTime   = uint32(2)
		argonMemory = uint32(32 * 1024) // KiB
		argonThread = uint8(4)
		argonKeyLen = uint32(32)
	)
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThread, argonKeyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThread, b64Salt, b64Hash)
}

// VerifyPassword comprueba la contraseña contra el hash codificado.
// Los parámetros (m, t, p) se leen DEL PRÓPIO HASH: así los hashes antiguos
// (t=1, m=64MiB) siguen verificando tras cambiar los parámetros de HashPassword
// (mejora A3 — antes estaban hardcodeados y cualquier cambio de params
// bloquearía a todos los usuarios existentes).
func VerifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	// ["", "argon2id", "v=19", "m=65536,t=1,p=4", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}

	// Se parsea en uint64 y SE ACOTA antes de cualquier conversión (evita el
	// overflow de G115: un param corrupto nunca llega a las conversiones).
	var memory, timeCost, threads uint64
	for _, kv := range strings.Split(parts[3], ",") {
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			return false
		}
		n, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return false
		}
		switch key {
		case "m":
			memory = n
		case "t":
			timeCost = n
		case "p":
			threads = n
		}
	}
	// Límites sanos: los params vienen de la DB, pero se acotan para no
	// convertir un hash corrupto/envenenado en un DoS de memoria/CPU.
	if memory == 0 || memory > 512*1024 || timeCost == 0 || timeCost > 10 || threads == 0 || threads > 16 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	// Keylen de Argon2 acotado (16-64 bytes): además de higiene, deja la
	// conversión a uint32 demostradamente sin overflow.
	if err != nil || len(decodedHash) < 16 || len(decodedHash) > 64 {
		return false
	}
	hash := argon2.IDKey([]byte(password), salt,
		uint32(timeCost), uint32(memory), uint8(threads), uint32(len(decodedHash))) // #nosec G115 — valores acotados arriba (t<=10, m<=512MiB, p<=16, keylen<=64)
	return hmac.Equal(decodedHash, hash)
}

// GetTOTPCodeAt genera el código TOTP para un epoch concreto (RFC 6238).
// Se exporta para poder construir códigos de ventanas pasadas en tests
// (deriva de reloj, anti-replay).
func GetTOTPCodeAt(secret string, epoch int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(epoch)) // #nosec G115 — epoch fits in uint64

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

// GetTOTPCode devuelve el código TOTP vigente (compatibilidad).
func GetTOTPCode(secret string) string {
	return GetTOTPCodeAt(secret, time.Now().Unix()/30)
}

// VerifyTOTP valida code con ventana de deriva ±1 epoch (±30 s) usando
// comparación constante en tiempo (mejora A2). Devuelve true y el epoch del
// código aceptado — el epoch alimenta el anti-replay en los handlers.
func VerifyTOTP(secret, code string) (bool, int64) {
	if secret == "" || code == "" {
		return false, 0
	}
	actual := time.Now().Unix() / 30
	for _, epoch := range []int64{actual - 1, actual, actual + 1} {
		valid := GetTOTPCodeAt(secret, epoch)
		if valid != "" && subtle.ConstantTimeCompare([]byte(valid), []byte(code)) == 1 {
			return true, epoch
		}
	}
	return false, 0
}

func GenerateTOTPSecret() string {
	b := make([]byte, 10)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		log.Fatal("Error crítico de entropía:", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func GenerateSessionToken() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		log.Fatal("Error crítico de entropía:", err)
	}
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
