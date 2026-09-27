package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// makeLegacyHash replica el formato EXACTO de HashPassword ANTES de la mejora
// A3: t=1, m=64MiB, p=4 (params hardcodeados en la verificación original).
func makeLegacyHash(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		t.Fatalf("salt: %v", err)
	}
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=1,p=4$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))
}

// TestVerifyPasswordCompatibilidadLegacy es la red de seguridad de A3: los
// hashes antiguos (t=1, m=64MiB) deben seguir verificando tras cambiar los
// parámetros de HashPassword, porque ahora los params se leen del hash.
func TestVerifyPasswordCompatibilidadLegacy(t *testing.T) {
	legacy := makeLegacyHash(t, "contrasena-legacy-123")
	if !VerifyPassword("contrasena-legacy-123", legacy) {
		t.Error("un hash LEGACY (t=1, m=64MiB) dejó de verificar: los params no se leen del hash")
	}
	if VerifyPassword("contrasena-equivocada", legacy) {
		t.Error("contraseña incorrecta aceptada sobre hash legacy")
	}

	// Hash nuevo con los params de A3
	nuevo := HashPassword("contrasena-nueva-123")
	if !strings.Contains(nuevo, "m=32768,t=2,p=4") {
		t.Errorf("hash nuevo = %q; want params m=32768,t=2,p=4 (A3)", nuevo)
	}
	if !VerifyPassword("contrasena-nueva-123", nuevo) {
		t.Error("roundtrip del hash nuevo falló")
	}
	// Verificación cruzada: contraseña de un hash en el otro nunca coincide
	if VerifyPassword("contrasena-nueva-123", legacy) {
		t.Error("cross-verify entre hashes distintos no debe pasar")
	}
}

// TestVerifyPasswordParamsCorruptos verifica que params manipulados (desde
// una DB envenenada) se rechazan con límites sanos en vez de provocar un
// DoS de memoria/CPU.
func TestVerifyPasswordParamsCorruptos(t *testing.T) {
	corruptos := []string{
		// memoria fuera de límite (>512MiB en KiB)
		"$argon2id$v=19$m=999999999,t=1,p=4$c2FsdHNhbHQ$aGFzaGhhc2g",
		// tiempo fuera de límite (>10)
		"$argon2id$v=19$m=65536,t=99,p=4$c2FsdHNhbHQ$aGFzaGhhc2g",
		// hilos fuera de límite (>16)
		"$argon2id$v=19$m=65536,t=1,p=99$c2FsdHNhbHQ$aGFzaGhhc2g",
		// params no numéricos
		"$argon2id$v=19$m=abc,t=1,p=4$c2FsdHNhbHQ$aGFzaGhhc2g",
		// sección de params ausente/inválida
		"$argon2id$v=19$rotsop$c2FsdHNhbHQ$aGFzaGhhc2g",
		// no argon2id
		"$bcrypt$v=19$m=65536,t=1,p=4$c2FsdHNhbHQ$aGFzaGhhc2g",
	}
	for _, h := range corruptos {
		if VerifyPassword("cualquiera", h) {
			t.Errorf("hash con params corruptos aceptado: %s", h)
		}
	}
}
