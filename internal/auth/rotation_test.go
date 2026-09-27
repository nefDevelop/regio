package auth

import (
	"database/sql"
	"os"
	"testing"

	"regio/internal/db"
)

// testDBTotp crea una fixture con la columna totp_secret (la fixture común
// de auth_test no la incluye) y restaura el handle global al final.
func testDBTotp(t *testing.T) {
	t.Helper()
	orig := db.DB
	_ = os.MkdirAll("./testdata", 0755)
	t.Cleanup(func() {
		if db.DB != nil {
			db.DB.Close()
		}
		db.DB = orig
		os.RemoveAll("./testdata")
	})

	var err error
	db.DB, err = sql.Open("sqlite", "./testdata/test_rotation.db")
	if err != nil {
		t.Fatalf("abriendo DB: %v", err)
	}
	if _, err := db.DB.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY,
		username TEXT,
		totp_secret TEXT
	)`); err != nil {
		t.Fatalf("creando users: %v", err)
	}
}

// TestRotateMasterKeyContract cubre RotateMasterKey y UpdateEncryptionKey
// (0% en el baseline). La clave maestra de todo el test se restaura siempre.
func TestRotateMasterKeyContract(t *testing.T) {
	claveActual := os.Getenv("MASTER_KEY")
	if claveActual == "" {
		t.Skip("MASTER_KEY no definida en el entorno de tests")
	}
	const claveNueva = "otra-clave-maestra-para-rotacion-123"

	// Cualquier salida del test debe restaurar la clave en memoria
	t.Cleanup(func() { UpdateEncryptionKey(claveActual) })

	testDBTotp(t)

	secret := "JBSWY3DPEHPK3PXP"
	enc, err := Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO users (id, username, totp_secret) VALUES (1, 'u', ?)", enc); err != nil {
		t.Fatalf("insert: %v", err)
	}

	t.Run("rotación re-cifra todos los secretos", func(t *testing.T) {
		count, err := RotateMasterKey(claveActual, claveNueva)
		if err != nil {
			t.Fatalf("RotateMasterKey: %v", err)
		}
		if count != 1 {
			t.Errorf("count = %d; want 1", count)
		}

		// Con la clave nueva activa, el secreto debe descifrarse
		var nuevoEnc string
		db.DB.QueryRow("SELECT totp_secret FROM users WHERE id=1").Scan(&nuevoEnc)
		if nuevoEnc == enc {
			t.Error("el secreto no fue re-cifrado (idéntico al original)")
		}
		plain, err := Decrypt(nuevoEnc)
		if err != nil || plain != secret {
			t.Errorf("Decrypt tras rotar = (%q, %v); want %q", plain, err, secret)
		}
	})

	t.Run("clave antigua incorrecta devuelve error", func(t *testing.T) {
		// NOTA: RotateMasterKey deja la clave "antigua" activa incluso al
		// fallar (comportamiento congelado; en el CLI el proceso aborta).
		_, err := RotateMasterKey("clave-totalmente-equivocada", claveNueva)
		if err == nil {
			t.Error("con la clave antigua incorrecta debe fallar")
		}
		// Restaurar para los siguientes subtests
		UpdateEncryptionKey(claveNueva)
	})

	t.Run("vuelta a la clave original", func(t *testing.T) {
		count, err := RotateMasterKey(claveNueva, claveActual)
		if err != nil {
			t.Fatalf("rotación inversa: %v", err)
		}
		if count != 1 {
			t.Errorf("count = %d; want 1", count)
		}
		var reenc string
		db.DB.QueryRow("SELECT totp_secret FROM users WHERE id=1").Scan(&reenc)
		plain, err := Decrypt(reenc)
		if err != nil || plain != secret {
			t.Errorf("Decrypt tras volver = (%q, %v); want %q", plain, err, secret)
		}
	})

	t.Run("UpdateEncryptionKey cambia la clave en memoria", func(t *testing.T) {
		cifradoViejo, _ := Encrypt("dato")
		UpdateEncryptionKey(claveNueva)
		if _, err := Decrypt(cifradoViejo); err == nil {
			t.Error("el cifrado con la clave vieja no debe descifrarse con la nueva")
		}
		cifradoNuevo, _ := Encrypt("dato")
		if plain, err := Decrypt(cifradoNuevo); err != nil || plain != "dato" {
			t.Errorf("roundtrip con clave nueva = (%q, %v)", plain, err)
		}
		UpdateEncryptionKey(claveActual)
	})
}
