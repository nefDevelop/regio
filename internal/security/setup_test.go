package security

import (
	"os"
	"testing"

	"regio/internal/db"
)

func TestMain(m *testing.M) {
	// Setup para los tests
	_ = os.MkdirAll("./data", 0755)

	// Inicializar DB
	db.InitDB()

	// Ejecutar tests
	code := m.Run()

	// Cleanup
	os.RemoveAll("./data")
	os.Exit(code)
}
