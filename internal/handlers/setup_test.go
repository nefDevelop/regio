package handlers

import (
	"os"
	"testing"

	"regio/internal/auth"
	"regio/internal/db"
)

func TestMain(m *testing.M) {
	// Setup para los tests
	_ = os.MkdirAll("./data", 0755)
	
	// Establecer MASTER_KEY para los tests
	os.Setenv("MASTER_KEY", "test-master-key-32-bytes-length-!!!")
	auth.InitEncryption()

	// Inicializar DB (en los tests usará el archivo local ./data/REGIO.db)
	// En un entorno ideal usaríamos :memory: pero InitDB está hardcodeado a archivo.
	// Al menos nos aseguramos de que el directorio existe.
	db.InitDB()

	// Inicializar plantillas y otros recursos
	Init()

	// Mock de configuración mínima
	AdminDomain = "admin.test"
	NeedsSetup = false

	// Ejecutar tests
	code := m.Run()

	// Cleanup
	os.RemoveAll("./data")
	os.Exit(code)
}
