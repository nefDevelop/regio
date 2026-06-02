package security

import (
	"fmt"
	"net/http"
	"net/url"
	"regio/internal/db"
	"regio/internal/models"
	"testing"
)

func TestGetSubnet(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
	}{
		{"192.168.1.10", "192.168.1.0/24"},
		{"192.168.1.254", "192.168.1.0/24"},
		{"10.0.0.1", "10.0.0.0/24"},
		{"invalid", ""},
	}

	for _, tt := range tests {
		res := GetSubnet(tt.ip)
		if res != tt.expected {
			t.Errorf("GetSubnet(%s) = %s; want %s", tt.ip, res, tt.expected)
		}
	}
}

func TestFail2BanIndividual(t *testing.T) {
	db.InitDB()
	// Limpiar estado
	ipMu.Lock()
	IntentosDB = make(map[string]*models.Intento)
	ipMu.Unlock()

	ip := "1.2.3.4"

	// Simular 4 fallos (no debería bloquear todavía)
	for i := 0; i < 4; i++ {
		RegistrarFallo(ip)
		blocked, _ := IsIPBlocked(ip)
		if blocked {
			t.Errorf("IP %s bloqueada prematuramente en intento %d", ip, i+1)
		}
	}

	// El 5º fallo debe bloquear la IP
	RegistrarFallo(ip)
	blocked, _ := IsIPBlocked(ip)
	if !blocked {
		t.Errorf("IP %s NO bloqueada tras 5 intentos", ip)
	}
}

func TestFail2BanSubnet(t *testing.T) {
	db.InitDB()
	// Limpiar estado
	ipMu.Lock()
	IntentosDB = make(map[string]*models.Intento)
	ipMu.Unlock()

	subnetBase := "10.10.10.%d"

	// Simular fallos desde 14 IPs diferentes del mismo rango /24
	for i := 1; i <= 14; i++ {
		ip := fmt.Sprintf(subnetBase, i)
		RegistrarFallo(ip)
		
		blocked, _ := IsIPBlocked(ip)
		if blocked {
			t.Errorf("IP %s bloqueada prematuramente. El bloqueo debería ser por rango, no individual.", ip)
		}
	}

	// El 15º fallo desde otra IP del mismo rango debe activar el bloqueo de subred
	ip15 := "10.10.10.254"
	RegistrarFallo(ip15)

	// Ahora cualquier IP de ese rango debería estar bloqueada
	blocked, motivo := IsIPBlocked("10.10.10.100")
	if !blocked {
		t.Errorf("El rango 10.10.10.0/24 debería estar bloqueado")
	}
	if motivo != "Rango de red bloqueado" {
		t.Errorf("Motivo incorrecto: %s", motivo)
	}
}

// TestWAFInputSizeLimit verifica que inputs > 4KB son bloqueados (M05).
func TestWAFInputSizeLimit(t *testing.T) {
	largeInput := string(make([]byte, 5000))
	if !isMalicious(largeInput) {
		t.Error("isMalicious debería bloquear input de 5000 bytes")
	}

	smallInput := string(make([]byte, 1000))
	if isMalicious(smallInput) {
		t.Error("isMalicious no debería bloquear input de 1000 bytes")
	}
}

// TestWAFNewSQLiPatterns verifica las nuevas detecciones de SQLi (M05).
func TestWAFNewSQLiPatterns(t *testing.T) {
	tests := []struct {
		input    string
		blocked  bool
		scenario string
	}{
		{"exec(xp_cmdshell)", true, "exec xp_cmdshell"},
		{"WAITFOR DELAY '0:0:5'", true, "WAITFOR DELAY"},
		{"SLEEP(5)", true, "SLEEP"},
		{"pg_sleep(5)", true, "pg_sleep"},
		{"0xdeadbeef", true, "Hex literal 0x"},
		{"information_schema.tables", true, "information_schema"},
		{"CHAR(65,66,67)", true, "CHAR function"},
		{"NCHAR(65)", true, "NCHAR function"},
		{"SELECT * FROM users", true, "SELECT FROM"},
		{"DROP TABLE users", true, "DROP TABLE"},
		{"UNION SELECT 1,2,3 --", true, "UNION SELECT"},
		{"delete from users", true, "DELETE FROM"},
		{"UPDATE users SET pass=1", true, "UPDATE SET"},

		{"safe-normal-query", false, "Texto normal"},
		{"hello world", false, "Texto inocuo"},
		{"SELECTION", false, "SELECT como parte de palabra"},
	}

	AllowLoopback = true
	defer func() { AllowLoopback = false }()

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			req := &http.Request{
				URL: &url.URL{Path: "/test", RawQuery: url.QueryEscape(tt.input)},
			}
			err := CheckWAF(req)
			if tt.blocked && err == nil {
				t.Errorf("CheckWAF debería BLOQUEAR %q pero fue permitido", tt.input)
			}
			if !tt.blocked && err != nil {
				t.Errorf("CheckWAF debería PERMITIR %q pero fue bloqueado: %v", tt.input, err)
			}
		})
	}
}
