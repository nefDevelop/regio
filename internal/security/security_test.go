package security

import (
	"fmt"
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
