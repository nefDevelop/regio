package security

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestSafeDialContextValidation(t *testing.T) {
	// Limpiar antes de test
	AllowedNetworks = nil
	AllowLoopback = false
	InitAllowedNetworks("192.168.30.0/24")

	// Test whitelisted private IP
	_, err := SafeDialContext(context.Background(), "tcp", "192.168.30.30:80")
	// Fallará en el Dial real (connection refused/timeout), pero NO debe fallar por el bloqueo de IP privada
	if err != nil && strings.Contains(err.Error(), "acceso a IP privada bloqueado") {
		t.Errorf("IP privada permitida fue bloqueada: %v", err)
	}

	// Test non-whitelisted private IP
	_, err = SafeDialContext(context.Background(), "tcp", "192.168.1.1:80")
	if err == nil || !strings.Contains(err.Error(), "acceso a IP privada bloqueado") {
		t.Errorf("IP privada NO permitida no fue bloqueada correctamente: %v", err)
	}
}

func TestInitAllowedNetworks(t *testing.T) {
	// Limpiar antes de test
	AllowedNetworks = nil

	err := InitAllowedNetworks("192.168.30.0/24, 10.0.0.0/8")
	if err != nil {
		t.Fatalf("InitAllowedNetworks falló: %v", err)
	}

	if len(AllowedNetworks) != 2 {
		t.Errorf("Se esperaban 2 redes, se obtuvieron %d", len(AllowedNetworks))
	}

	tests := []struct {
		ip      string
		allowed bool
	}{
		{"192.168.30.1", true},
		{"192.168.30.254", true},
		{"192.168.1.1", false},
		{"10.0.0.5", true},
		{"172.16.0.1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		isPrivate := IsPrivateIP(ip)
		if !isPrivate && tt.allowed {
			// Si no es privada, no debería estar en AllowedNetworks para este test (aunque AllowedNetworks solo contiene privadas aquí)
			continue
		}

		allowed := false
		for _, subnet := range AllowedNetworks {
			if subnet.Contains(ip) {
				allowed = true
				break
			}
		}

		if allowed != tt.allowed {
			t.Errorf("IP %s: allowed=%v, want %v", tt.ip, allowed, tt.allowed)
		}
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip        string
		isPrivate bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false},
		{"192.168.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		res := IsPrivateIP(ip)
		if res != tt.isPrivate {
			t.Errorf("IsPrivateIP(%s) = %v; want %v", tt.ip, res, tt.isPrivate)
		}
	}
}
