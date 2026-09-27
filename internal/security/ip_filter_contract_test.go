package security

import (
	"testing"
	"time"

	"regio/internal/db"
	"regio/internal/models"
)

// TestIPFilterContract cubre InitIPFilter / BanIP / UnbanIP / GetBannedIPs /
// LimpiarBloqueosExpirados (0% pkg-local en el baseline).
func TestIPFilterContract(t *testing.T) {
	limpiarIntentos := func() {
		ipMu.Lock()
		IntentosDB = make(map[string]*models.Intento)
		ipMu.Unlock()
	}
	t.Cleanup(func() {
		limpiarIntentos()
		db.DB.Exec("DELETE FROM banned_ips")
	})

	t.Run("BanIP + IsIPBlocked + GetBannedIPs + UnbanIP", func(t *testing.T) {
		limpiarIntentos()
		db.DB.Exec("DELETE FROM banned_ips")

		ip := "203.0.113.200"
		if bloqueada, _ := IsIPBlocked(ip); bloqueada {
			t.Fatal("no debería estar bloqueada al inicio")
		}

		BanIP(ip, "manual", time.Hour)
		if bloqueada, motivo := IsIPBlocked(ip); !bloqueada || motivo != "IP bloqueada individualmente" {
			t.Errorf("IsIPBlocked = (%v, %q); want (true, 'IP bloqueada individualmente')", bloqueada, motivo)
		}
		if !rowContains(GetBannedIPs(), ip) {
			t.Error("GetBannedIPs no incluye la IP baneada")
		}
		if !banRowExists(ip) {
			t.Error("BanIP debe persistir en banned_ips")
		}

		UnbanIP(ip)
		if bloqueada, _ := IsIPBlocked(ip); bloqueada {
			t.Error("UnbanIP no desbloqueó la IP")
		}
		if banRowExists(ip) {
			t.Error("UnbanIP debe borrar la fila de banned_ips")
		}
	})

	t.Run("InitIPFilter recarga bloqueos desde la DB", func(t *testing.T) {
		limpiarIntentos()
		db.DB.Exec("DELETE FROM banned_ips")

		ip := "203.0.113.201"
		hasta := time.Now().Add(time.Hour)
		db.DB.Exec("INSERT INTO banned_ips (ip, hasta, razon) VALUES (?, ?, 'persistido')", ip, hasta)
		// memoria vacía: InitIPFilter debe repoblarla
		InitIPFilter()

		if bloqueada, _ := IsIPBlocked(ip); !bloqueada {
			t.Error("InitIPFilter no cargó el bloqueo persistido")
		}
	})

	t.Run("LimpiarBloqueosExpirados elimina solo los vencidos", func(t *testing.T) {
		limpiarIntentos()
		vencida := "203.0.113.202"
		viva := "203.0.113.203"
		IntentosDB[vencida] = &models.Intento{Fallos: 99, BloqueadoHasta: time.Now().Add(-time.Hour)}
		IntentosDB[viva] = &models.Intento{Fallos: 99, BloqueadoHasta: time.Now().Add(time.Hour)}

		LimpiarBloqueosExpirados()

		if _, quedó := IntentosDB[vencida]; quedó {
			t.Error("el bloqueo vencido debió purgarse")
		}
		if _, quedó := IntentosDB[viva]; !quedó {
			t.Error("el bloqueo vivo no debe purgarse")
		}
	})
}

func rowContains(banned []models.BannedIP, target string) bool {
	for _, b := range banned {
		if b.Target == target {
			return true
		}
	}
	return false
}

func banRowExists(ip string) bool {
	var n int
	db.DB.QueryRow("SELECT COUNT(*) FROM banned_ips WHERE ip=?", ip).Scan(&n)
	return n > 0
}
