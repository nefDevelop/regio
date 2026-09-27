package security

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"regio/internal/db"
)

// snapshotSettings congela las claves de ajustes geo y las restaura al final.
func snapshotSettings(t *testing.T) {
	t.Helper()
	keys := []string{"geo_mode", "geo_countries", "geo_fail_mode"}
	prevPolicy := GetGlobalGeoPolicy()
	prev := map[string]string{}
	for _, k := range keys {
		if v, ok := db.GetSetting(k); ok {
			prev[k] = v
		}
	}
	t.Cleanup(func() {
		db.DB.Exec("DELETE FROM settings WHERE key IN ('geo_mode','geo_countries','geo_fail_mode')")
		for k, v := range prev {
			_ = db.SetSetting(k, v)
		}
		_ = SetGlobalGeoPolicy(prevPolicy)
	})
}

// TestInitGeoPolicyContract cubre InitGeoPolicy (0% en el baseline):
// prioridad env -> override de DB -> fallback ante configuración inválida.
func TestInitGeoPolicyContract(t *testing.T) {
	t.Run("solo variables de entorno (sin settings en DB)", func(t *testing.T) {
		snapshotSettings(t)
		db.DB.Exec("DELETE FROM settings WHERE key IN ('geo_mode','geo_countries','geo_fail_mode')")

		t.Setenv("GEO_MODE", "allow")
		t.Setenv("GEO_COUNTRIES", "es")
		t.Setenv("GEO_FAIL_MODE", "closed")
		InitGeoPolicy()

		v := GetGeoPolicyView()
		if v.Mode != "allow" || v.Countries != "ES" || v.FailMode != "closed" || v.Source != "env" {
			t.Errorf("vista = %+v; want allow/ES/closed/env", v)
		}
	})

	t.Run("los settings de DB sobrescriben el entorno", func(t *testing.T) {
		snapshotSettings(t)
		_ = db.SetSetting("geo_mode", "deny")
		_ = db.SetSetting("geo_countries", "IN")
		_ = db.SetSetting("geo_fail_mode", "open")

		t.Setenv("GEO_MODE", "allow")
		t.Setenv("GEO_COUNTRIES", "ES")
		t.Setenv("GEO_FAIL_MODE", "closed")
		InitGeoPolicy()

		v := GetGeoPolicyView()
		if v.Mode != "deny" || v.Countries != "IN" || v.FailMode != "open" || v.Source != "db" {
			t.Errorf("vista = %+v; want deny/IN/open/db", v)
		}
	})

	t.Run("entorno inválido (allow sin países) cae a off", func(t *testing.T) {
		snapshotSettings(t)
		db.DB.Exec("DELETE FROM settings WHERE key IN ('geo_mode','geo_countries','geo_fail_mode')")

		t.Setenv("GEO_MODE", "allow")
		t.Setenv("GEO_COUNTRIES", "")
		t.Setenv("GEO_FAIL_MODE", "closed")
		InitGeoPolicy()

		if v := GetGeoPolicyView(); v.Mode != "off" {
			t.Errorf("vista = %+v; want off ante config inválida", v)
		}
	})

	t.Run("settings corruptos en DB caen al default de entorno", func(t *testing.T) {
		snapshotSettings(t)
		_ = db.SetSetting("geo_mode", "banana")

		t.Setenv("GEO_MODE", "deny")
		t.Setenv("GEO_COUNTRIES", "IN")
		t.Setenv("GEO_FAIL_MODE", "closed")
		InitGeoPolicy()

		v := GetGeoPolicyView()
		if v.Mode != "deny" || v.Countries != "IN" || v.Source != "env" {
			t.Errorf("vista = %+v; want fallback a env (deny/IN)", v)
		}
	})
}

// TestGeoIPSinBaseDeDatos congela el comportamiento sin fichero .mmdb:
// InitGeoIP no aborta, LookupCountry devuelve error y el reload es no-op.
func TestGeoIPSinBaseDeDatos(t *testing.T) {
	geoIPLock.Lock()
	prevReader, prevPath, prevMod := geoReader, geoIPPath, geoIPModTime
	geoIPLock.Unlock()
	t.Cleanup(func() {
		geoIPLock.Lock()
		geoReader, geoIPPath, geoIPModTime = prevReader, prevPath, prevMod
		geoIPLock.Unlock()
	})

	t.Setenv("GEOIP_DB_PATH", filepath.Join(t.TempDir(), "no-existe.mmdb"))
	InitGeoIP()

	v := GetGeoIPView()
	if v.Loaded {
		t.Error("Loaded debe ser false sin fichero")
	}
	if v.Path == "" || v.Path == DefaultGeoIPPath {
		t.Errorf("Path = %q; want la ruta del entorno", v.Path)
	}

	if _, err := LookupCountry(net.ParseIP("8.8.8.8")); err == nil {
		t.Error("LookupCountry sin BD debe devolver error")
	}

	// Recarga con fichero inexistente: no-op sin panic
	ReloadGeoIPIfChanged()

	// Abrir un fichero existente pero no válido como .mmdb
	invalido := filepath.Join(t.TempDir(), "invalido.mmdb")
	if err := os.WriteFile(invalido, []byte("esto no es una base maxmind"), 0600); err != nil {
		t.Fatalf("creando fichero: %v", err)
	}
	t.Setenv("GEOIP_DB_PATH", invalido)
	InitGeoIP()
	if GetGeoIPView().Loaded {
		t.Error("un .mmdb inválido no debe marcar Loaded")
	}
}
