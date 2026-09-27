package security

import (
	"errors"
	"net"
	"testing"

	"regio/internal/db"
)

// stubLookup inyecta un resolvedor de países falso para los tests.
func stubLookup(t *testing.T, fn func(net.IP) (string, error)) {
	t.Helper()
	orig := lookupCountryFunc
	lookupCountryFunc = fn
	t.Cleanup(func() { lookupCountryFunc = orig })
}

// setGlobalPolicyForTest fuerza la política global y la restaura al final.
func setGlobalPolicyForTest(t *testing.T, p GeoPolicy) {
	t.Helper()
	if err := validateGeoPolicy(p); err != nil {
		t.Fatalf("política de test inválida: %v", err)
	}
	geoMu.Lock()
	orig := geoGlobal
	geoGlobal = p
	geoMu.Unlock()
	t.Cleanup(func() {
		geoMu.Lock()
		geoGlobal = orig
		geoMu.Unlock()
	})
}

func TestParseCountries(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{"una país", "es", []string{"ES"}, false},
		{"varios con espacios", "es, fr , PT", []string{"ES", "FR", "PT"}, false},
		{"duplicados", "ES,es", []string{"ES"}, false},
		{"vacío", "", nil, false},
		{"nombre completo", "España", nil, true},
		{"un solo carácter", "E", nil, true},
		{"números", "12", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCountries(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCountries(%q) debería fallar", tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCountries(%q) error inesperado: %v", tt.raw, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseCountries(%q) = %v; want %v", tt.raw, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ParseCountries(%q)[%d] = %s; want %s", tt.raw, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestValidateGeoSelection(t *testing.T) {
	if _, err := ValidateGeoSelection("", ""); err != nil {
		t.Errorf("modo heredar con lista vacía debería ser válido: %v", err)
	}
	if _, err := ValidateGeoSelection("allow", ""); err == nil {
		t.Error("allow sin países debería fallar")
	}
	if _, err := ValidateGeoSelection("deny", "ES"); err != nil {
		t.Errorf("deny con ES debería ser válido: %v", err)
	}
	if _, err := ValidateGeoSelection("whatever", "ES"); err == nil {
		t.Error("modo inválido debería fallar")
	}
	if _, err := ValidateGeoSelection("allow", "España"); err == nil {
		t.Error("país inválido debería fallar")
	}
}

func TestNewGeoPolicy(t *testing.T) {
	p, err := NewGeoPolicy("ALLOW", " es ", "OPEN")
	if err != nil {
		t.Fatalf("NewGeoPolicy error: %v", err)
	}
	if p.Mode != GeoModeAllow || p.FailMode != GeoFailOpen || len(p.Countries) != 1 || p.Countries[0] != "ES" {
		t.Errorf("política normalizada incorrecta: %+v", p)
	}

	if _, err := NewGeoPolicy("allow", "ES", "maybe"); err == nil {
		t.Error("fail mode inválido debería fallar")
	}
	if _, err := NewGeoPolicy("", "", ""); err != nil {
		t.Errorf("defaults deberían ser válidos: %v", err)
	}
}

func TestCheckGeoPolicyAllowlist(t *testing.T) {
	setGlobalPolicyForTest(t, GeoPolicy{Mode: GeoModeAllow, Countries: []string{"ES"}, FailMode: GeoFailOpen})

	stubLookup(t, func(ip net.IP) (string, error) { return "IN", nil })
	if err := CheckGeoPolicy("203.0.113.10", "app.test"); !errors.Is(err, ErrGeoBlocked) {
		t.Errorf("allow [ES] con país IN debería bloquear, got %v", err)
	}

	stubLookup(t, func(ip net.IP) (string, error) { return "ES", nil })
	if err := CheckGeoPolicy("203.0.113.10", "app.test"); err != nil {
		t.Errorf("allow [ES] con país ES debería pasar, got %v", err)
	}

	// País desconocido + fail-open -> pasa
	stubLookup(t, func(ip net.IP) (string, error) { return "", nil })
	if err := CheckGeoPolicy("203.0.113.10", "app.test"); err != nil {
		t.Errorf("fail-open con país desconocido debería pasar, got %v", err)
	}
}

func TestCheckGeoPolicyDenylist(t *testing.T) {
	setGlobalPolicyForTest(t, GeoPolicy{Mode: GeoModeDeny, Countries: []string{"IN"}, FailMode: GeoFailOpen})

	stubLookup(t, func(ip net.IP) (string, error) { return "IN", nil })
	if err := CheckGeoPolicy("203.0.113.10", "app.test"); !errors.Is(err, ErrGeoBlocked) {
		t.Errorf("deny [IN] con país IN debería bloquear, got %v", err)
	}

	stubLookup(t, func(ip net.IP) (string, error) { return "DE", nil })
	if err := CheckGeoPolicy("203.0.113.10", "app.test"); err != nil {
		t.Errorf("deny [IN] con país DE debería pasar, got %v", err)
	}
}

func TestCheckGeoPolicyFailClosed(t *testing.T) {
	setGlobalPolicyForTest(t, GeoPolicy{Mode: GeoModeAllow, Countries: []string{"ES"}, FailMode: GeoFailClosed})

	stubLookup(t, func(ip net.IP) (string, error) { return "", errors.New("bd no cargada") })
	if err := CheckGeoPolicy("203.0.113.10", "app.test"); !errors.Is(err, ErrGeoBlocked) {
		t.Errorf("fail-closed sin determinar país debería bloquear, got %v", err)
	}

	stubLookup(t, func(ip net.IP) (string, error) { return "ES", nil })
	if err := CheckGeoPolicy("203.0.113.10", "app.test"); err != nil {
		t.Errorf("fail-closed con país ES debería pasar, got %v", err)
	}
}

func TestCheckGeoPolicyOffNoLookup(t *testing.T) {
	setGlobalPolicyForTest(t, GeoPolicy{Mode: GeoModeOff, FailMode: GeoFailClosed})

	called := false
	stubLookup(t, func(ip net.IP) (string, error) {
		called = true
		return "IN", nil
	})

	if err := CheckGeoPolicy("203.0.113.10", "app.test"); err != nil {
		t.Errorf("modo off debería pasar siempre, got %v", err)
	}
	if called {
		t.Error("modo off no debería consultar la base de datos GeoIP")
	}
}

func TestCheckGeoPolicyPrivateIPBypass(t *testing.T) {
	setGlobalPolicyForTest(t, GeoPolicy{Mode: GeoModeAllow, Countries: []string{"ES"}, FailMode: GeoFailClosed})

	for _, ip := range []string{"192.168.1.10", "10.0.0.5", "127.0.0.1", "no-ip"} {
		called := false
		stubLookup(t, func(net.IP) (string, error) {
			called = true
			return "IN", nil
		})
		if err := CheckGeoPolicy(ip, "app.test"); err != nil {
			t.Errorf("IP privada/local %q no debería bloquearse, got %v", ip, err)
		}
		if called {
			t.Errorf("IP %q no debería consultar GeoIP", ip)
		}
	}
}

func TestCheckGeoPolicyHostOverride(t *testing.T) {
	// Global: desactivado
	setGlobalPolicyForTest(t, GeoPolicy{Mode: GeoModeOff, FailMode: GeoFailClosed})
	stubLookup(t, func(ip net.IP) (string, error) { return "IN", nil })

	// Override del servicio: solo ES
	SetHostGeoPolicy("app.test", "allow", []string{"ES"})
	defer DeleteHostGeoPolicy("app.test")

	if err := CheckGeoPolicy("203.0.113.10", "app.test:9999"); !errors.Is(err, ErrGeoBlocked) {
		t.Errorf("servicio con override allow [ES] y país IN debería bloquear, got %v", err)
	}
	if err := CheckGeoPolicy("203.0.113.10", "otro.test"); err != nil {
		t.Errorf("otro servicio sin override debe seguir la global (off), got %v", err)
	}

	// Restaurar herencia global
	SetHostGeoPolicy("app.test", "off", nil)
	if err := CheckGeoPolicy("203.0.113.10", "app.test"); err != nil {
		t.Errorf("override eliminado debería volver a la global (off), got %v", err)
	}
}

func TestReplaceHostGeoPolicies(t *testing.T) {
	setGlobalPolicyForTest(t, GeoPolicy{Mode: GeoModeOff, FailMode: GeoFailOpen})
	stubLookup(t, func(ip net.IP) (string, error) { return "IN", nil })
	defer func() {
		geoMu.Lock()
		geoHosts = map[string]geoHostPolicy{}
		geoMu.Unlock()
	}()

	ReplaceHostGeoPolicies(
		map[string]string{"ok.test": "allow", "mala.test": "allow", "off.test": "off"},
		map[string]string{"ok.test": "ES", "mala.test": "España"},
	)

	if err := CheckGeoPolicy("203.0.113.10", "ok.test"); !errors.Is(err, ErrGeoBlocked) {
		t.Errorf("ok.test con allow [ES] y país IN debería bloquear, got %v", err)
	}
	if err := CheckGeoPolicy("203.0.113.10", "mala.test"); err != nil {
		t.Errorf("política inválida debe ignorarse (hereda global off), got %v", err)
	}
	if err := CheckGeoPolicy("203.0.113.10", "off.test"); err != nil {
		t.Errorf("off.test debería estar sin filtro, got %v", err)
	}
}

func TestSaveGlobalGeoPolicyPersistsSettings(t *testing.T) {
	p, err := NewGeoPolicy("deny", "IN", "closed")
	if err != nil {
		t.Fatalf("NewGeoPolicy: %v", err)
	}
	if err := SaveGlobalGeoPolicy(p); err != nil {
		t.Fatalf("SaveGlobalGeoPolicy: %v", err)
	}
	t.Cleanup(func() {
		// Limpiar ajustes de test
		_ = db.SetSetting("geo_mode", "off")
		_ = db.SetSetting("geo_countries", "")
		_ = db.SetSetting("geo_fail_mode", "open")
		_ = SetGlobalGeoPolicy(GeoPolicy{Mode: GeoModeOff, FailMode: GeoFailOpen})
	})

	if v, ok := db.GetSetting("geo_mode"); !ok || v != "deny" {
		t.Errorf("geo_mode guardado = %q, want deny", v)
	}
	view := GetGeoPolicyView()
	if view.Mode != GeoModeDeny || view.FailMode != GeoFailClosed || view.Countries != "IN" || view.Source != "db" {
		t.Errorf("vista de política incorrecta: %+v", view)
	}
}
