package security

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"regio/internal/db"
)

// Modos de política geográfica (GeoIP).
const (
	GeoModeOff   = "off"   // Sin filtrado
	GeoModeDeny  = "deny"  // Lista negra: se bloquean solo los países listados
	GeoModeAllow = "allow" // Lista blanca: solo pasan los países listados

	GeoFailOpen   = "open"   // País desconocido/sin BD -> permitir
	GeoFailClosed = "closed" // País desconocido/sin BD -> bloquear
)

// ErrGeoBlocked envuelve los errores producidos por la política geográfica.
// Permite detectar el bloqueo con errors.Is() en los handlers (403).
var ErrGeoBlocked = errors.New("acceso denegado por política geográfica")

// GeoPolicy es la política de filtrado por país aplicable globalmente o por servicio.
type GeoPolicy struct {
	Mode      string   // off|deny|allow
	Countries []string // Códigos ISO 3166-1 alpha-2 (ej: ES, IN)
	FailMode  string   // open|closed
}

// geoHostPolicy es la política propia de un servicio; FailMode siempre lo aporta la global.
type geoHostPolicy struct {
	Mode      string
	Countries []string
}

// GeoPolicyView es la vista de la política global para el panel admin.
type GeoPolicyView struct {
	Mode      string
	Countries string
	FailMode  string
	Source    string // "env" | "db"
}

var (
	geoMu     sync.RWMutex
	geoGlobal = GeoPolicy{Mode: GeoModeOff, FailMode: GeoFailOpen}
	geoHosts  = map[string]geoHostPolicy{}
	geoSource = "env"

	// lookupCountryFunc se inyecta en tests para no requerir una BD .mmdb real.
	lookupCountryFunc = LookupCountry
)

// ParseCountries normaliza una lista "es, fr" a ["ES","FR"] validando el formato ISO.
func ParseCountries(raw string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, c := range strings.Split(raw, ",") {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
			return nil, fmt.Errorf("código de país inválido: %q (usa ISO 3166-1 alpha-2, ej: ES)", c)
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// FormatCountries convierte ["ES","FR"] en "ES, FR".
func FormatCountries(countries []string) string {
	return strings.Join(countries, ", ")
}

// ValidateGeoSelection valida una selección de países del panel para una política dada.
// Devuelve los países parseados. mode "" o "off" no requieren países.
func ValidateGeoSelection(mode, countriesRaw string) ([]string, error) {
	countries, err := ParseCountries(countriesRaw)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", GeoModeOff:
	case GeoModeAllow, GeoModeDeny:
		if len(countries) == 0 {
			return nil, errors.New("indica al menos un país (ej: ES)")
		}
	default:
		return nil, fmt.Errorf("modo geográfico inválido: %q", mode)
	}
	return countries, nil
}

// NewGeoPolicy construye y valida la política global a partir de los campos del formulario.
func NewGeoPolicy(mode, countriesRaw, failMode string) (GeoPolicy, error) {
	var p GeoPolicy
	p.Mode = strings.ToLower(strings.TrimSpace(mode))
	if p.Mode == "" {
		p.Mode = GeoModeOff
	}
	countries, err := ValidateGeoSelection(p.Mode, countriesRaw)
	if err != nil {
		return p, err
	}
	p.Countries = countries

	p.FailMode = strings.ToLower(strings.TrimSpace(failMode))
	if p.FailMode == "" {
		p.FailMode = GeoFailOpen
	}
	if p.FailMode != GeoFailOpen && p.FailMode != GeoFailClosed {
		return p, fmt.Errorf("modo de fallo inválido: %q (usa open o closed)", failMode)
	}
	return p, nil
}

// InitGeoPolicy carga la política global: variables de entorno como default,
// sobrescritas por los valores guardados en la DB (panel admin) si existen.
func InitGeoPolicy() {
	p, err := NewGeoPolicy(os.Getenv("GEO_MODE"), os.Getenv("GEO_COUNTRIES"), os.Getenv("GEO_FAIL_MODE"))
	if err != nil {
		logGeoWarn(fmt.Sprintf("Configuración GeoIP inválida en el entorno (%v). Geobloqueo desactivado.", err))
		p = GeoPolicy{Mode: GeoModeOff, FailMode: GeoFailOpen}
	}
	source := "env"

	if db.DB != nil {
		if mode, ok := db.GetSetting("geo_mode"); ok {
			p.Mode = mode
			source = "db"
		}
		if raw, ok := db.GetSetting("geo_countries"); ok {
			countries, cerr := ParseCountries(raw)
			if cerr != nil {
				logGeoWarn(fmt.Sprintf("Países guardados en DB inválidos (%v); se ignoran.", cerr))
				p.Countries = nil
			} else {
				p.Countries = countries
			}
		}
		if fail, ok := db.GetSetting("geo_fail_mode"); ok && (fail == GeoFailOpen || fail == GeoFailClosed) {
			p.FailMode = fail
		}
		if verr := validateGeoPolicy(p); verr != nil {
			logGeoWarn(fmt.Sprintf("Política geográfica guardada inválida (%v); se usa el default de entorno.", verr))
			envPolicy, eerr := NewGeoPolicy(os.Getenv("GEO_MODE"), os.Getenv("GEO_COUNTRIES"), os.Getenv("GEO_FAIL_MODE"))
			if eerr != nil {
				envPolicy = GeoPolicy{Mode: GeoModeOff, FailMode: GeoFailOpen}
			}
			p = envPolicy
			source = "env"
		}
	}

	geoMu.Lock()
	geoGlobal = p
	geoSource = source
	geoMu.Unlock()

	if p.Mode == GeoModeOff {
		logGeoInfo("Geobloqueo por país: desactivado")
	} else {
		logGeoInfo(fmt.Sprintf("Geobloqueo por país: modo=%s países=[%s] fail=%s (origen: %s)",
			p.Mode, FormatCountries(p.Countries), p.FailMode, source))
	}
}

func validateGeoPolicy(p GeoPolicy) error {
	switch p.Mode {
	case GeoModeOff:
	case GeoModeAllow, GeoModeDeny:
		if len(p.Countries) == 0 {
			return errors.New("la política requiere al menos un país")
		}
	default:
		return fmt.Errorf("modo geográfico inválido: %q", p.Mode)
	}
	if p.FailMode != GeoFailOpen && p.FailMode != GeoFailClosed {
		return fmt.Errorf("modo de fallo inválido: %q", p.FailMode)
	}
	return nil
}

// GetGlobalGeoPolicy devuelve una copia de la política global vigente.
func GetGlobalGeoPolicy() GeoPolicy {
	geoMu.RLock()
	defer geoMu.RUnlock()
	return geoGlobal
}

// SetGlobalGeoPolicy actualiza la política global en memoria (validada), sin persistir.
func SetGlobalGeoPolicy(p GeoPolicy) error {
	if err := validateGeoPolicy(p); err != nil {
		return err
	}
	geoMu.Lock()
	geoGlobal = p
	geoMu.Unlock()
	return nil
}

// SaveGlobalGeoPolicy persiste la política global en la DB y la aplica en memoria.
func SaveGlobalGeoPolicy(p GeoPolicy) error {
	if err := validateGeoPolicy(p); err != nil {
		return err
	}
	if err := db.SetSetting("geo_mode", p.Mode); err != nil {
		return err
	}
	if err := db.SetSetting("geo_countries", FormatCountries(p.Countries)); err != nil {
		return err
	}
	if err := db.SetSetting("geo_fail_mode", p.FailMode); err != nil {
		return err
	}
	geoMu.Lock()
	geoGlobal = p
	geoSource = "db"
	geoMu.Unlock()
	return nil
}

// GetGeoPolicyView expone la política global para el panel admin.
func GetGeoPolicyView() GeoPolicyView {
	geoMu.RLock()
	defer geoMu.RUnlock()
	return GeoPolicyView{
		Mode:      geoGlobal.Mode,
		Countries: FormatCountries(geoGlobal.Countries),
		FailMode:  geoGlobal.FailMode,
		Source:    geoSource,
	}
}

// SetHostGeoPolicy define la política de un servicio. Solo "allow" o "deny"
// crean un override; cualquier otro modo elimina el override (hereda la global).
func SetHostGeoPolicy(host, mode string, countries []string) {
	host = normalizeGeoHost(host)
	mode = strings.ToLower(strings.TrimSpace(mode))
	geoMu.Lock()
	defer geoMu.Unlock()
	if mode != GeoModeAllow && mode != GeoModeDeny {
		delete(geoHosts, host)
		return
	}
	geoHosts[host] = geoHostPolicy{Mode: mode, Countries: countries}
}

// DeleteHostGeoPolicy elimina la política de un servicio (vuelve a la global).
func DeleteHostGeoPolicy(host string) {
	geoMu.Lock()
	defer geoMu.Unlock()
	delete(geoHosts, normalizeGeoHost(host))
}

// ReplaceHostGeoPolicies sincroniza las políticas por servicio desde la configuración cargada.
func ReplaceHostGeoPolicies(modes, countryMap map[string]string) {
	newHosts := map[string]geoHostPolicy{}
	for host, mode := range modes {
		mode = strings.ToLower(strings.TrimSpace(mode))
		if mode == "" || mode == GeoModeOff {
			continue
		}
		countries, err := ParseCountries(countryMap[host])
		if err != nil || len(countries) == 0 {
			logGeoWarn(fmt.Sprintf("Política por servicio inválida para %q; se ignora.", host))
			continue
		}
		newHosts[normalizeGeoHost(host)] = geoHostPolicy{Mode: mode, Countries: countries}
	}
	geoMu.Lock()
	geoHosts = newHosts
	geoMu.Unlock()
}

// CheckGeoPolicy aplica la política geográfica a la IP de origen para el host indicado.
// Devuelve un error envuelto con ErrGeoBlocked si la petición debe rechazarse.
func CheckGeoPolicy(ipStr, host string) error {
	geoMu.RLock()
	pol := geoGlobal
	override, hasOverride := geoHosts[normalizeGeoHost(host)]
	geoMu.RUnlock()

	if hasOverride {
		pol.Mode = override.Mode
		pol.Countries = override.Countries
		// FailMode siempre procede de la política global
	}

	if pol.Mode == GeoModeOff || len(pol.Countries) == 0 {
		return nil
	}

	ip := net.ParseIP(ipStr)
	// Las IPs privadas/locales/No-global-unicast no se geolocalizan: nunca se bloquean por país.
	if ip == nil || IsPrivateIP(ip) || !ip.IsGlobalUnicast() {
		return nil
	}

	country, err := lookupCountryFunc(ip)
	if err != nil || country == "" {
		if pol.FailMode == GeoFailClosed {
			msg := "país no determinable"
			if err != nil {
				msg = fmt.Sprintf("país no determinable (%v)", err)
			}
			logGeoBlock(fmt.Sprintf("Petición bloqueada (fail-closed) en %q: %s", normalizeGeoHost(host), msg))
			return fmt.Errorf("%w: %s", ErrGeoBlocked, msg)
		}
		return nil
	}

	country = strings.ToUpper(country)
	listed := containsCountry(pol.Countries, country)
	blocked := (pol.Mode == GeoModeAllow && !listed) || (pol.Mode == GeoModeDeny && listed)
	if blocked {
		logGeoBlock(fmt.Sprintf("Petición bloqueada en %q: país %s no permitido (modo %s, países [%s])",
			normalizeGeoHost(host), country, pol.Mode, FormatCountries(pol.Countries)))
		return fmt.Errorf("%w: país %s no permitido", ErrGeoBlocked, country)
	}
	return nil
}

func containsCountry(countries []string, country string) bool {
	for _, c := range countries {
		if c == country {
			return true
		}
	}
	return false
}

// normalizeGeoHost pasa a minúsculas y elimina el puerto (igual que handlers.normalizeHost).
func normalizeGeoHost(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(h)
}

func logGeoInfo(msg string)  { db.LogEvent(msg, "geo") }
func logGeoWarn(msg string)  { db.LogEvent(fmt.Sprintf("%s %s", db.PrefixWARN, msg), "geo") }
func logGeoBlock(msg string) { db.LogEvent(fmt.Sprintf("%s %s", db.PrefixBLOCK, msg), "geo") }
