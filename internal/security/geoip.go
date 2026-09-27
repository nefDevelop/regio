package security

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"

	"regio/internal/db"
)

// DefaultGeoIPPath es la ruta por defecto de la base de datos de países (.mmdb).
const DefaultGeoIPPath = "./data/GeoLite2-Country.mmdb"

var (
	geoIPLock    sync.RWMutex
	geoReader    *geoip2.Reader
	geoIPPath    string
	geoIPModTime time.Time
)

// InitGeoIP carga la base de datos GeoIP de países (MaxMind DB / DB-IP).
// Si el fichero no existe, el geobloqueo aplicará el modo de fallo configurado.
func InitGeoIP() {
	path := os.Getenv("GEOIP_DB_PATH")
	if path == "" {
		path = DefaultGeoIPPath
	}

	geoIPLock.Lock()
	geoIPPath = path
	geoIPLock.Unlock()

	if err := openGeoIP(path); err != nil {
		db.LogEvent(fmt.Sprintf("%s GeoIP: no se pudo cargar %s: %v (se aplicará el modo de fallo configurado)", db.PrefixWARN, path, err), "geo")
		return
	}
	geoIPLock.RLock()
	mtime := geoIPModTime
	geoIPLock.RUnlock()
	db.LogEvent(fmt.Sprintf("%s GeoIP: base de datos cargada: %s (mod: %s)", db.PrefixOK, path, mtime.Format("2006-01-02")), "geo")
}

// openGeoIP abre (o reabre) la BD y la intercambia de forma segura.
func openGeoIP(path string) error {
	reader, err := geoip2.Open(path)
	if err != nil {
		return err
	}

	mtime := time.Time{}
	if info, err := os.Stat(path); err == nil { // #nosec G703 — GEOIP_DB_PATH es configuración del operador (env)
		mtime = info.ModTime() // #nosec G703 — idem
	}

	geoIPLock.Lock()
	old := geoReader
	geoReader = reader
	geoIPModTime = mtime
	geoIPLock.Unlock()

	// El lector antiguo ya no se usa: los lookups en vuelo retienen RLock,
	// por lo que en este punto no hay readers concurrentes sobre `old`.
	if old != nil {
		old.Close()
	}
	return nil
}

// LookupCountry devuelve el código ISO de país (alpha-2) de una IP, o error si
// la BD no está cargada o la IP no está contemplada.
func LookupCountry(ip net.IP) (string, error) {
	geoIPLock.RLock()
	defer geoIPLock.RUnlock()
	if geoReader == nil {
		return "", fmt.Errorf("base de datos GeoIP no cargada")
	}
	country, err := geoReader.Country(ip)
	if err != nil {
		return "", err
	}
	return country.Country.IsoCode, nil
}

// ReloadGeoIPIfChanged recarga la BD si el fichero cambió (actualizaciones mensuales).
// Se invoca desde la rutina de limpieza periódica.
func ReloadGeoIPIfChanged() {
	geoIPLock.RLock()
	path := geoIPPath
	last := geoIPModTime
	geoIPLock.RUnlock()

	if path == "" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		// Si el fichero desaparece temporalmente, mantenemos el lector actual.
		return
	}
	if !info.ModTime().After(last) {
		return
	}
	if err := openGeoIP(path); err != nil {
		db.LogEvent(fmt.Sprintf("%s GeoIP: error recargando %s: %v", db.PrefixWARN, path, err), "geo")
		return
	}
	db.LogEvent(fmt.Sprintf("%s GeoIP: base de datos recargada: %s", db.PrefixOK, path), "geo")
}

// GeoIPView es la vista del estado del lector GeoIP para el panel admin.
type GeoIPView struct {
	Path    string
	Loaded  bool
	ModTime string
}

// GetGeoIPView devuelve el estado actual del lector GeoIP.
func GetGeoIPView() GeoIPView {
	geoIPLock.RLock()
	defer geoIPLock.RUnlock()
	view := GeoIPView{Path: geoIPPath, Loaded: geoReader != nil}
	if !geoIPModTime.IsZero() {
		view.ModTime = geoIPModTime.Format("2006-01-02 15:04")
	}
	return view
}
