package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Servicios map[string]string `json:"servicios"`
}

type Intento struct {
	fallos         int
	bloqueadoHasta time.Time
}

type User struct {
	ID           int
	Username     string
	PasswordHash string
	TotpSecret   string
	IsAdmin      bool
	CSRFToken    string // Token para protección CSRF
	TotpActive   bool
}

var (
	intentosDB     = make(map[string]*Intento)
	activeSessions = make(map[string]*User) // Mapa de Token -> Usuario
	mu             sync.Mutex
	config         Config
	adminDomain    string
	sessionKey     = "REGIO_session"
	db             *sql.DB
	needsSetup     bool
)

func getSubnet(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return ip.Mask(net.CIDRMask(24, 32)).String() + "/24" // Rango IPv4
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64" // Rango IPv6
}

func main() {
	adminDomain = os.Getenv("ADMIN_DOMAIN")
	if adminDomain == "" {
		log.Fatal("✕ ERROR: Configura ADMIN_DOMAIN")
	}

	initDB()
	needsSetup = checkNeedsSetup()

	configFile, err := os.ReadFile("config.json")
	if err == nil {
		json.Unmarshal(configFile, &config)
	} else {
		config.Servicios = make(map[string]string)
	}

	// Rutina de limpieza en segundo plano (Evita fugas de memoria limpiando IPs viejas cada hora)
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			mu.Lock()
			for ip, intento := range intentosDB {
				if time.Now().After(intento.bloqueadoHasta) {
					delete(intentosDB, ip)
				}
			}
			mu.Unlock()
		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Cabeceras de seguridad globales
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		ip := r.Header.Get("CF-Connecting-IP")
		if ip == "" {
			// Extraer IP limpia sin el puerto
			var err error
			if ip, _, err = net.SplitHostPort(r.RemoteAddr); err != nil {
				ip = r.RemoteAddr
			}
		}

		// 0. Servir archivos estáticos (ej: icono) desde la carpeta ./static/
		if strings.HasPrefix(r.URL.Path, "/static/") {
			http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))).ServeHTTP(w, r)
			return
		}

		// 0. Modo Instalación (Setup)
		mu.Lock()
		isSetup := needsSetup
		mu.Unlock()
		if isSetup {
			if r.URL.Path == "/setup" {
				handleSetup(w, r)
				return
			}
			http.Redirect(w, r, "/setup", http.StatusTemporaryRedirect)
			return
		}

		// 1. Verificar bloqueo por IP
		mu.Lock()
		reg, existe := intentosDB[ip]
		if existe && time.Now().Before(reg.bloqueadoHasta) {
			mu.Unlock()
			http.Error(w, "Demasiados intentos. IP bloqueada temporalmente.", http.StatusForbidden)
			return
		}
		mu.Unlock()

		// 2. Ruta de Login (Exenta de verificación de sesión)
		if r.URL.Path == "/REGIO-login" {
			handleLogin(w, r, ip)
			return
		}

		// 3. Verificar Sesión (Cookie)
		cookie, err := r.Cookie(sessionKey)
		if err != nil {
			http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
			return
		}

		mu.Lock()
		user, validSession := activeSessions[cookie.Value]
		mu.Unlock()

		if !validSession {
			http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
			return
		}

		// Ruta de Logout
		if r.URL.Path == "/logout" {
			mu.Lock()
			delete(activeSessions, cookie.Value)
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{
				Name: sessionKey, Value: "", Path: "/",
				MaxAge: -1, // Expira la cookie inmediatamente
			})
			http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
			return
		}

		// 4. Rutas internas (Admin y Perfil)
		if r.Host == adminDomain {
			if r.URL.Path == "/profile" {
				handleProfile(w, r)
				return
			}
			if r.URL.Path == "/admin" || r.URL.Path == "/" {
				if !user.IsAdmin {
					http.Redirect(w, r, "/profile", http.StatusSeeOther)
					return
				}
				if r.URL.Path == "/" {
					http.Redirect(w, r, "/admin", http.StatusSeeOther)
					return
				}
				handleAdmin(w, r)
				return
			}
		}

		// 5. Proxy Inverso
		target, ok := config.Servicios[r.Host]
		if !ok {
			http.Error(w, "Servicio no configurado para este dominio: "+r.Host, http.StatusNotFound)
			return
		}

		remote, _ := url.Parse(target)
		proxy := httputil.NewSingleHostReverseProxy(remote)
		r.URL.Host = remote.Host
		r.URL.Scheme = remote.Scheme
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		r.Host = remote.Host

		proxy.ServeHTTP(w, r)
	})

	log.Printf("⎈ REGIO Multi-User iniciado. Admin en: https://%s/admin", adminDomain)
	log.Fatal(http.ListenAndServe(":80", nil))
}
