package main

import (
	"embed"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"regio/internal/auth"
	"regio/internal/db"
	"regio/internal/handlers"
	"regio/internal/models"
)

//go:embed templates/*.html
var templateFiles embed.FS

func main() {
	handlers.AdminDomain = os.Getenv("ADMIN_DOMAIN")
	if handlers.AdminDomain == "" {
		log.Fatal("✕ ERROR: Configura ADMIN_DOMAIN")
	}

	db.InitDB()
	handlers.NeedsSetup = db.CheckNeedsSetup()
	
	// Carga centralizada de plantillas
	tmpl := template.Must(template.ParseFS(templateFiles, "templates/*.html"))
	handlers.InitTemplates(tmpl)

	configFile, err := os.ReadFile("./data/config.json")
	if err == nil {
		json.Unmarshal(configFile, &handlers.Config)
	} else {
		handlers.Config.Servicios = make(map[string]string)
	}

	// Rutina de limpieza
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			handlers.Mu.Lock()
			for ip, intento := range handlers.IntentosDB {
				if time.Now().After(intento.BloqueadoHasta) {
					delete(handlers.IntentosDB, ip)
				}
			}
			handlers.Mu.Unlock()
		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		ip := r.Header.Get("CF-Connecting-IP")
		if ip == "" {
			var err error
			if ip, _, err = net.SplitHostPort(r.RemoteAddr); err != nil {
				ip = r.RemoteAddr
			}
		}

		if strings.HasPrefix(r.URL.Path, "/static/") {
			http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))).ServeHTTP(w, r)
			return
		}

		handlers.Mu.Lock()
		isSetup := handlers.NeedsSetup
		reg, existe := handlers.IntentosDB[ip]
		if existe && time.Now().Before(reg.BloqueadoHasta) {
			handlers.Mu.Unlock()
			http.Error(w, "IP bloqueada temporalmente.", http.StatusForbidden)
			return
		}
		handlers.Mu.Unlock()

		if isSetup {
			if r.URL.Path == "/setup" {
				handlers.HandleSetup(w, r)
				return
			}
			http.Redirect(w, r, "/setup", http.StatusTemporaryRedirect)
			return
		}

		if r.URL.Path == "/REGIO-login" {
			handlers.HandleLogin(w, r, ip)
			return
		}

		cookie, err := r.Cookie(handlers.SessionKey)
		var user *models.User
		var validSession bool

		if err == nil {
			handlers.Mu.Lock()
			user, validSession = handlers.ActiveSessions[cookie.Value]
			handlers.Mu.Unlock()
		}

		if !validSession {
			var tokenUsed string
			if apiKey := r.URL.Query().Get("api_key"); apiKey != "" {
				user, tokenUsed, validSession = auth.VerifyAppToken(apiKey)
			}
			if !validSession {
				if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
					user, tokenUsed, validSession = auth.VerifyAppToken(apiKey)
				}
			}
			if !validSession {
				_, reqPass, ok := r.BasicAuth()
				if ok {
					user, tokenUsed, validSession = auth.VerifyAppToken(reqPass)
				}
			}

			if !validSession {
				if !strings.Contains(r.Header.Get("Accept"), "text/html") {
					w.Header().Set("WWW-Authenticate", `Basic realm="reGiO protegido"`)
					http.Error(w, "No autorizado", http.StatusUnauthorized)
					return
				}
				http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
				return
			}
			_ = tokenUsed
		}

		if r.URL.Path == "/logout" {
			handlers.Mu.Lock()
			delete(handlers.ActiveSessions, cookie.Value)
			handlers.Mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: handlers.SessionKey, Value: "", Path: "/", MaxAge: -1})
			http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
			return
		}

		if r.Host == handlers.AdminDomain {
			if r.URL.Path == "/profile" {
				handlers.HandleProfile(w, r)
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
				handlers.HandleAdmin(w, r)
				return
			}
		}

		target, ok := handlers.Config.Servicios[r.Host]
		if !ok {
			http.Error(w, "Servicio no configurado", http.StatusNotFound)
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

	log.Printf("⎈ REGIO iniciado. Admin en: https://%s/admin", handlers.AdminDomain)
	
	server := &http.Server{
		Addr:         ":80",
		Handler:      nil, // Usa el DefaultServeMux donde registramos todo
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	
	log.Fatal(server.ListenAndServe())
}
