package main

import (
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

func main() {
	log.Println("🚀 Iniciando ReGiO...")
	
	handlers.AdminDomain = os.Getenv("ADMIN_DOMAIN")
	if handlers.AdminDomain == "" {
		log.Println("✕ ERROR: Configura la variable de entorno ADMIN_DOMAIN")
		log.Fatal("✕ ERROR: Configura la variable de entorno ADMIN_DOMAIN")
	}
	log.Printf("ℹ️ Admin Domain: %s", handlers.AdminDomain)

	// 1. Inicializar DB
	log.Println("ℹ️ Inicializando Base de Datos...")
	db.InitDB()
	log.Println("✅ Base de Datos inicializada.")
	
	// 2. Comprobar si necesita instalación inicial
	handlers.NeedsSetup = db.CheckNeedsSetup()
	log.Printf("ℹ️ Necesita instalación (Setup): %v", handlers.NeedsSetup)
	
	// 3. Inicializar plantillas y recursos internos
	log.Println("ℹ️ Inicializando plantillas y recursos...")
	handlers.Init() 
	log.Println("✅ Recursos inicializados.")

	// 4. Cargar configuración de servicios
	log.Println("ℹ️ Cargando configuración de servicios...")
	configFile, err := os.ReadFile("./data/config.json")
	if err == nil {
		json.Unmarshal(configFile, &handlers.Config)
		log.Printf("✅ Configuración cargada: %d servicios encontrados.", len(handlers.Config.Servicios))
	} else {
		log.Printf("⚠️ No se pudo cargar config.json: %v. Usando configuración vacía.", err)
		handlers.Config.Servicios = make(map[string]string)
	}

	// Rutina de limpieza en segundo plano (IPs bloqueadas y Rate Limiter)
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			handlers.Mu.Lock()
			for ip, intento := range handlers.IntentosDB {
				if time.Now().After(intento.BloqueadoHasta) {
					delete(handlers.IntentosDB, ip)
				}
			}
			handlers.LimpiarRateLimiter()
			handlers.Mu.Unlock()
		}
	}()

	// Router Principal
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("📥 [%s] %s %s (Host: %s)", r.Method, r.URL.Path, r.RemoteAddr, r.Host)

		// Cabeceras de seguridad globales
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Obtener IP real del cliente
		ip := r.Header.Get("CF-Connecting-IP")
		if ip == "" {
			var err error
			if ip, _, err = net.SplitHostPort(r.RemoteAddr); err != nil {
				ip = r.RemoteAddr
			}
		}

		// 0. RATE LIMITING GLOBAL (Límite: 100 peticiones / minuto)
		if !handlers.CheckRateLimit(ip) {
			http.Error(w, "Demasiadas peticiones. Por favor, espera un minuto.", http.StatusTooManyRequests)
			return
		}

		// 0. Servir archivos estáticos desde el sistema de archivos embebido
		if strings.HasPrefix(r.URL.Path, "/static/") {
			handlers.ServeStatic(w, r)
			return
		}

		// 1. Verificar bloqueo por IP (Fail2Ban)
		handlers.Mu.Lock()
		isSetup := handlers.NeedsSetup
		blocked, _ := handlers.IsIPBlocked(ip)
		handlers.Mu.Unlock()

		if blocked {
			log.Printf("🚫 IP Bloqueada: %s", ip)
			http.Error(w, "IP bloqueada temporalmente por seguridad.", http.StatusForbidden)
			return
		}

		// 2. Modo Instalación (Setup)
		if isSetup {
			log.Println("🛠 Modo Setup activo")
			if r.URL.Path == "/setup" {
				handlers.HandleSetup(w, r)
				return
			}
			log.Println("↪️ Redirigiendo a /setup")
			http.Redirect(w, r, "/setup", http.StatusTemporaryRedirect)
			return
		}

		// 3. Ruta de Login
		if r.URL.Path == "/REGIO-login" {
			log.Println("🔑 Accediendo a HandleLogin")
			handlers.HandleLogin(w, r, ip)
			return
		}

		// 4. Verificar Sesión (Cookie) o App Token
		cookie, err := r.Cookie(handlers.SessionKey)
		var user *models.User
		var validSession bool

		if err == nil {
			handlers.Mu.Lock()
			user, validSession = handlers.ActiveSessions[cookie.Value]
			handlers.Mu.Unlock()
		}

		// Si no hay sesión de navegador, intentamos API/App Tokens
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
				_ = tokenUsed
				// Si no es un navegador, pedimos Basic Auth (con App Token)
				if !strings.Contains(r.Header.Get("Accept"), "text/html") {
					log.Println("🛑 No autorizado (API/Basic)")
					w.Header().Set("WWW-Authenticate", `Basic realm="reGiO protegido"`)
					http.Error(w, "No autorizado", http.StatusUnauthorized)
					return
				}
				// Si es un navegador, enviamos a login
				log.Println("↪️ Redirigiendo a /REGIO-login (Sesión no válida)")
				http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
				return
			}
			log.Printf("👤 Sesión válida vía Token para: %s (Token: %s)", user.Username, tokenUsed)
		} else {
			log.Printf("👤 Sesión válida vía Cookie para: %s", user.Username)
		}

		// Ruta de Logout
		if r.URL.Path == "/logout" {
			handlers.Mu.Lock()
			if err == nil {
				delete(handlers.ActiveSessions, cookie.Value)
			}
			handlers.Mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: handlers.SessionKey, Value: "", Path: "/", MaxAge: -1})
			http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
			return
		}

		// 5. Rutas internas (Admin y Perfil)
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

		// 6. Proxy Inverso a servicios configurados
		target, ok := handlers.Config.Servicios[r.Host]
		if !ok {
			http.Error(w, "Dominio no configurado en ReGiO: "+r.Host, http.StatusNotFound)
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

	log.Printf("⎈ REGIO Blindado Iniciado. Admin en: https://%s/admin. Escuchando en :80", handlers.AdminDomain)
	
	// Configuración del servidor con timeouts para evitar DoS
	server := &http.Server{
		Addr:         ":80",
		Handler:      nil,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	
	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("✕ ERROR FATAL al iniciar el servidor: %v", err)
	}
}
