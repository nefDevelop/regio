package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"regio/internal/auth"
	"regio/internal/db"
	"regio/internal/handlers"
)

func loadConfig() {
	config, err := db.LoadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("ℹ️ No se encontró config.json, iniciando con configuración vacía.")
		} else {
			log.Printf("✕ ERROR cargando config.json: %v", err)
		}
		return
	}

	handlers.Mu.Lock()
	handlers.Config = config
	handlers.Mu.Unlock()
}

func handleCLI() {
	if len(os.Args) < 2 {
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "list":
		config, _ := db.LoadConfig()
		fmt.Println("\n📋 SERVICIOS CONFIGURADOS:")
		fmt.Printf("%-30s %-30s %-10s %-20s\n", "HOST", "TARGET", "PUBLIC", "BYPASS HEADER")
		fmt.Println(strings.Repeat("-", 95))
		
		var hosts []string
		for h := range config.Servicios {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)

		for _, h := range hosts {
			isPublic := "No"
			if config.Publicos[h] {
				isPublic = "Sí"
			}
			bypass := config.BypassHeaders[h]
			fmt.Printf("%-30s %-30s %-10s %-20s\n", h, config.Servicios[h], isPublic, bypass)
		}
		fmt.Println()
		os.Exit(0)

	case "add":
		addCmd := flag.NewFlagSet("add", flag.ExitOnError)
		host := addCmd.String("host", "", "Dominio (ej: app.com)")
		target := addCmd.String("target", "", "Destino interno (ej: http://10.0.0.5:8080)")
		public := addCmd.Bool("public", false, "Hacer servicio público")
		bypass := addCmd.String("bypass", "", "Header de bypass (ej: X-My-Key:Value)")
		addCmd.Parse(os.Args[2:])

		if *host == "" || *target == "" {
			fmt.Println("✕ Error: --host y --target son obligatorios")
			addCmd.Usage()
			os.Exit(1)
		}

		err := db.AddService(*host, *target, *public, *bypass)
		if err != nil {
			log.Fatalf("✕ Error guardando servicio: %v", err)
		}
		fmt.Printf("✅ Servicio añadido/actualizado: %s -> %s (Público: %v)\n", *host, *target, *public)
		os.Exit(0)

	case "del":
		delCmd := flag.NewFlagSet("del", flag.ExitOnError)
		host := delCmd.String("host", "", "Dominio a eliminar")
		delCmd.Parse(os.Args[2:])

		if *host == "" {
			fmt.Println("✕ Error: --host es obligatorio")
			delCmd.Usage()
			os.Exit(1)
		}

		err := db.DeleteService(*host)
		if err != nil {
			log.Fatalf("✕ Error eliminando servicio: %v", err)
		}
		fmt.Printf("✅ Servicio eliminado: %s\n", *host)
		os.Exit(0)
	}
}

func main() {
	log.Println("🚀 Iniciando ReGiO...")

	handlers.AdminDomain = os.Getenv("ADMIN_DOMAIN")
	if handlers.AdminDomain == "" {
		log.Println("✕ ERROR: Configura la variable de entorno ADMIN_DOMAIN")
		log.Fatal("✕ ERROR: Configura la variable de entorno ADMIN_DOMAIN")
	}
	log.Printf("ℹ️ Admin Domain: %s", handlers.AdminDomain)

	// 1. Verificar clave maestra de cifrado
	log.Println("ℹ️ Verificando clave maestra de cifrado...")
	auth.InitEncryption()
	log.Println("✅ Clave maestra verificada.")

	// 2. Inicializar DB
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
	loadConfig()

	// 5. Manejar comandos CLI (si existen)
	handleCLI()

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
			handlers.Mu.Unlock()
			handlers.CleanupSessions()
			handlers.LimpiarRateLimiter()
			handlers.LimpiarIntentosUsuario()
		}
	}()

	// Router Principal
	tlsCert := os.Getenv("TLS_CERT")
	tlsKey := os.Getenv("TLS_KEY")
	forceHTTPS := os.Getenv("FORCE_HTTPS") == "true"

	mainHandler := http.HandlerFunc(handlers.MainHandler)

	if tlsCert != "" && tlsKey != "" {
		// Modo TLS: HTTPS en :443 + redirección HTTP en :80
		log.Printf("⎈ REGIO Blindado Iniciado con TLS. Admin en: https://%s/admin", handlers.AdminDomain)

		// Servidor HTTPS
		tlsServer := &http.Server{
			Addr:         ":443",
			Handler:      mainHandler,
			ReadTimeout:  120 * time.Second,
			WriteTimeout: 120 * time.Second,
			IdleTimeout:  300 * time.Second,
		}

		// Servidor HTTP: redirige a HTTPS
		go func() {
			httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			})
			httpServer := &http.Server{
				Addr:         ":80",
				Handler:      httpHandler,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 5 * time.Second,
			}
			log.Println("ℹ️ Servidor HTTP en :80 redirigiendo a HTTPS")
			if err := httpServer.ListenAndServe(); err != nil {
				log.Printf("⚠ Servidor HTTP de redirección falló: %v", err)
			}
		}()

		if err := tlsServer.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			log.Fatalf("✕ ERROR FATAL al iniciar servidor TLS: %v", err)
		}
	} else {
		// Modo HTTP estándar (detrás de proxy/tunnel)
		if forceHTTPS {
			// Envolver handler para forzar redirección si llega HTTP directo
			originalHandler := mainHandler
			mainHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Forwarded-Proto") != "https" && r.TLS == nil {
					target := "https://" + r.Host + r.URL.RequestURI()
					http.Redirect(w, r, target, http.StatusMovedPermanently)
					return
				}
				originalHandler.ServeHTTP(w, r)
			})
		}

		log.Printf("⎈ REGIO Blindado Iniciado. Admin en: https://%s/admin. Escuchando en :80", handlers.AdminDomain)

		server := &http.Server{
			Addr:         ":80",
			Handler:      mainHandler,
			ReadTimeout:  120 * time.Second,
			WriteTimeout: 120 * time.Second,
			IdleTimeout:  300 * time.Second,
		}

		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("✕ ERROR FATAL al iniciar el servidor: %v", err)
		}
	}
}
