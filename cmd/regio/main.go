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
	"regio/internal/security"
)

func loadConfig() {
	config, err := db.LoadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("%s No se encontró config.json, iniciando con configuración vacía.", db.PrefixINFO)
		} else {
			log.Printf("%s ERROR cargando config.json: %v", db.PrefixERR, err)
		}
		return
	}

	handlers.Mu.Lock()
	handlers.Config = config
	handlers.UpdateAllowedNetworksFromConfig()
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
		fmt.Printf("\n%s SERVICIOS CONFIGURADOS:\n", db.PrefixINFO)
		fmt.Printf("%-20s %-25s %-8s %-15s %-20s\n", "HOST", "TARGET", "PUBLIC", "BYPASS", "CSP")
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
			csp := config.CSPs[h]
			if len(csp) > 20 {
				csp = csp[:17] + "..."
			}
			fmt.Printf("%-20s %-25s %-8s %-15s %-20s\n", h, config.Servicios[h], isPublic, bypass, csp)
		}
		fmt.Println()
		os.Exit(0)

	case "add":
		addCmd := flag.NewFlagSet("add", flag.ExitOnError)
		host := addCmd.String("host", "", "Dominio (ej: app.com)")
		target := addCmd.String("target", "", "Destino interno (ej: http://10.0.0.5:8080)")
		public := addCmd.Bool("public", false, "Hacer servicio público")
		bypass := addCmd.String("bypass", "", "Header de bypass (ej: X-My-Key:Value)")
		csp := addCmd.String("csp", "", "Content Security Policy")
		addCmd.Parse(os.Args[2:])

		if *host == "" || *target == "" {
			fmt.Printf("%s Error: --host y --target son obligatorios\n", db.PrefixERR)
			addCmd.Usage()
			os.Exit(1)
		}

		err := db.AddService(*host, *target, *public, *bypass, *csp)
		if err != nil {
			log.Fatalf("%s Error guardando servicio: %v", db.PrefixERR, err)
		}
		fmt.Printf("%s Servicio añadido/actualizado: %s -> %s (Público: %v)\n", db.PrefixOK, *host, *target, *public)
		os.Exit(0)
	case "del":
		delCmd := flag.NewFlagSet("del", flag.ExitOnError)
		host := delCmd.String("host", "", "Dominio a eliminar")
		delCmd.Parse(os.Args[2:])

		if *host == "" {
			fmt.Printf("%s Error: --host es obligatorio\n", db.PrefixERR)
			delCmd.Usage()
			os.Exit(1)
		}

		err := db.DeleteService(*host)
		if err != nil {
			log.Fatalf("%s Error eliminando servicio: %v", db.PrefixERR, err)
		}
		fmt.Printf("%s Servicio eliminado: %s\n", db.PrefixOK, *host)
		os.Exit(0)

	case "rotate-key":
		rotateCmd := flag.NewFlagSet("rotate-key", flag.ExitOnError)
		oldKey := rotateCmd.String("old", "", "MASTER_KEY actual")
		newKey := rotateCmd.String("new", "", "Nueva MASTER_KEY deseada")
		rotateCmd.Parse(os.Args[2:])

		if *oldKey == "" || *newKey == "" {
			fmt.Printf("%s Error: --old y --new son obligatorios\n", db.PrefixERR)
			rotateCmd.Usage()
			os.Exit(1)
		}

		fmt.Printf("%s Rotando MASTER_KEY y re-cifrando secretos...\n", db.PrefixINFO)
		count, err := auth.RotateMasterKey(*oldKey, *newKey)
		if err != nil {
			log.Fatalf("%s ERROR FATAL durante la rotación: %v", db.PrefixERR, err)
		}
		fmt.Printf("%s Rotación completada con éxito. %d secretos re-cifrados.\n", db.PrefixOK, count)
		fmt.Printf("%s IMPORTANTE: Actualiza ahora tu archivo .env con la nueva MASTER_KEY y reinicia el contenedor.\n", db.PrefixWARN)
		os.Exit(0)
	}
}

func main() {
	log.Printf("%s Iniciando reGIO...", db.PrefixREGIO)

	handlers.AdminDomain = os.Getenv("ADMIN_DOMAIN")
	if handlers.AdminDomain == "" {
		log.Printf("%s ERROR: Configura la variable de entorno ADMIN_DOMAIN", db.PrefixERR)
		log.Fatal("ERROR: Configura la variable de entorno ADMIN_DOMAIN")
	}
	log.Printf("%s Admin Domain: %s", db.PrefixINFO, handlers.AdminDomain)

	// 1. Verificar clave maestra de cifrado

	log.Printf("%s Verificando clave maestra de cifrado...", db.PrefixINFO)
	auth.InitEncryption()
	log.Printf("%s Clave maestra verificada.", db.PrefixOK)

	// 2. Inicializar DB
	log.Printf("%s Inicializando Base de Datos...", db.PrefixINFO)
	db.InitDB()
	log.Printf("%s Base de Datos inicializada.", db.PrefixOK)

	// 2. Comprobar si necesita instalación inicial
	handlers.NeedsSetup = db.CheckNeedsSetup()
	log.Printf("%s Necesita instalación (Setup): %v", db.PrefixINFO, handlers.NeedsSetup)

	// 3. Inicializar plantillas y recursos internos
	log.Printf("%s Inicializando plantillas y recursos...", db.PrefixINFO)
	handlers.Init()
	log.Printf("%s Recursos inicializados.", db.PrefixOK)

	// 4. Cargar configuración de servicios
	log.Printf("%s Cargando configuración de servicios...", db.PrefixINFO)
	loadConfig()

	// 5. Manejar comandos CLI (si existen)
	handleCLI()

	// Rutina de limpieza en segundo plano (IPs bloqueadas, Rate Limiter y Sesiones)
	go func() {
	        for {
	                // Limpieza cada 10 minutos para mayor seguridad y liberación de recursos
	                time.Sleep(10 * time.Minute)
	                security.LimpiarBloqueosExpirados()
	                security.LimpiarRateLimiter()
	                security.LimpiarIntentosUsuario()
	                handlers.CleanupSessions()
	        }
	}()	// Router Principal
	tlsCert := os.Getenv("TLS_CERT")
	tlsKey := os.Getenv("TLS_KEY")
	forceHTTPS := os.Getenv("FORCE_HTTPS") == "true"

	mainHandler := http.HandlerFunc(handlers.MainHandler)

	if tlsCert != "" && tlsKey != "" {
		// Modo TLS: HTTPS en :443 + redirección HTTP en :80
		log.Printf("%s reGIO Iniciado con TLS. Admin en: https://%s/admin", db.PrefixREGIO, handlers.AdminDomain)

		// Servidor HTTPS
		tlsServer := &http.Server{
			Addr:              ":443",
			Handler:           mainHandler,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
		}

		// Servidor HTTP: redirige a HTTPS
		go func() {
			httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			})
			httpServer := &http.Server{
				Addr:              ":80",
				Handler:           httpHandler,
				ReadTimeout:       2 * time.Second,
				WriteTimeout:      2 * time.Second,
				ReadHeaderTimeout: 1 * time.Second,
			}
			log.Printf("%s Servidor HTTP en :80 redirigiendo a HTTPS", db.PrefixINFO)
			if err := httpServer.ListenAndServe(); err != nil {
				log.Printf("%s Servidor HTTP de redirección falló: %v", db.PrefixWARN, err)
			}
		}()

		if err := tlsServer.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			log.Fatalf("%s ERROR FATAL al iniciar servidor TLS: %v", db.PrefixERR, err)
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

		log.Printf("%s reGIO Iniciado. Admin en: https://%s/admin. Escuchando en :80", db.PrefixREGIO, handlers.AdminDomain)

		server := &http.Server{
			Addr:              ":80",
			Handler:           mainHandler,
			ReadTimeout:       60 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
		}

		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("%s ERROR FATAL al iniciar el servidor: %v", db.PrefixERR, err)
		}
	}
}

