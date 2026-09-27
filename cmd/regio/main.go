package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"regio/internal/auth"
	"regio/internal/db"
	"regio/internal/handlers"
	"regio/internal/security"
)

var reValidHost = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(:\d+)?$`)

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

	security.ReplaceHostGeoPolicies(config.GeoModes, config.GeoCountries)
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

// shutdownSignals registra las señales de apagado ordenado (mejora B1):
// SIGINT (Ctrl-C) y SIGTERM (docker stop).
func shutdownSignals() chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	return ch
}

// drainServers drena los servidores tras una señal: deja de aceptar conexiones
// nuevas, espera a que terminen las peticiones en vuelo (máx 10 s) y recoge
// los returns de las goroutines de Serve.
func drainServers(sig os.Signal, servers []*http.Server, errCh chan error, esperados int) {
	log.Printf("%s Señal %v recibida: drenando conexiones en vuelo (máx 10s)...", db.PrefixINFO, sig)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("%s Error drenando servidor: %v", db.PrefixWARN, err)
		}
	}
	for i := 0; i < esperados; i++ {
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("%s Error durante el apagado: %v", db.PrefixWARN, err)
		}
	}
	log.Printf("%s Apagado ordenado completado.", db.PrefixOK)
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

	// 4.1 GeoIP: base de datos de países y política geográfica (env + DB)
	security.InitGeoIP()
	security.InitGeoPolicy()

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
			security.ReloadGeoIPIfChanged()
			db.PurgeCSPReports()
		}
	}() // Router Principal
	port := os.Getenv("PORT")
	if port == "" {
		port = "80"
	}
	portTLS := os.Getenv("PORT_TLS")
	if portTLS == "" {
		portTLS = "443"
	}
	tlsCert := os.Getenv("TLS_CERT")
	tlsKey := os.Getenv("TLS_KEY")
	forceHTTPS := os.Getenv("FORCE_HTTPS") == "true"

	mainHandler := http.HandlerFunc(handlers.MainHandler)

	if tlsCert != "" && tlsKey != "" {
		// Modo TLS: HTTPS en :443 + redirección HTTP en :80
		log.Printf("%s reGIO Iniciado con TLS en :%s. Admin en: https://%s/admin", db.PrefixREGIO, portTLS, handlers.AdminDomain) // #nosec G706 — valores de entorno (ADMIN_DOMAIN/PORT)

		// Servidor HTTPS
		tlsServer := &http.Server{
			Addr:              ":" + portTLS,
			Handler:           mainHandler,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			MaxHeaderBytes:    64 << 10, // Fix S6: límite de cabeceras (default 1MB)
		}

		// Servidor HTTP: redirige a HTTPS (se drena también en el apagado B1)
		redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !reValidHost.MatchString(r.Host) || !handlers.IsKnownHost(r.Host) {
				http.Error(w, "Host inválido", http.StatusBadRequest)
				return
			}
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently) // #nosec G710 — limitado a hosts conocidos (IsKnownHost); e2e TestE2EHTTPSRedirect
		})
		redirectServer := &http.Server{
			Addr:              ":" + port,
			Handler:           redirectHandler,
			ReadTimeout:       2 * time.Second,
			WriteTimeout:      2 * time.Second,
			ReadHeaderTimeout: 1 * time.Second,
			MaxHeaderBytes:    64 << 10, // Fix S6: límite de cabeceras (default 1MB)
		}
		go func() {
			log.Printf("%s Servidor HTTP en :%s redirigiendo a HTTPS", db.PrefixINFO, port) // #nosec G706 — valor de entorno (PORT)
			if err := redirectServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("%s Servidor HTTP de redirección falló: %v", db.PrefixWARN, err)
			}
		}()

		httpsLn, err := net.Listen("tcp", ":"+portTLS)
		if err != nil {
			log.Fatalf("%s ERROR FATAL al escuchar en :%s: %v", db.PrefixERR, portTLS, err) // #nosec G706 — valor de entorno (PORT_TLS)
		}
		tlsErrCh := make(chan error, 1)
		go func() { tlsErrCh <- tlsServer.ServeTLS(httpsLn, tlsCert, tlsKey) }()

		select {
		case err := <-tlsErrCh:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("%s ERROR FATAL al iniciar servidor TLS: %v", db.PrefixERR, err)
			}
		case sig := <-shutdownSignals():
			drainServers(sig, []*http.Server{tlsServer, redirectServer}, tlsErrCh, 1)
		}
	} else {
		// Modo HTTP estándar (detrás de proxy/tunnel)
		if forceHTTPS {
			// Envolver handler para forzar redirección si llega HTTP directo
			// Solo confiar en X-Forwarded-Proto si viene de un proxy de confianza (previene spoofing)
			originalHandler := mainHandler
			mainHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
				isHTTPS := r.TLS != nil
				if !isHTTPS && handlers.IsTrustedProxy(remoteIP) {
					isHTTPS = r.Header.Get("X-Forwarded-Proto") == "https"
				}
				if !isHTTPS {
					if !reValidHost.MatchString(r.Host) || !handlers.IsKnownHost(r.Host) {
						http.Error(w, "Host inválido", http.StatusBadRequest)
						return
					}
					target := "https://" + r.Host + r.URL.RequestURI()
					http.Redirect(w, r, target, http.StatusMovedPermanently) // #nosec G710 — limitado a hosts conocidos (IsKnownHost); e2e TestE2EHTTPSRedirect
					return
				}
				originalHandler.ServeHTTP(w, r)
			})
		}

		log.Printf("%s reGIO Iniciado. Admin en: https://%s/admin. Escuchando en :%s", db.PrefixREGIO, handlers.AdminDomain, port) // #nosec G706 — valores de entorno (ADMIN_DOMAIN/PORT)

		server := &http.Server{
			Addr:              ":" + port,
			Handler:           mainHandler,
			ReadTimeout:       60 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
			MaxHeaderBytes:    64 << 10, // Fix S6: límite de cabeceras (default 1MB)
		}

		ln, err := net.Listen("tcp", ":"+port)
		if err != nil {
			log.Fatalf("%s ERROR FATAL al escuchar en :%s: %v", db.PrefixERR, port, err) // #nosec G706 — valor de entorno (PORT)
		}
		errCh := make(chan error, 1)
		go func() { errCh <- server.Serve(ln) }()

		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("%s ERROR FATAL al iniciar el servidor: %v", db.PrefixERR, err)
			}
		case sig := <-shutdownSignals():
			drainServers(sig, []*http.Server{server}, errCh, 1)
		}
	}
}
