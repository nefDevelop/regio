package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"regio/internal/db"
	"regio/internal/handlers"
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
		err = json.Unmarshal(configFile, &handlers.Config)
		if err != nil {
			log.Printf("✕ ERROR: No se pudo procesar el JSON de config.json: %v", err)
		}
		if handlers.Config.Servicios == nil {
			handlers.Config.Servicios = make(map[string]string)
		}
		if handlers.Config.Publicos == nil {
			handlers.Config.Publicos = make(map[string]bool)
		}
		if handlers.Config.BypassHeaders == nil {
			handlers.Config.BypassHeaders = make(map[string]string)
		}
		log.Printf("✅ Configuración cargada: %d servicios encontrados.", len(handlers.Config.Servicios))
	} else {
		log.Printf("⚠️ No se pudo cargar config.json: %v. Usando configuración vacía.", err)
		handlers.Config.Servicios = make(map[string]string)
		handlers.Config.Publicos = make(map[string]bool)
		handlers.Config.BypassHeaders = make(map[string]string)
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
			handlers.Mu.Unlock()
			handlers.CleanupSessions()
			handlers.LimpiarRateLimiter()
		}
	}()

	// Router Principal
	http.HandleFunc("/", handlers.MainHandler)

	log.Printf("⎈ REGIO Blindado Iniciado. Admin en: https://%s/admin. Escuchando en :80", handlers.AdminDomain)
	
	// Configuración del servidor con timeouts para evitar DoS
	server := &http.Server{
		Addr:         ":80",
		Handler:      nil,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  300 * time.Second,
	}
	
	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("✕ ERROR FATAL al iniciar el servidor: %v", err)
	}
}
