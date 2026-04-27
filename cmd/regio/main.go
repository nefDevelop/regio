package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"regio/internal/db"
	"regio/internal/handlers"
	"regio/internal/models"
)

func loadConfig() {
	data, err := os.ReadFile("./data/config.json")
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("ℹ️ No se encontró config.json, iniciando con configuración vacía.")
		} else {
			log.Printf("✕ ERROR leyendo config.json: %v", err)
		}
		return
	}

	var tempConfig models.Config
	if err := json.Unmarshal(data, &tempConfig); err != nil {
		log.Printf("✕ ERROR parseando config.json (ignorando cambios): %v", err)
		return
	}

	handlers.Mu.Lock()
	handlers.Config = tempConfig
	handlers.Mu.Unlock()
}

func watchConfig() {
	var lastMod time.Time
	if stat, err := os.Stat("./data/config.json"); err == nil {
		lastMod = stat.ModTime()
	}
	for {
		time.Sleep(5 * time.Second)
		if stat, err := os.Stat("./data/config.json"); err == nil && stat.ModTime().After(lastMod) {
			log.Println("ℹ️ Cambios detectados en config.json, recargando configuración...")
			loadConfig()
			lastMod = stat.ModTime()
		}
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
	loadConfig()
	go watchConfig()

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
	log.Printf("⎈ REGIO Blindado Iniciado. Admin en: https://%s/admin. Escuchando en :80", handlers.AdminDomain)

	// Configuración del servidor con timeouts para evitar DoS
	server := &http.Server{
		Addr:         ":80",
		Handler:      http.HandlerFunc(handlers.MainHandler),
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  300 * time.Second,
	}

	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("✕ ERROR FATAL al iniciar el servidor: %v", err)
	}
}
