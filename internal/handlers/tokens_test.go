package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"regio/internal/db"
)

func TestMain(m *testing.M) {
	// Inicializar DB de prueba en una ubicación temporal
	db.InitDB()
	m.Run()
}

func TestMainHandlerTokens(t *testing.T) {
	// 1. Configuración de prueba
	db.InitDB()
	Config.Servicios = map[string]string{
		"test.local": "http://backend.local",
	}
	AdminDomain = "admin.local"
	NeedsSetup = false

	// Crear un token de prueba en la DB
	rawToken := "test-token-123"
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := base64.StdEncoding.EncodeToString(hash[:])
	
	// Asegurar que existe un usuario
	db.DB.Exec("INSERT OR IGNORE INTO users (id, username, is_admin) VALUES (1, 'testuser', 1)")
	db.DB.Exec("INSERT INTO app_tokens (user_id, name, token_hash) VALUES (1, 'test-token', ?)", tokenHash)

	tests := []struct {
		name           string
		method         string
		url            string
		host           string
		header         http.Header
		expectedStatus int
		expectedPath   string // Path que debería llegar al proxy (si status es 200/proxy)
	}{
		{
			name:           "Acceso Denegado (Sin Token)",
			method:         "GET",
			url:            "/some-path",
			host:           "test.local",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Token en Path (/r-auth/TOKEN/path)",
			method:         "GET",
			url:            "/r-auth/" + rawToken + "/actual-path",
			host:           "test.local",
			expectedStatus: http.StatusOK,
			expectedPath:   "/actual-path",
		},
		{
			name:           "Token en Query (?api_key=TOKEN)",
			method:         "GET",
			url:            "/path?api_key=" + rawToken,
			host:           "test.local",
			expectedStatus: http.StatusOK,
			expectedPath:   "/path",
		},
		{
			name:           "Token en Basic Auth (Usuario:TOKEN)",
			method:         "GET",
			url:            "/path",
			host:           "test.local",
			header:         http.Header{"Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("user:"+rawToken))}},
			expectedStatus: http.StatusOK,
			expectedPath:   "/path",
		},
		{
			name:           "Token en Basic Auth (TOKEN solo)",
			method:         "GET",
			url:            "/path",
			host:           "test.local",
			header:         http.Header{"Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte(rawToken+":"))}},
			expectedStatus: http.StatusOK,
			expectedPath:   "/path",
		},
		{
			name:           "Servicio Público",
			method:         "GET",
			url:            "/public-path",
			host:           "public.local",
			expectedStatus: http.StatusOK,
		},
	}

	// Añadir servicio público a la config
	Config.Publicos = map[string]bool{"public.local": true}
	Config.Servicios["public.local"] = "http://backend.public"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.url, nil)
			req.Host = tt.host
			if tt.header != nil {
				req.Header = tt.header
			}

			rr := httptest.NewRecorder()
			
			// Mock del proxy para no intentar conectar a backends reales
			// En un test real de handler que hace proxy, esto es complejo, 
			// pero aquí verificamos hasta donde llega el handler antes de fallar por el proxy nil o similar.
			// Como MainHandler usa httputil.NewSingleHostReverseProxy, intentará hacer la petición.
			// Para el test, vamos a interceptar si llega a la fase de proxy.
			
			MainHandler(rr, req)

			if rr.Code != tt.expectedStatus && !(tt.expectedStatus == http.StatusOK && rr.Code == http.StatusBadGateway) {
				// StatusBadGateway es aceptable porque el backend mock no existe
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, tt.expectedStatus)
			}

			if tt.expectedPath != "" && req.URL.Path != tt.expectedPath {
				t.Errorf("handler did not clean path: got %v want %v", req.URL.Path, tt.expectedPath)
			}
		})
	}
}
