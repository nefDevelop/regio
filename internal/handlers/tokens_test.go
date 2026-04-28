package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"regio/internal/db"
)

func TestMainHandlerTokens(t *testing.T) {
	// 1. Configuración de prueba
	db.InitDB()
	AllowLoopback = true
	defer func() { AllowLoopback = false }()
	
	// Backend mock para recibir las peticiones del proxy
	backendCalled := false
	receivedPath := ""
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	Config.Servicios = map[string]string{
		"test.local": backend.URL,
	}
	AdminDomain = "admin.local"
	NeedsSetup = false

	// Crear un token de prueba en la DB
	rawToken := "test-token-123"
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := base64.StdEncoding.EncodeToString(hash[:])
	
	// Asegurar que existe un usuario
	db.DB.Exec("DELETE FROM users")
	db.DB.Exec("DELETE FROM app_tokens")
	db.DB.Exec("INSERT INTO users (id, username, is_admin) VALUES (1, 'testuser', 1)")
	db.DB.Exec("INSERT INTO app_tokens (user_id, name, token_hash) VALUES (1, 'test-token', ?)", tokenHash)

	tests := []struct {
		name           string
		method         string
		url            string
		host           string
		header         http.Header
		expectedStatus int
		expectedPath   string // Path que debería llegar al backend
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backendCalled = false
			receivedPath = ""
			
			req := httptest.NewRequest(tt.method, tt.url, nil)
			req.Host = tt.host
			if tt.header != nil {
				req.Header = tt.header
			}

			rr := httptest.NewRecorder()
			MainHandler(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("%s: handler returned wrong status code: got %v want %v", tt.name, rr.Code, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusOK {
				if !backendCalled {
					t.Errorf("%s: backend was not called", tt.name)
				}
				if tt.expectedPath != "" && receivedPath != tt.expectedPath {
					t.Errorf("%s: backend received wrong path: got %v want %v", tt.name, receivedPath, tt.expectedPath)
				}
			}
		})
	}
}

func TestSecurityAttacks(t *testing.T) {
	db.InitDB()
	AllowLoopback = true
	defer func() { AllowLoopback = false }()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	Config.Servicios = map[string]string{"test.local": backend.URL}
	AdminDomain = "admin.local"
	NeedsSetup = false

	t.Run("SQL Injection en Path Token", func(t *testing.T) {
		// Intentar un token que sea una inyección SQL
		badToken := url.PathEscape("' OR '1'='1")
		req := httptest.NewRequest("GET", "/r-auth/"+badToken+"/path", nil)
		req.Host = "test.local"
		rr := httptest.NewRecorder()
		MainHandler(rr, req)
		
		if rr.Code == http.StatusOK {
			t.Errorf("SQL Injection might have worked! Expected unauthorized, got %v", rr.Code)
		}
	})

	t.Run("Rate Limiting", func(t *testing.T) {
		// Reset rate limiter for this test
		Mu.Lock()
		peticionesDB = make(map[string][]time.Time)
		Mu.Unlock()

		ip := "1.2.3.4"
		for i := 0; i < 100; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = ip + ":1234"
			req.Host = "test.local"
			rr := httptest.NewRecorder()
			MainHandler(rr, req)
			if rr.Code == http.StatusTooManyRequests {
				t.Errorf("Rate limit hit too early at request %d", i)
			}
		}

		// La petición 101 debería ser bloqueada
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = ip + ":1234"
		req.Host = "test.local"
		rr := httptest.NewRecorder()
		MainHandler(rr, req)
		if rr.Code != http.StatusTooManyRequests {
			t.Errorf("Rate limit NOT hit at request 101: got %v", rr.Code)
		}
	})

	t.Run("IP Blocking", func(t *testing.T) {
		ip := "9.9.9.9"
		RegistrarFallo(ip)
		RegistrarFallo(ip)
		RegistrarFallo(ip)
		RegistrarFallo(ip)
		RegistrarFallo(ip) // 5 fallos bloquean

		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = ip + ":1234"
		req.Host = "test.local"
		rr := httptest.NewRecorder()
		MainHandler(rr, req)
		
		if rr.Code != http.StatusForbidden {
			t.Errorf("Blocked IP should get 403 Forbidden, got %v", rr.Code)
		}
	})

	t.Run("SSRF Prevention - Adding Private IP", func(t *testing.T) {
		// Restaurar AllowLoopback a false para esta subprueba específica
		AllowLoopback = false
		defer func() { AllowLoopback = true }()

		err := isValidTarget("http://192.168.1.1")
		if err == nil {
			t.Error("Should have blocked private IP")
		}
		
		err = isValidTarget("http://localhost:8080")
		if err == nil {
			t.Error("Should have blocked localhost")
		}
	})
	
	t.Run("Path Traversal in Path Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/r-auth/../../../etc/passwd", nil)
		req.Host = "test.local"
		rr := httptest.NewRecorder()
		MainHandler(rr, req)
		
		if rr.Code == http.StatusOK {
			t.Errorf("Path traversal in token path should not work")
		}
	})
}
