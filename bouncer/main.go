package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
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
}

var (
	intentosDB  = make(map[string]*Intento)
	mu          sync.Mutex
	config      Config
	adminDomain string
	sessionKey  = "bouncer_session"
	db          *sql.DB
)

// --- BASE DE DATOS Y ARGON2ID ---
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./data/bouncer.db")
	if err != nil {
		log.Fatal("Error abriendo DB:", err)
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE,
		password_hash TEXT,
		totp_secret TEXT
	);`
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal("Error creando tabla users:", err)
	}
}

func createInitialAdmin(username, password, totpSecret string) {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count == 0 {
		hash := hashPassword(password)
		_, err := db.Exec("INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)", username, hash, totpSecret)
		if err == nil {
			log.Println("✅ Usuario inicial creado desde variables de entorno.")
		}
	}
}

func hashPassword(password string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=1,p=4$%s$%s", b64Salt, b64Hash)
}

func verifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return hmac.Equal(decodedHash, hash)
}

// --- TOTP LÓGICA ---
func getTOTPCode(secret string) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	epoch := time.Now().Unix() / 30
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(epoch))

	h := hmac.New(sha1.New, key)
	h.Write(buf)
	sum := h.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3] & 0xff)))

	return fmt.Sprintf("%06d", value%1000000)
}

func generateTOTPSecret() string {
	b := make([]byte, 10)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func saveConfig() error {
	data, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile("config.json", data, 0644)
}

func main() {
	adminDomain = os.Getenv("ADMIN_DOMAIN")
	if adminDomain == "" {
		log.Fatal("❌ ERROR: Configura ADMIN_DOMAIN")
	}

	initDB()
	
	// Solo para retrocompatibilidad/primer inicio
	initUser := os.Getenv("BOUNCER_USER")
	initPass := os.Getenv("BOUNCER_PASS")
	initTotp := os.Getenv("BOUNCER_TOTP_SECRET")
	if initUser != "" && initPass != "" && initTotp != "" {
		createInitialAdmin(initUser, initPass, initTotp)
	}

	configFile, err := os.ReadFile("config.json")
	if err == nil {
		json.Unmarshal(configFile, &config)
	} else {
		config.Servicios = make(map[string]string)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ip := r.Header.Get("CF-Connecting-IP")
		if ip == "" {
			ip = r.RemoteAddr
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
		if r.URL.Path == "/bouncer-login" {
			handleLogin(w, r, ip, existe)
			return
		}

		// 3. Verificar Sesión (Cookie)
		cookie, err := r.Cookie(sessionKey)
		// En un entorno real, validar la cookie (ej. token en DB)
		if err != nil || cookie.Value != "session_active" {
			http.Redirect(w, r, "/bouncer-login", http.StatusSeeOther)
			return
		}

		// 4. Panel de Administración
		if r.Host == adminDomain && r.URL.Path == "/admin" {
			handleAdmin(w, r)
			return
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

	log.Printf("🚀 Bouncer Multi-User iniciado. Admin en: https://%s/admin", adminDomain)
	log.Fatal(http.ListenAndServe(":80", nil))
}

func handleLogin(w http.ResponseWriter, r *http.Request, ip string, existe bool) {
	if r.Method == "POST" {
		inputUser := r.FormValue("user")
		inputPass := r.FormValue("pass")
		input2fa := r.FormValue("2fa")

		var hash, totp string
		err := db.QueryRow("SELECT password_hash, totp_secret FROM users WHERE username = ?", inputUser).Scan(&hash, &totp)

		if err == nil && verifyPassword(inputPass, hash) && input2fa == getTOTPCode(totp) {
			// Login Correcto: Crear Cookie Segura
			http.SetCookie(w, &http.Cookie{
				Name: sessionKey, Value: "session_active", Path: "/",
				HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
				MaxAge: 3600 * 24, // 24 horas de duración
			})
			mu.Lock()
			delete(intentosDB, ip) // Resetear fallos
			mu.Unlock()
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Login Fallido: Aumentar contador
		mu.Lock()
		if !existe {
			intentosDB[ip] = &Intento{fallos: 1}
		} else {
			intentosDB[ip].fallos++
			if intentosDB[ip].fallos >= 5 {
				intentosDB[ip].bloqueadoHasta = time.Now().Add(15 * time.Minute)
				log.Printf("⚠️ IP BLOQUEADA por fallos de login: %s", ip)
			}
		}
		mu.Unlock()
		http.Redirect(w, r, "/bouncer-login?error=1", http.StatusSeeOther)
		return
	}

	tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Bouncer Login</title>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<style>
			body { font-family: -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; margin:0; }
			.login-box { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.1); width: 100%; max-width: 350px; }
			h2 { margin-top: 0; color: #1c1e21; text-align: center; }
			input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #dddfe2; border-radius: 6px; box-sizing: border-box; font-size: 16px; }
			button { width: 100%; padding: 12px; background: #1877f2; color: white; border: none; border-radius: 6px; font-size: 18px; font-weight: bold; cursor: pointer; margin-top: 10px; }
			button:hover { background: #166fe5; }
			.error { color: #f02849; background: #ffebe8; padding: 10px; border-radius: 4px; font-size: 14px; text-align: center; margin-bottom: 15px; }
		</style>
	</head>
	<body>
		<div class="login-box">
			<h2>🛡️ Bouncer Login</h2>
			{{if .}} <div class="error">Usuario, contraseña o 2FA incorrectos</div> {{end}}
			<form method="POST">
				<input type="text" name="user" placeholder="Usuario" required autofocus>
				<input type="password" name="pass" placeholder="Contraseña" required>
				<input type="text" name="2fa" placeholder="Código 2FA (6 dígitos)" required inputmode="numeric" autocomplete="one-time-code">
				<button type="submit">Iniciar Sesión</button>
			</form>
		</div>
	</body>
	</html>`
	t := template.Must(template.New("login").Parse(tmpl))
	t.Execute(w, r.URL.Query().Get("error") != "")
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		accion := r.FormValue("accion")
		
		// Acciones de Puentes (Servicios)
		if accion == "add_service" {
			host := r.FormValue("host")
			target := r.FormValue("target")
			if host != "" && target != "" {
				mu.Lock()
				config.Servicios[host] = target
				saveConfig()
				mu.Unlock()
			}
		} else if accion == "delete_service" {
			host := r.FormValue("host")
			mu.Lock()
			delete(config.Servicios, host)
			saveConfig()
			mu.Unlock()
		} else if accion == "add_user" {
			// Acciones de Usuarios
			newUser := r.FormValue("new_user")
			newPass := r.FormValue("new_pass")
			if newUser != "" && newPass != "" {
				hash := hashPassword(newPass)
				totp := generateTOTPSecret()
				db.Exec("INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)", newUser, hash, totp)
			}
		} else if accion == "delete_user" {
			delUser := r.FormValue("del_user")
			db.Exec("DELETE FROM users WHERE username = ?", delUser)
		}
		
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	var users []User
	rows, _ := db.Query("SELECT id, username, totp_secret FROM users")
	defer rows.Close()
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.TotpSecret)
		users = append(users, u)
	}

	data := struct {
		Config Config
		Users  []User
	}{
		Config: config,
		Users:  users,
	}

	tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Bouncer Admin</title>
		<style>
			body { font-family: sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; background: #f9f9f9; }
			.section { background: white; padding: 20px; margin-top: 30px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
			table { width: 100%; border-collapse: collapse; margin-top: 10px; }
			th, td { padding: 12px; border-bottom: 1px solid #eee; text-align: left; }
			th { background: #f4f4f4; }
			.btn-del { background: #ff4d4d; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; }
			input { padding: 10px; border: 1px solid #ddd; border-radius: 4px; margin-right: 10px; margin-bottom: 10px; }
			.btn-add { background: #42b983; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold; }
			.totp-secret { background: #eee; padding: 4px 8px; border-radius: 4px; font-family: monospace; }
		</style>
	</head>
	<body>
		<h1>🛡️ Bouncer Admin Panel</h1>
		
		<div class="section">
			<h2>🌐 Gestión de Puentes (Servicios)</h2>
			<table>
				<tr><th>Hostname Público</th><th>Destino Local</th><th>Acción</th></tr>
				{{range $host, $target := .Config.Servicios}}
				<tr>
					<td>{{$host}}</td>
					<td>{{$target}}</td>
					<td>
						<form method="POST"><input type="hidden" name="accion" value="delete_service"><input type="hidden" name="host" value="{{$host}}"><button class="btn-del">Eliminar</button></form>
					</td>
				</tr>
				{{end}}
			</table>
			<br>
			<h3>Añadir Nuevo Puente</h3>
			<form method="POST">
				<input type="hidden" name="accion" value="add_service">
				<input type="text" name="host" placeholder="nas.tudominio.com" required>
				<input type="text" name="target" placeholder="http://localhost:4545" required>
				<button type="submit" class="btn-add">Añadir Puente</button>
			</form>
		</div>

		<div class="section">
			<h2>👥 Gestión de Usuarios</h2>
			<table>
				<tr><th>Usuario</th><th>Secreto TOTP (Base32)</th><th>Acción</th></tr>
				{{range .Users}}
				<tr>
					<td>{{.Username}}</td>
					<td><span class="totp-secret">{{.TotpSecret}}</span></td>
					<td>
						<form method="POST"><input type="hidden" name="accion" value="delete_user"><input type="hidden" name="del_user" value="{{.Username}}"><button class="btn-del">Eliminar</button></form>
					</td>
				</tr>
				{{end}}
			</table>
			<br>
			<h3>Crear Nuevo Usuario</h3>
			<form method="POST">
				<input type="hidden" name="accion" value="add_user">
				<input type="text" name="new_user" placeholder="Nombre de usuario" required>
				<input type="password" name="new_pass" placeholder="Contraseña" required>
				<button type="submit" class="btn-add">Crear Usuario</button>
			</form>
			<p><small>* El secreto TOTP se generará automáticamente para nuevos usuarios. Cópialo en Google Authenticator.</small></p>
		</div>
	</body>
	</html>`
	t := template.Must(template.New("admin").Parse(tmpl))
	t.Execute(w, data)
}
