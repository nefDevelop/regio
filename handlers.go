package main

import (
	"fmt"
	"html/template"
	"net/http"
	"time"
)

var (
	loginTmpl = template.Must(template.New("login").Parse(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>REGIO Login</title>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<link rel="icon" type="image/svg+xml" href="/static/reGiO.svg">
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #0b0c10; color: #e0e0e0; margin:0; }
			.login-box { background: #16181d; padding: 40px; border-radius: 24px; box-shadow: 0 12px 40px rgba(0,0,0,0.5); width: 100%; max-width: 360px; border: 1px solid #2d313a; }
			h2 { margin-top: 0; color: #ffffff; text-align: center; font-size: 24px; font-weight: 600; margin-bottom: 25px; }
			input { width: 100%; padding: 14px 16px; margin: 8px 0 16px 0; background: #1f2228; border: 1px solid #2d313a; color: #ffffff; border-radius: 12px; box-sizing: border-box; font-size: 15px; transition: all 0.2s ease; }
			input:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2); }
			button { width: 100%; padding: 14px; background: #3b82f6; color: white; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; margin-top: 10px; transition: all 0.2s ease; }
			button:hover { background: #2563eb; transform: translateY(-1px); }
			.error { color: #ff7675; background: rgba(255, 118, 117, 0.1); border: 1px solid rgba(255, 118, 117, 0.2); padding: 12px; border-radius: 12px; font-size: 14px; text-align: center; margin-bottom: 20px; }
		</style>
	</head>
	<body>
		<div class="login-box">
			<h2><img src="/static/reGiO.svg" alt="logo" style="height: 32px; vertical-align: middle; margin-right: 10px; margin-top: -4px; filter: invert(1);">reGiO Login</h2>
			{{if .}} <div class="error">Usuario, contraseña o 2FA incorrectos</div> {{end}}
			<form method="POST">
				<input type="text" name="user" placeholder="Usuario" required autofocus>
				<input type="password" name="pass" placeholder="Contraseña (vacío si eres nuevo)">
				<input type="text" name="2fa" placeholder="Código 2FA (Opcional)" inputmode="numeric" autocomplete="one-time-code">
				<button type="submit">Iniciar Sesión</button>
			</form>
		</div>
	</body>
	</html>`))

	adminTmpl = template.Must(template.New("admin").Parse(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>REGIO Admin</title>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<link rel="icon" type="image/svg+xml" href="/static/reGiO.svg">
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 960px; margin: 40px auto; padding: 20px; background: #0b0c10; color: #e0e0e0; }
			.section { background: #16181d; padding: 32px; margin-top: 30px; border-radius: 24px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); border: 1px solid #2d313a; }
			h2 { color: #ffffff; margin-top: 0; font-size: 20px; border-bottom: 1px solid #2d313a; padding-bottom: 15px; margin-bottom: 20px; }
			h3 { color: #e0e0e0; font-size: 16px; margin-top: 25px; }
			table { width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 10px; }
			th, td { padding: 14px 16px; border-bottom: 1px solid #2d313a; text-align: left; font-size: 15px; }
			th { background: #1f2228; color: #a1a1aa; font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; }
			th:first-child { border-top-left-radius: 12px; }
			th:last-child { border-top-right-radius: 12px; }
			td:first-child { border-left: 1px solid transparent; }
			.btn-del { background: #ef4444; color: white; border: none; padding: 8px 14px; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 600; transition: all 0.2s; }
			.btn-del:hover { background: #dc2626; }
			input { padding: 12px 16px; background: #1f2228; border: 1px solid #2d313a; color: #ffffff; border-radius: 12px; margin-right: 10px; margin-bottom: 10px; font-size: 14px; transition: all 0.2s; }
			input:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2); }
			.btn-add { background: #10b981; color: white; border: none; padding: 12px 20px; border-radius: 12px; cursor: pointer; font-weight: 600; font-size: 14px; transition: all 0.2s; }
			.btn-add:hover { background: #059669; }
			.totp-secret { background: #1f2228; padding: 6px 10px; border-radius: 8px; font-family: ui-monospace, monospace; color: #a1a1aa; border: 1px solid #2d313a; font-size: 13px; }
			.badge { background: #3b82f6; color: white; padding: 4px 10px; border-radius: 12px; font-size: 11px; margin-left: 8px; vertical-align: middle; font-weight: 600; letter-spacing: 0.5px; }
			.header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
			.header h1 { color: #ffffff; font-size: 28px; margin: 0; }
			.btn-logout { background: #3f3f46; color: white; text-decoration: none; padding: 10px 18px; border-radius: 12px; font-size: 14px; font-weight: 600; transition: all 0.2s; }
			.btn-logout:hover { background: #52525b; }
			p small { color: #a1a1aa; }
			.btn-copy { background: transparent; border: none; cursor: pointer; font-size: 16px; color: #a1a1aa; padding: 0 6px; transition: color 0.2s; vertical-align: middle; }
			.btn-copy:hover { color: #ffffff; }
			.ip-match { font-family: ui-monospace, monospace; color: #60a5fa; }
		</style>
	</head>
	<body>
		<div class="header">
			<h1>⌂ reGiO Admin Panel</h1>
			<div>
				<a href="/profile" class="btn-logout" style="background:#3b82f6; margin-right: 8px;">♞ Mi Perfil</a>
				<a href="/logout" class="btn-logout">Cerrar Sesión</a>
			</div>
		</div>
		
		<div class="section">
			<h2>❖ Gestión de Puentes (Servicios)</h2>
			<table>
				<tr><th>Hostname Público</th><th>Destino Local</th><th>Acción</th></tr>
				{{range $host, $target := .Config.Servicios}}
				<tr>
					<td>{{$host}}</td>
					<td>{{$target}}</td>
					<td>
						<form method="POST"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="accion" value="delete_service"><input type="hidden" name="host" value="{{$host}}"><button class="btn-del">Eliminar</button></form>
					</td>
				</tr>
				{{end}}
			</table>
			<br>
			<h3>Añadir Nuevo Puente</h3>
			<form method="POST">
				<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
				<input type="hidden" name="accion" value="add_service">
				<input type="text" name="host" placeholder="nas.tudominio.com" required>
				<input type="text" name="target" placeholder="http://localhost:4545" required>
				<button type="submit" class="btn-add">Añadir Puente</button>
			</form>
		</div>

		<div class="section">
			<h2>⚇ Gestión de Usuarios</h2>
			<table>
				<tr><th>Usuario</th><th>Estado 2FA</th><th>Acción</th></tr>
				{{range .Users}}
				<tr>
					<td>{{.Username}}{{if .IsAdmin}} <span class="badge">Admin</span>{{end}}</td>
					<td>{{if .TotpActive}}<span class="badge" style="background:#10b981;">Activo</span>{{else}}<span class="badge" style="background:#71717a;">Inactivo</span>{{end}}</td>
					<td>
						{{if eq .ID 1}}
							<span class="badge" style="background:#3f3f46; padding: 8px 14px; font-size: 13px; font-weight: normal;">🔒 Protegido</span>
						{{else}}
							<form method="POST"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="accion" value="delete_user"><input type="hidden" name="del_user" value="{{.Username}}"><button class="btn-del">Eliminar</button></form>
						{{end}}
					</td>
				</tr>
				{{end}}
			</table>
			<br>
			<h3>Crear Nuevo Usuario</h3>
			<form method="POST">
				<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
				<input type="hidden" name="accion" value="add_user">
				<input type="text" name="new_user" placeholder="Nombre de usuario" required>
				<input type="password" name="new_pass" placeholder="Contraseña (dejar en blanco para que el usuario la cree)">
				<button type="submit" class="btn-add">Crear Usuario</button>
			</form>
			<p><small>* Si dejas la contraseña en blanco, el usuario la creará al iniciar sesión por primera vez.</small></p>
			<p><small>* Los usuarios podrán generar su código QR para el 2FA entrando a su Perfil.</small></p>
		</div>

		<div class="section">
			<h2>⊘ Gestión de Seguridad (Fail2Ban)</h2>
			<table>
				<tr><th>IP o Rango</th><th>Bloqueado Hasta</th><th>Acción</th></tr>
				{{range .BannedIPs}}
				<tr>
					<td>{{.Target}}</td>
					<td>{{.Hasta}}</td>
					<td>
						<form method="POST"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="accion" value="unban_ip"><input type="hidden" name="target_ip" value="{{.Target}}"><button class="btn-add" style="padding: 8px 14px; font-size: 13px; background:#3b82f6;">Desbloquear</button></form>
					</td>
				</tr>
				{{end}}
			</table>
			<br>
			<h3>Bloquear IP / Rango manualmente</h3>
			<form method="POST">
				<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
				<input type="hidden" name="accion" value="ban_ip">
				<input type="text" name="target_ip" placeholder="192.168.1.50 o 10.0.0.0/24" required>
				<button type="submit" class="btn-del">Bloquear</button>
			</form>
		</div>

		<div class="section">
			<h2>📋 Registro de Eventos</h2>
			<div style="max-height: 300px; overflow-y: auto; background: #1f2228; border: 1px solid #2d313a; border-radius: 12px; padding: 10px 0;">
				<table style="margin-top: 0; width: 100%;">
					{{range .Events}}
					<tr>
						<td style="width: 170px; color: #a1a1aa; font-family: ui-monospace, monospace; font-size: 13px; border-bottom: none; padding: 8px 20px; vertical-align: top;">{{.Timestamp}}</td>
						<td class="log-msg" style="border-bottom: none; padding: 8px 20px; font-size: 14px; color: #e0e0e0;">{{.Message}}</td>
					</tr>
					{{else}}
					<tr><td style="border-bottom: none; color: #a1a1aa; text-align: center; padding: 20px;">No hay eventos registrados.</td></tr>
					{{end}}
				</table>
			</div>
		</div>

		<script>
			document.querySelectorAll('.log-msg').forEach(el => {
				// Detecta direcciones IPv4 e IPv6 (incluso si tienen sufijo CIDR tipo /24 o /64)
				const ipRegex = /((?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?|(?:[a-fA-F0-9]{0,4}:){2,}[a-fA-F0-9]{1,4}(?:\/\d{1,3})?)/gi;
				let html = el.innerHTML;
				if (ipRegex.test(html)) {
					el.innerHTML = html.replace(ipRegex, '<span class="ip-match">$1</span><button class="btn-copy" onclick="copyIP(\'$1\', this)" title="Copiar IP">📋</button>');
				}
			});
			function copyIP(ip, btn) {
				navigator.clipboard.writeText(ip);
				let old = btn.innerText;
				btn.innerText = '✓';
				btn.style.color = '#10b981';
				setTimeout(() => { btn.innerText = old; btn.style.color = ''; }, 1500);
			}
		</script>
	</body>
	</html>`))

	profileTmpl = template.Must(template.New("profile").Parse(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>Mi Perfil - reGiO</title>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<link rel="icon" type="image/svg+xml" href="/static/reGiO.svg">
		<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 640px; margin: 40px auto; padding: 20px; background: #0b0c10; color: #e0e0e0; }
			.section { background: #16181d; padding: 40px; margin-top: 30px; border-radius: 24px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); text-align: center; border: 1px solid #2d313a; }
			h3 { color: #ffffff; font-size: 20px; margin-top: 0; margin-bottom: 25px; }
			input { width: 100%; max-width: 320px; padding: 14px 16px; background: #1f2228; border: 1px solid #2d313a; color: #ffffff; border-radius: 12px; margin-bottom: 16px; font-size: 16px; text-align: center; transition: all 0.2s; }
			input:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2); }
			.btn-add { background: #10b981; color: white; border: none; padding: 14px 20px; border-radius: 12px; cursor: pointer; font-weight: 600; width: 100%; max-width: 320px; font-size: 15px; transition: all 0.2s; }
			.btn-add:hover { background: #059669; transform: translateY(-1px); }
			.btn-del { background: #ef4444; color: white; border: none; padding: 14px 20px; border-radius: 12px; cursor: pointer; font-weight: 600; width: 100%; max-width: 320px; font-size: 15px; transition: all 0.2s; }
			.btn-del:hover { background: #dc2626; transform: translateY(-1px); }
			#qrcode { display: flex; justify-content: center; margin: 24px auto; background: white; padding: 20px; border-radius: 16px; width: fit-content; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
			.secret-text { background: #1f2228; padding: 8px 12px; border-radius: 8px; font-family: ui-monospace, monospace; font-size: 15px; letter-spacing: 2px; color: #e0e0e0; border: 1px solid #2d313a; }
			.header { display: flex; justify-content: space-between; align-items: center; }
			.header h2 { margin: 0; font-size: 24px; color: #ffffff; }
			.btn-nav { background: #3f3f46; color: white; text-decoration: none; padding: 10px 18px; border-radius: 12px; font-size: 14px; font-weight: 600; transition: all 0.2s; }
			.btn-nav:hover { background: #52525b; }
			.error { color: #ff7675; background: rgba(255, 118, 117, 0.1); border: 1px solid rgba(255, 118, 117, 0.2); padding: 12px; border-radius: 12px; font-size: 14px; text-align: center; margin-bottom: 20px; max-width: 320px; margin: 0 auto 20px auto; }
			p { color: #a1a1aa; line-height: 1.5; }
		</style>
	</head>
	<body>
		<div class="header">
			<h2>⚇ Mi Perfil</h2>
			<div>
				{{if .User.IsAdmin}}<a href="/admin" class="btn-nav" style="margin-right: 8px; background: #3b82f6;">Volver al Panel</a>{{end}}
				<a href="/logout" class="btn-nav">Cerrar Sesión</a>
			</div>
		</div>
		
		<div class="section">
			<h3>✎ Detalles de la Cuenta</h3>
			<form method="POST">
				<input type="hidden" name="accion" value="update_profile">
				<input type="text" name="new_username" value="{{.User.Username}}" required>
				<input type="password" name="new_password" placeholder="Nueva contraseña (opcional)">
				<button class="btn-add" style="background:#3b82f6;">Guardar Cambios</button>
			</form>
		</div>

		<div class="section">
			<h3>Autenticación en Dos Pasos (2FA)</h3>
			{{if .User.TotpActive}}
				<p style="color: #10b981; font-weight: 600; margin-bottom: 24px; font-size: 16px;">✓ El 2FA está activado y protegiendo tu cuenta.</p>
				<form method="POST">
					<input type="hidden" name="accion" value="disable_2fa">
					<button class="btn-del">Desactivar 2FA</button>
				</form>
			{{else}}
				<p>Aumenta la seguridad de tu cuenta activando el 2FA.</p>
				<p style="font-size: 14px;">1. Escanea este código con Google Authenticator o Authy:</p>
				<div id="qrcode"></div>
				<p style="font-size: 14px;">O usa la clave manual: <span class="secret-text">{{.User.TotpSecret}}</span></p>
				
				<hr style="border:0; border-top:1px solid #2d313a; margin: 30px 0;">
				
				<p style="font-size: 14px;">2. Introduce el código generado para confirmar:</p>
				<form method="POST">
					<input type="hidden" name="accion" value="enable_2fa">
					{{if .Error}}<div class="error">Código incorrecto, inténtalo de nuevo.</div>{{end}}
					<input type="text" name="code" placeholder="Código de 6 dígitos" required inputmode="numeric" autocomplete="one-time-code"><br>
					<button class="btn-add">Activar 2FA</button>
				</form>
				<script>
					new QRCode(document.getElementById("qrcode"), {
						text: "{{.OtpUrl}}", width: 150, height: 150,
						colorDark : "#000000", colorLight : "#ffffff", correctLevel : QRCode.CorrectLevel.M
					});
				</script>
			{{end}}
		</div>
	</body>
	</html>`))

	setPasswordTmpl = template.Must(template.New("setpassword").Parse(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>Crear Contraseña - reGiO</title>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<link rel="icon" type="image/svg+xml" href="/static/reGiO.svg">
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #0b0c10; color: #e0e0e0; margin:0; }
			.login-box { background: #16181d; padding: 40px; border-radius: 24px; box-shadow: 0 12px 40px rgba(0,0,0,0.5); width: 100%; max-width: 360px; border: 1px solid #2d313a; }
			h2 { margin-top: 0; color: #ffffff; text-align: center; font-size: 24px; font-weight: 600; }
			p { text-align: center; color: #a1a1aa; font-size: 15px; margin-bottom: 25px; line-height: 1.5; }
			input { width: 100%; padding: 14px 16px; margin: 8px 0 16px 0; background: #1f2228; border: 1px solid #2d313a; color: #ffffff; border-radius: 12px; box-sizing: border-box; font-size: 15px; transition: all 0.2s ease; }
			input:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2); }
			button { width: 100%; padding: 14px; background: #10b981; color: white; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; margin-top: 10px; transition: all 0.2s ease; }
			button:hover { background: #059669; transform: translateY(-1px); }
		</style>
	</head>
	<body>
		<div class="login-box">
			<h2><img src="/static/reGiO.svg" alt="logo" style="height: 32px; vertical-align: middle; margin-right: 10px; margin-top: -4px; filter: invert(1);">Hola, {{.}}</h2>
			<p>Bienvenido. Por favor, crea tu contraseña para continuar.</p>
			<form method="POST" action="/REGIO-login">
				<input type="hidden" name="step" value="set_password">
				<input type="hidden" name="user" value="{{.}}">
				<input type="password" name="new_pass" placeholder="Nueva Contraseña" required autofocus>
				<button type="submit">Guardar y Entrar</button>
			</form>
		</div>
	</body>
	</html>`))
)

func handleLogin(w http.ResponseWriter, r *http.Request, ip string) {
	if r.Method == "POST" {
		inputUser := r.FormValue("user")

		var hash, totp string
		var id int
		var isAdmin, totpActive bool
		err := db.QueryRow("SELECT id, password_hash, totp_secret, is_admin, totp_active FROM users WHERE username = ?", inputUser).Scan(&id, &hash, &totp, &isAdmin, &totpActive)

		// Si el usuario existe y aún no tiene contraseña
		if err == nil && hash == "" {
			step := r.FormValue("step")
			if step == "set_password" {
				newPass := r.FormValue("new_pass")
				if newPass != "" {
					newHash := hashPassword(newPass)
					db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", newHash, id)

					token := generateSessionToken()
					http.SetCookie(w, &http.Cookie{Name: sessionKey, Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 3600 * 24})

					mu.Lock()
					activeSessions[token] = &User{ID: id, Username: inputUser, IsAdmin: isAdmin, TotpActive: totpActive, CSRFToken: generateSessionToken()}
					delete(intentosDB, ip)
					subnet := getSubnet(ip)
					if subnet != "" {
						delete(intentosDB, subnet)
					}
					mu.Unlock()

					logEvent(fmt.Sprintf("⚿ Contraseña inicial creada y sesión iniciada: %s", inputUser))
					http.Redirect(w, r, "/", http.StatusSeeOther)
					return
				}
			}
			// Mostrar pantalla para crear la contraseña
			setPasswordTmpl.Execute(w, inputUser)
			return
		}

		inputPass := r.FormValue("pass")
		input2fa := r.FormValue("2fa")

		loginValido := false
		if err == nil && verifyPassword(inputPass, hash) {
			// Si el 2FA está activo, validamos el código. Si no, le dejamos pasar.
			if !totpActive || input2fa == getTOTPCode(totp) {
				loginValido = true
			}
		}

		if loginValido {
			token := generateSessionToken()
			http.SetCookie(w, &http.Cookie{Name: sessionKey, Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 3600 * 24})

			mu.Lock()
			activeSessions[token] = &User{ID: id, Username: inputUser, IsAdmin: isAdmin, TotpActive: totpActive, CSRFToken: generateSessionToken()}
			delete(intentosDB, ip)
			subnet := getSubnet(ip)
			if subnet != "" {
				delete(intentosDB, subnet)
			}
			mu.Unlock()

			logEvent(fmt.Sprintf("✓ Inicio de sesión exitoso: %s (%s)", inputUser, ip))
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Login Fallido: Aumentar contador
		subnet := getSubnet(ip)
		mu.Lock()
		if _, ok := intentosDB[ip]; !ok {
			intentosDB[ip] = &Intento{fallos: 1}
		} else {
			intentosDB[ip].fallos++
			if intentosDB[ip].fallos >= 5 {
				intentosDB[ip].bloqueadoHasta = time.Now().Add(15 * time.Minute)
				logEvent(fmt.Sprintf("⊘ IP BLOQUEADA (Fuerza bruta): %s", ip))
			}
		}
		// Contador por subred
		if subnet != "" {
			if _, ok := intentosDB[subnet]; !ok {
				intentosDB[subnet] = &Intento{fallos: 1}
			} else {
				intentosDB[subnet].fallos++
				if intentosDB[subnet].fallos >= 15 {
					intentosDB[subnet].bloqueadoHasta = time.Now().Add(1 * time.Hour)
					logEvent(fmt.Sprintf("⊘ RANGO BLOQUEADO (Ataque múltiple): %s", subnet))
				}
			}
		}
		mu.Unlock()
		http.Redirect(w, r, "/REGIO-login?error=1", http.StatusSeeOther)
		return
	}

	loginTmpl.Execute(w, r.URL.Query().Get("error") != "")
}

type BannedIP struct {
	Target string
	Hasta  string
}

type Event struct {
	Timestamp string
	Message   string
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(sessionKey)
	mu.Lock()
	user, ok := activeSessions[cookie.Value]
	mu.Unlock()
	if !ok {
		http.Error(w, "Sesión inválida", http.StatusUnauthorized)
		return
	}

	if r.Method == "POST" {
		// Validar token CSRF
		if r.FormValue("csrf_token") != user.CSRFToken {
			http.Error(w, "Error de validación CSRF: Petición inválida.", http.StatusForbidden)
			return
		}
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
				logEvent(fmt.Sprintf("⎈ Puente añadido: %s -> %s", host, target))
			}
		} else if accion == "delete_service" {
			host := r.FormValue("host")
			mu.Lock()
			delete(config.Servicios, host)
			saveConfig()
			mu.Unlock()
			logEvent(fmt.Sprintf("⎈ Puente eliminado: %s", host))
		} else if accion == "add_user" {
			// Acciones de Usuarios
			newUser := r.FormValue("new_user")
			newPass := r.FormValue("new_pass")
			if newUser != "" {
				hash := ""
				if newPass != "" {
					hash = hashPassword(newPass)
				}
				totp := generateTOTPSecret()
				db.Exec("INSERT INTO users (username, password_hash, totp_secret, is_admin, totp_active) VALUES (?, ?, ?, 0, 0)", newUser, hash, totp)
				logEvent(fmt.Sprintf("⚇ Usuario creado: %s", newUser))
			}
		} else if accion == "delete_user" {
			delUser := r.FormValue("del_user")

			// El usuario creador original (ID 1) está completamente protegido y no se puede borrar
			var idToDelete int
			db.QueryRow("SELECT id FROM users WHERE username = ?", delUser).Scan(&idToDelete)
			if idToDelete != 1 {
				db.Exec("DELETE FROM users WHERE username = ?", delUser)
				logEvent(fmt.Sprintf("⚇ Usuario eliminado: %s", delUser))
			}
		} else if accion == "ban_ip" {
			targetIP := r.FormValue("target_ip")
			if targetIP != "" {
				mu.Lock()
				intentosDB[targetIP] = &Intento{fallos: 99, bloqueadoHasta: time.Now().Add(365 * 24 * time.Hour)} // Ban de 1 año
				mu.Unlock()
				logEvent(fmt.Sprintf("⊘ IP/Rango bloqueado manualmente: %s", targetIP))
			}
		} else if accion == "unban_ip" {
			targetIP := r.FormValue("target_ip")
			mu.Lock()
			delete(intentosDB, targetIP)
			mu.Unlock()
			logEvent(fmt.Sprintf("✓ IP/Rango desbloqueado: %s", targetIP))
		}

		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	var users []User
	rows, _ := db.Query("SELECT id, username, totp_secret, is_admin, totp_active FROM users")
	defer rows.Close()
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.TotpSecret, &u.IsAdmin, &u.TotpActive)
		users = append(users, u)
	}

	var bannedList []BannedIP
	mu.Lock()
	for k, v := range intentosDB {
		if time.Now().Before(v.bloqueadoHasta) {
			bannedList = append(bannedList, BannedIP{Target: k, Hasta: v.bloqueadoHasta.Format("02/01/2006 15:04:05")})
		}
	}
	mu.Unlock()

	var events []Event
	rowsEvents, _ := db.Query("SELECT datetime(timestamp, 'localtime'), message FROM events ORDER BY id DESC LIMIT 50")
	defer rowsEvents.Close()
	for rowsEvents.Next() {
		var e Event
		rowsEvents.Scan(&e.Timestamp, &e.Message)
		events = append(events, e)
	}

	data := struct {
		Config    Config
		Users     []User
		CSRFToken string
		BannedIPs []BannedIP
		Events    []Event
	}{
		Config:    config,
		Users:     users,
		CSRFToken: user.CSRFToken,
		BannedIPs: bannedList,
		Events:    events,
	}

	adminTmpl.Execute(w, data)
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(sessionKey)
	mu.Lock()
	userSession, ok := activeSessions[cookie.Value]
	mu.Unlock()
	if !ok {
		http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
		return
	}

	var u User
	db.QueryRow("SELECT id, username, totp_secret, totp_active, is_admin FROM users WHERE id = ?", userSession.ID).Scan(&u.ID, &u.Username, &u.TotpSecret, &u.TotpActive, &u.IsAdmin)

	if u.TotpSecret == "" {
		u.TotpSecret = generateTOTPSecret()
		db.Exec("UPDATE users SET totp_secret = ? WHERE id = ?", u.TotpSecret, u.ID)
	}

	errorMsg := false
	if r.Method == "POST" {
		accion := r.FormValue("accion")
		if accion == "update_profile" {
			newUsername := r.FormValue("new_username")
			newPassword := r.FormValue("new_password")

			if newUsername != "" && newUsername != u.Username {
				_, err := db.Exec("UPDATE users SET username = ? WHERE id = ?", newUsername, u.ID)
				if err == nil {
					u.Username = newUsername
					mu.Lock()
					userSession.Username = newUsername
					mu.Unlock()
					logEvent(fmt.Sprintf("⚇ Nombre de usuario actualizado: %s", newUsername))
				}
			}
			if newPassword != "" {
				newHash := hashPassword(newPassword)
				db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", newHash, u.ID)
				logEvent(fmt.Sprintf("⚿ Contraseña actualizada por el usuario: %s", u.Username))
			}
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		} else if accion == "enable_2fa" {
			if r.FormValue("code") == getTOTPCode(u.TotpSecret) {
				db.Exec("UPDATE users SET totp_active = 1 WHERE id = ?", u.ID)
				logEvent(fmt.Sprintf("⚿ 2FA activado por el usuario: %s", u.Username))
				http.Redirect(w, r, "/profile", http.StatusSeeOther)
				return
			} else {
				errorMsg = true
			}
		} else if accion == "disable_2fa" {
			db.Exec("UPDATE users SET totp_active = 0 WHERE id = ?", u.ID)
			logEvent(fmt.Sprintf("⊘ 2FA desactivado por el usuario: %s", u.Username))
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		}
	}

	otpUrl := fmt.Sprintf("otpauth://totp/reGiO:%%20%s?secret=%s&issuer=reGiO", u.Username, u.TotpSecret)
	profileTmpl.Execute(w, struct {
		User   User
		OtpUrl string
		Error  bool
	}{u, otpUrl, errorMsg})
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		user := r.FormValue("user")
		pass := r.FormValue("pass")

		if user != "" && pass != "" {
			hash := hashPassword(pass)
			secret := generateTOTPSecret()
			_, err := db.Exec("INSERT INTO users (username, password_hash, totp_secret, is_admin, totp_active) VALUES (?, ?, ?, 1, 0)", user, hash, secret)
			if err == nil {
				logEvent("✓ Instalación completada. Administrador original creado.")
				mu.Lock()
				needsSetup = false
				mu.Unlock()
				http.Redirect(w, r, "/REGIO-login", http.StatusSeeOther)
				return
			}
		}
	}

	tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Instalación - reGiO</title>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<link rel="icon" type="image/svg+xml" href="/static/reGiO.svg">
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #0b0c10; color: #e0e0e0; margin:0; }
			.box { background: #16181d; padding: 40px; border-radius: 24px; box-shadow: 0 12px 40px rgba(0,0,0,0.5); width: 100%; max-width: 400px; text-align: center; border: 1px solid #2d313a; }
			h2 { margin-top: 0; color: #ffffff; font-size: 24px; font-weight: 600; margin-bottom: 10px; }
            p { color: #a1a1aa; font-size: 15px; margin-bottom: 25px; }
			input { width: 100%; padding: 14px 16px; margin: 8px 0 16px 0; background: #1f2228; border: 1px solid #2d313a; color: #ffffff; border-radius: 12px; box-sizing: border-box; font-size: 15px; transition: all 0.2s ease; }
			input:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2); }
			button { width: 100%; padding: 14px; background: #10b981; color: white; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; margin-top: 10px; transition: all 0.2s ease; }
			button:hover { background: #059669; transform: translateY(-1px); }
		</style>
	</head>
	<body>
		<div class="box">
			<h2><img src="/static/reGiO.svg" alt="logo" style="height: 32px; vertical-align: middle; margin-right: 10px; margin-top: -4px; filter: invert(1);">Bienvenido a reGiO</h2>
			<p>Crea tu cuenta de administrador.</p>
			<form method="POST">
				<input type="text" name="user" placeholder="Nombre de usuario" required autofocus>
				<input type="password" name="pass" placeholder="Contraseña segura" required>
				<button type="submit">Finalizar Instalación</button>
			</form>
		</div>
	</body>
	</html>`

	t := template.Must(template.New("setup").Parse(tmpl))
	t.Execute(w, nil)
}
