package handlers

import (
	"encoding/base64"
	"log"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"

	"regio/internal/auth"
	"regio/internal/db"
)

// proxyOptions parametriza las únicas diferencias que quedan entre rutas de
// proxy. Historial de decisiones:
//   - Mensajes 404 unificados: "Dominio no configurado en ReGiO: <host>".
//   - X-API-Key se borra SIEMPRE en ambas rutas (cabecera propia de reGIO).
//   - Authorization se borra solo si reGIO la consumió como app token
//     (tokenUsed != ""), consistente en sesión y bypass.
//   - La cookie de sesión REGIO_session se elimina SIEMPRE antes de proxyar
//     (mejora A1): los backends no deben recibir el bearer de sesión de reGIO.
type proxyOptions struct {
	// tokenUsed: si no está vacío, la credencial Authorization fue consumida
	// por reGIO (app token) y no debe reenviarse al backend.
	tokenUsed string
}

// stripSessionCookie elimina la cookie `cookieName` de la cabecera Cookie,
// conservando el resto (cookies propias del backend). Si no queda ninguna,
// borra la cabecera entera.
func stripSessionCookie(h http.Header, cookieName string) {
	lines := h.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	var kept []string
	for _, line := range lines {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name := part
			if i := strings.Index(part, "="); i >= 0 {
				name = strings.TrimSpace(part[:i])
			}
			if name == cookieName {
				continue
			}
			kept = append(kept, part)
		}
	}
	h.Del("Cookie")
	if len(kept) > 0 {
		h.Set("Cookie", strings.Join(kept, "; "))
	}
}

// serveProxy ejecuta el reverse proxy hacia el servicio configurado tras el
// host actual. Única implementación compartida por ambas rutas (R1).
func serveProxy(w http.ResponseWriter, r *http.Request, opts proxyOptions) {
	Mu.Lock()
	target, ok := Config.Servicios[normalizeHost(r.Host)]
	Mu.Unlock()
	if !ok {
		// El statusWriter (si el caller lo pasó como writer) queda marcado
		// para que el log de cierre de MainHandler refleje el 404 real.
		if sw, esStatusWriter := w.(*statusWriter); esStatusWriter {
			sw.status = http.StatusNotFound
		}
		http.Error(w, "Dominio no configurado en ReGiO: "+r.Host, http.StatusNotFound)
		return
	}

	remote, _ := url.Parse(target)
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.Transport = proxyTransport // Transporte con timeouts + validación anti-SSRF
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Eliminar cabeceras de seguridad del backend para que reGIO tenga el control total
		resp.Header.Del("Content-Security-Policy")
		resp.Header.Del("Content-Security-Policy-Report-Only")
		resp.Header.Del("X-Content-Security-Policy")
		resp.Header.Del("X-WebKit-CSP")
		resp.Header.Del("Strict-Transport-Security")
		resp.Header.Del("X-Frame-Options")
		resp.Header.Del("X-Content-Type-Options")
		resp.Header.Del("X-XSS-Protection")

		// Fix S4: filtrar cookies INTERNAS de reGIO que un backend pudiera
		// emitir (p.ej. REGIO_session con Domain superior → colisión/fijación
		// de sesión del panel). Las cookies del backend se conservan.
		if cookies := resp.Header.Values("Set-Cookie"); len(cookies) > 0 {
			kept := make([]string, 0, len(cookies))
			for _, c := range cookies {
				name := c
				if i := strings.Index(c, "="); i >= 0 {
					name = strings.TrimSpace(c[:i])
				}
				if name == SessionKey || strings.HasPrefix(name, "REGIO_") {
					continue
				}
				kept = append(kept, c)
			}
			resp.Header.Del("Set-Cookie")
			for _, c := range kept {
				resp.Header.Add("Set-Cookie", c)
			}
		}

		if resp.Header.Get("Content-Type") == "" {
			ext := filepath.Ext(resp.Request.URL.Path)
			if ct := mime.TypeByExtension(ext); ct != "" {
				resp.Header.Set("Content-Type", ct)
			}
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			log.Printf("%s REDIRECT DETECTADO: %s (Status: %d)", db.PrefixINFO, loc, resp.StatusCode)
			if originalHost := resp.Request.Header.Get("X-Forwarded-Host"); originalHost != "" {
				if strings.Contains(loc, remote.Host) {
					newLoc := strings.Replace(loc, remote.Host, originalHost, 1)
					log.Printf("%s REEMPLAZANDO HOST EN REDIRECT: %s -> %s", db.PrefixINFO, loc, newLoc)
					loc = newLoc
				}
				if strings.HasPrefix(loc, "http://"+originalHost) {
					newLoc := strings.Replace(loc, "http://"+originalHost, "https://"+originalHost, 1)
					log.Printf("%s FORZANDO HTTPS EN REDIRECT: %s -> %s", db.PrefixINFO, loc, newLoc)
					loc = newLoc
				}
				resp.Header.Set("Location", loc)
			}
		}
		return nil
	}

	// r.URL.Host y Scheme son necesarios para que el proxy sepa a dónde ir
	r.URL.Host, r.URL.Scheme = remote.Host, remote.Scheme

	// X-Forwarded headers para el backend
	r.Header.Set("X-Forwarded-Host", r.Host)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Host = remote.Host

	if opts.tokenUsed != "" {
		r.Header.Del("Authorization")
	} else if authz := r.Header.Get("Authorization"); len(authz) > 6 && strings.EqualFold(authz[:6], "basic ") {
		// Fix S7: si la credencial Basic ES un token de app de reGIO pero no
		// se consumió (p.ej. había sesión de cookie válida), tampoco se filtra
		// al backend. Un Basic que NO es de reGIO pertenece a la app y se
		// reenvía (preserva el login HTTP Basic de los backends).
		cred := strings.TrimSpace(authz[6:])
		if dec, err := base64.StdEncoding.DecodeString(cred); err == nil {
			candidatos := []string{string(dec)}
			if i := strings.Index(string(dec), ":"); i >= 0 {
				// reGIO prueba primero la pass y luego el usuario (como en HandleLogin)
				candidatos = append(candidatos, string(dec)[i+1:], string(dec)[:i])
			}
			for _, cand := range candidatos {
				if cand == "" {
					continue
				}
				if _, _, ok := auth.VerifyAppToken(cand); ok {
					r.Header.Del("Authorization")
					break
				}
			}
		}
	}
	// X-API-Key es una cabecera de autenticación de reGIO: jamás se reenvía
	// al backend (antes solo la borraba la ruta inline; la bypass la filtraba).
	r.Header.Del("X-API-Key")
	// Mejora A1: la cookie de sesión de reGIO tampoco sale hacia los backends
	// (un backend no debe poseer un bearer de sesión reGIO). Las cookies
	// ajenas del backend se conservan.
	stripSessionCookie(r.Header, SessionKey)
	proxy.ServeHTTP(w, r)
}
