package handlers

import (
	"net/http"
	"net/url"
	"strings"
)

// sanitizeLogURI redace el token de /r-auth/ y la query de los logs de acceso
// para que no se cuelen secretos en los logs (extracción R3 de MainHandler,
// comportamiento idéntico al código original inline).
func sanitizeLogURI(u *url.URL) string {
	logURI := u.Path
	if strings.HasPrefix(logURI, "/r-auth/") {
		parts := strings.SplitN(logURI, "/", 4)
		if len(parts) >= 4 {
			logURI = "/r-auth/[redacted]/" + parts[3]
		} else {
			logURI = "/r-auth/[redacted]"
		}
	}
	if u.RawQuery != "" {
		logURI += "?[redacted]"
	}
	return logURI
}

// setSecurityHeaders fija las cabeceras de seguridad base de toda respuesta
// (extracción R3 de MainHandler, comportamiento idéntico al inline original).
func setSecurityHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-XSS-Protection", "1; mode=block")
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}
