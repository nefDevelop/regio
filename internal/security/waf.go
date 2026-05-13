package security

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var (
	rePathTraversal = regexp.MustCompile(`(?i)(\.\.\/|\.\.\\)`)
	reSQLi         = regexp.MustCompile(`(?i)(union\s+.*select|select\s+.*\s+from|drop\s+table|insert\s+into|update\s+.*set|delete\s+from|--|#|\/\*)`)
	reXSS          = regexp.MustCompile(`(?i)(<script|javascript:|onerror\s*=|onload\s*=|onmouseover\s*=|onclick\s*=|onfocus\s*=|onscroll\s*=|onblur\s*=|onkeydown\s*=|onkeypress\s*=|onkeyup\s*=|onmousedown\s*=|onmouseup\s*=|onmousemove\s*=|onmouseout\s*=|onmouseenter\s*=|onmouseleave\s*=|oncontextmenu\s*=|onwheel\s*=|oncopy\s*=|oncut\s*=|onpaste\s*=|ondrag\s*=|ondrop\s*=|onabort\s*=|oncanplay\s*=|oncanplaythrough\s*=|ondurationchange\s*=|onemptied\s*=|onended\s*=|onerror\s*=|onloadeddata\s*=|onloadedmetadata\s*=|onloadstart\s*=|onpause\s*=|onplay\s*=|onplaying\s*=|onprogress\s*=|onratechange\s*=|onseeked\s*=|onseeking\s*=|onstalled\s*=|onsuspend\s*=|ontimeupdate\s*=|onvolumechange\s*=|onwaiting\s*=|onsearch\s*=|onselect\s*=|onsubmit\s*=|onreset\s*=|oninvalid\s*=|oninput\s*=|onshow\s*=|ontoggle\s*=|onpagehide\s*=|onpageshow\s*=|onpopstate\s*=|onhashchange\s*=|onbeforeprint\s*=|onafterprint\s*=|onbeforeunload\s*=|onunload\s*=|onmessage\s*=|onoffline\s*=|ononline\s*=|onstorage\s*=|onredo\s*=|onundo\s*=|onchange\s*=|onstorage\s*=|onanimationstart\s*=|onanimationend\s*=|onanimationiteration\s*=|ontransitionend\s*=|onmousewheel\s*=|onpointerdown\s*=|onpointerup\s*=|onpointermove\s*=|onpointerover\s*=|onpointerout\s*=|onpointerenter\s*=|onpointerleave\s*=|onpointercancel\s*=|onpointerlockchange\s*=|onpointerlockerror\s*=|onselectstart\s*=|onselectionchange\s*=|onauxclick\s*=|onlostpointercapture\s*=|ongotpointercapture\s*=|onbeforematch\s*=|oncontentvisibilityautostatechange\s*=|onformdata\s*=|onsecuritypolicyviolation\s*=|oncuechange\s*=|onpointerrawupdate\s*=|oncancel\s*=|onclose\s*=|oncontextrestored\s*=|oncontextlost\s*=|onscrollend\s*=|<iframe|<object|<embed|<svg)`)
)

// CheckWAF realiza una inspección básica de seguridad en la petición HTTP
func CheckWAF(r *http.Request) error {
	// 1. Filtrado de URI y query parameters (evitar path traversal y SQLi/XSS básico)
	if isMalicious(r.URL.Path) {
		return fmt.Errorf("petición bloqueada por WAF (ruta sospechosa)")
	}
	
	if r.URL.RawQuery != "" {
		decodedQuery, err := url.QueryUnescape(r.URL.RawQuery)
		if err == nil {
			if isMalicious(decodedQuery) {
				return fmt.Errorf("petición bloqueada por WAF (parámetros sospechosos)")
			}
		}
	}

	// 2. Filtrado básico de User-Agent (bloquear escáneres comunes)
	ua := strings.ToLower(r.UserAgent())
	if strings.Contains(ua, "nmap") || strings.Contains(ua, "sqlmap") || strings.Contains(ua, "nikto") || strings.Contains(ua, "curl") || strings.Contains(ua, "wget") && !AllowLoopback {
		return fmt.Errorf("user-agent bloqueado por WAF")
	}

	return nil
}

// isMalicious utiliza expresiones regulares para detectar patrones comunes de ataque.
func isMalicious(input string) bool {
	// Directory traversal
	if rePathTraversal.MatchString(input) {
		return true
	}

	// XSS
	if reXSS.MatchString(input) {
		return true
	}

	// SQLi
	if reSQLi.MatchString(input) {
		return true
	}

	return false
}
