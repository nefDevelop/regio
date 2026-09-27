package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"regio/internal/db"
)

// TestCSPReportIngestContract congela el contrato completo de /api/csp-report:
// payload válido -> 204 + fila persistida con los campos parseados; host
// derivado de document-uri (sin puerto).
func TestCSPReportIngestContract(t *testing.T) {
	isolateState(t)

	// Limpiar reportes previos
	if _, err := db.DB.Exec("DELETE FROM csp_reports"); err != nil {
		t.Fatalf("limpiando csp_reports: %v", err)
	}

	payload := `{
		"csp-report": {
			"document-uri": "https://app.legacy.com:8443/pagina",
			"blocked-uri": "https://evil.test/script.js",
			"violated-directive": "script-src-elem",
			"original-policy": "default-src 'self'",
			"disposition": "report",
			"status-code": 200
		}
	}`

	req := httptest.NewRequest("POST", "/api/csp-report", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/csp-report")
	req.Host = "admin.test"
	rr := httptest.NewRecorder()
	HandleCSPReport(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", rr.Code)
	}

	var host, blocked, directive, policy string
	err := db.DB.QueryRow(
		"SELECT host, blocked_uri, violated_directive, original_policy FROM csp_reports ORDER BY id DESC LIMIT 1").
		Scan(&host, &blocked, &directive, &policy)
	if err != nil {
		t.Fatalf("reporte no persistido: %v", err)
	}
	// Host derivado de document-uri y SIN puerto (QUIRK: SplitHostPort)
	if host != "app.legacy.com" {
		t.Errorf("host = %q; want app.legacy.com (derivado de document-uri sin puerto)", host)
	}
	if blocked != "https://evil.test/script.js" {
		t.Errorf("blocked_uri = %q", blocked)
	}
	// Fix S1: las comillas se eliminan al persistir (anti inyección), por lo
	// que el policy guardado es "default-src self" y no "default-src 'self'".
	if directive != "script-src-elem" || policy != "default-src self" {
		t.Errorf("directiva=%q policy=%q", directive, policy)
	}
}

// TestSanitizeCSPFieldFixS1 son las unitarias de la sanitización de store (S1).
func TestSanitizeCSPFieldFixS1(t *testing.T) {
	t.Run("texto: sin caracteres HTML/JS ni controles", func(t *testing.T) {
		in := "https://evil.test/x')\"><img src=x onerror=alert(1)>`\\ línea\nnueva"
		got := sanitizeCSPText(in, 512)
		for _, bad := range []string{"<", ">", "\"", "'", "`", "\\", "\n"} {
			if strings.Contains(got, bad) {
				t.Errorf("sanitizeCSPText dejó %q en %q", bad, got)
			}
		}
		if !strings.HasPrefix(got, "https://evil.test/x") {
			t.Errorf("debería conservar el contenido útil: %q", got)
		}
	})

	t.Run("texto: respeta la longitud máxima", func(t *testing.T) {
		got := sanitizeCSPText(strings.Repeat("a", 2000), 512)
		if len(got) != 512 {
			t.Errorf("len = %d; want 512", len(got))
		}
	})

	t.Run("directiva: solo [a-z0-9 .-] en minúsculas", func(t *testing.T) {
		got := sanitizeCSPDirective("ScRiPt-SrC <svg onload=alert(1)>")
		if got != "script-src svg onload" && !strings.HasPrefix(got, "script-src") {
			t.Errorf("directiva sanitizada = %q", got)
		}
		if strings.ContainsAny(got, "<>=()") {
			t.Errorf("la directiva aún contiene caracteres peligrosos: %q", got)
		}
	})
}

// TestCSPReportPersistidoSinInyeccionFixS1 es el contrato end-to-end del
// store: payload de XSS almacenado -> fila en DB imposible de renderizar.
func TestCSPReportPersistidoSinInyeccionFixS1(t *testing.T) {
	isolateState(t)
	if _, err := db.DB.Exec("DELETE FROM csp_reports"); err != nil {
		t.Fatalf("limpiando: %v", err)
	}

	payload := `{"csp-report":{"document-uri":"https://app.legacy.com/pag","blocked-uri":"https://evil.test/a')\"><img src=x onerror=alert(1)>","violated-directive":"SCRIPT-SRC <svg onload=alert(1)>","original-policy":"default-src 'self'\"><script>alert(2)</script>"}}`

	req := httptest.NewRequest("POST", "/api/csp-report", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "admin.test"
	rr := httptest.NewRecorder()
	HandleCSPReport(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", rr.Code)
	}

	var blocked, directive, policy string
	err := db.DB.QueryRow(
		"SELECT blocked_uri, violated_directive, original_policy FROM csp_reports ORDER BY id DESC LIMIT 1").
		Scan(&blocked, &directive, &policy)
	if err != nil {
		t.Fatalf("sin fila persistida: %v", err)
	}
	for nombre, v := range map[string]string{"blocked_uri": blocked, "violated_directive": directive, "original_policy": policy} {
		if strings.ContainsAny(v, "<>\"'`\\") {
			t.Errorf("%s contiene caracteres de inyección: %q", nombre, v)
		}
	}
	if strings.ContainsAny(directive, "ABCDEFGHIJKLMNOPQRSTUVWXYZ<>=") {
		t.Errorf("directiva sin normalizar: %q", directive)
	}
}
