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

// TestCSPReportReportingAPIContract congela el contrato del formato Reporting
// API (application/reports+json): array de entradas con "type" y "body".
// Es lo que envían Chrome/Firefox modernos vía report-to/Reporting-Endpoints;
// antes el handler devolvía 415 y esos informes reales se perdían.
func TestCSPReportReportingAPIContract(t *testing.T) {
	isolateState(t)
	if _, err := db.DB.Exec("DELETE FROM csp_reports"); err != nil {
		t.Fatalf("limpiando csp_reports: %v", err)
	}

	payload := `[{
		"type": "csp-violation",
		"url": "https://app.modern.test/tools/image-hub",
		"user_agent": "Mozilla/5.0",
		"body": {
			"document-url": "https://app.modern.test/tools/image-hub",
			"blocked-uri": "blob:https://app.modern.test/uuid-1234",
			"violated-directive": "img-src",
			"effective-directive": "img-src",
			"original-policy": "default-src 'self'; img-src 'self' data:",
			"disposition": "enforce",
			"status-code": 200
		}
	}]`

	req := httptest.NewRequest("POST", "/api/csp-report", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/reports+json")
	req.Host = "admin.test"
	rr := httptest.NewRecorder()
	HandleCSPReport(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204 (formato Reporting API aceptado)", rr.Code)
	}

	var host, blocked, directive string
	err := db.DB.QueryRow(
		"SELECT host, blocked_uri, violated_directive FROM csp_reports ORDER BY id DESC LIMIT 1").
		Scan(&host, &blocked, &directive)
	if err != nil {
		t.Fatalf("reporte no persistido: %v", err)
	}
	// Host derivado de document-url (Reporting API) sin puerto.
	if host != "app.modern.test" {
		t.Errorf("host = %q; want app.modern.test (derivado de document-url)", host)
	}
	if blocked != "blob:https://app.modern.test/uuid-1234" {
		t.Errorf("blocked_uri = %q", blocked)
	}
	if directive != "img-src" {
		t.Errorf("violated_directive = %q; want img-src", directive)
	}
}

// TestCSPReportReportingAPIBatch verifica que un array con varias entradas
// persiste cada violación CSP y descarta los tipos que no lo son.
func TestCSPReportReportingAPIBatch(t *testing.T) {
	isolateState(t)
	if _, err := db.DB.Exec("DELETE FROM csp_reports"); err != nil {
		t.Fatalf("limpiando csp_reports: %v", err)
	}

	payload := `[
		{"type":"csp-violation","url":"https://batch.test/a","body":{"document-url":"https://batch.test/a","blocked-uri":"https://evil.test/1.js","violated-directive":"script-src-elem"}},
		{"type":"network-error","url":"https://batch.test/net","body":{"blocked-uri":"https://cdn.test/x"}},
		{"type":"csp-violation","url":"https://batch.test/b","body":{"document-url":"https://batch.test/b","blocked-uri":"blob:https://batch.test/2","violated-directive":"img-src"}}
	]`

	req := httptest.NewRequest("POST", "/api/csp-report", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/reports+json")
	req.Host = "admin.test"
	rr := httptest.NewRecorder()
	HandleCSPReport(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", rr.Code)
	}

	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM csp_reports").Scan(&count); err != nil {
		t.Fatalf("contando reportes: %v", err)
	}
	if count != 2 {
		t.Errorf("reportes persistidos = %d; want 2 (las violaciones CSP del batch, sin el network-error)", count)
	}
}

// TestCSPReportContentTypeConParámetro verifica que los Content-Type con
// parámetros (charset=…) se aceptan por tipo base y que los tipos desconocidos
// siguen respondiendo 415 (contrato de seguridad).
func TestCSPReportContentTypeConParametro(t *testing.T) {
	isolateState(t)
	if _, err := db.DB.Exec("DELETE FROM csp_reports"); err != nil {
		t.Fatalf("limpiando csp_reports: %v", err)
	}

	payload := `{"csp-report":{"blocked-uri":"https://evil.test/x.js","violated-directive":"script-src"}}`

	t.Run("application/csp-report; charset=UTF-8 es aceptado", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/csp-report", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/csp-report; charset=UTF-8")
		req.Host = "admin.test"
		rr := httptest.NewRecorder()
		HandleCSPReport(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Errorf("status = %d; want 204 (tipo base aceptado, parámetro ignorado)", rr.Code)
		}
	})

	t.Run("application/reports+json malformado es 400", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/csp-report", strings.NewReader("[{no-es-json"))
		req.Header.Set("Content-Type", "application/reports+json")
		req.Host = "admin.test"
		rr := httptest.NewRecorder()
		HandleCSPReport(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d; want 400", rr.Code)
		}
	})

	t.Run("tipo desconocido sigue en 415", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/csp-report", strings.NewReader(payload))
		req.Header.Set("Content-Type", "text/plain")
		req.Host = "admin.test"
		rr := httptest.NewRecorder()
		HandleCSPReport(rr, req)
		if rr.Code != http.StatusUnsupportedMediaType {
			t.Errorf("status = %d; want 415", rr.Code)
		}
	})
}
