package handlers

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"regio/internal/models"
)

// TestProxyBodyLimit congela el contrato del tope de body del proxy
// (MainHandler): el cap subió de 10MB a 30MB para que las subidas de
// hasta 25MB de gOols lleguen íntegras a su backend (que aplica su
// propio límite con mensaje amable) en vez de cortarse en el proxy con
// un 502 opaco.
func TestProxyBodyLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("modo -short: test de integración (proxy con backend real)")
	}

	// Backend que exige recibir exactamente los bytes enviados.
	const want = 11 * 1024 * 1024 // 11MB: pasaba el viejo cap de 10MB
	backend, _ := newBackend(t, func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		if n == int64(want) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("completo"))
			return
		}
		w.WriteHeader(http.StatusConflict) // cuerpo truncado por el proxy
	})

	t.Run("11MB llega íntegro al backend (cap 30MB)", func(t *testing.T) {
		isolateState(t)
		setupProxy(t, backend.URL)
		seedSession(t, "body-limit-1", &models.User{ID: 1, Username: "admin", IsAdmin: true, CSRFToken: "csrf-body"})

		req := httptest.NewRequest("POST", "/subida", bytes.NewReader(bytes.Repeat([]byte("a"), want)))
		req.Host = "app.test"
		req.AddCookie(&http.Cookie{Name: SessionKey, Value: "body-limit-1"})

		rr := httptest.NewRecorder()
		MainHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d; want 200 (el cap de 30MB debe dejar pasar 11MB). body=%s", rr.Code, rr.Body.String())
		}
		if rr.Body.String() != "completo" {
			t.Errorf("body = %q; want %q (11MB recibidos íntegros)", rr.Body.String(), "completo")
		}
	})

	t.Run("31MB supera el cap y no llega completo", func(t *testing.T) {
		isolateState(t)
		setupProxy(t, backend.URL)
		seedSession(t, "body-limit-2", &models.User{ID: 1, Username: "admin", IsAdmin: true, CSRFToken: "csrf-body"})

		req := httptest.NewRequest("POST", "/subida", bytes.NewReader(bytes.Repeat([]byte("b"), 31*1024*1024)))
		req.Host = "app.test"
		req.AddCookie(&http.Cookie{Name: SessionKey, Value: "body-limit-2"})

		rr := httptest.NewRecorder()
		MainHandler(rr, req)

		if rr.Code == http.StatusOK {
			t.Errorf("status = 200; el body de 31MB debe superar el cap de 30MB y cortarse")
		}
	})
}
