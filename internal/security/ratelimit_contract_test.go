package security

import (
	"testing"
	"time"

	"regio/internal/db"
)

// TestRateLimiterContract cubre CheckRateLimit/loadFromDB/persistIP/
// LimpiarRateLimiter (0% pkg-local en el baseline).
func TestRateLimiterContract(t *testing.T) {
	t.Run("límite exacto: 100 permitidas, la 101 rechazada", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.7"
		for i := 0; i < 100; i++ {
			if !CheckRateLimit(ip) {
				t.Fatalf("rechazada en la petición %d (want 101)", i+1)
			}
		}
		if CheckRateLimit(ip) {
			t.Error("la petición 101 debe rechazarse")
		}
	})

	t.Run("carga persistida: 100 filas recientes en DB ya agotan el límite", func(t *testing.T) {
		ResetRateLimiter() // limpia memoria Y DB
		ip := "198.51.100.8"
		base := time.Now().Add(-30 * time.Second)
		for i := 0; i < 100; i++ {
			// Timestamps distintos (nanosegundos consecutivos) y dentro de la
			// ventana: el índice único (ip,timestamp) rechaza duplicados exactos
			ts := base.Add(time.Duration(i))
			if _, err := db.DB.Exec("INSERT INTO rate_limits (ip, timestamp) VALUES (?, ?)", ip, ts); err != nil {
				t.Fatalf("seed rate_limits: %v", err)
			}
		}
		// Primera consulta de este IP -> loadFromDB debe recuperar las 100
		if CheckRateLimit(ip) {
			t.Error("loadFromDB no aplicó las 100 peticiones persistidas")
		}
	})

	t.Run("ventana de 1 minuto: filas antiguas no cuentan", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.9"
		viejo := time.Now().Add(-5 * time.Minute)
		for i := 0; i < 100; i++ {
			db.DB.Exec("INSERT INTO rate_limits (ip, timestamp) VALUES (?, ?)", ip, viejo)
		}
		if !CheckRateLimit(ip) {
			t.Error("las filas fuera de la ventana no deben contar")
		}
	})

	t.Run("ResetRateLimiter purga memoria y DB", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.10"
		for i := 0; i < 100; i++ {
			CheckRateLimit(ip)
		}
		ResetRateLimiter()
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM rate_limits WHERE ip=?", ip).Scan(&count)
		if count != 0 {
			t.Errorf("quedan %d filas tras reset", count)
		}
		if !CheckRateLimit(ip) {
			t.Error("tras reset debe volver a permitir")
		}
	})

	t.Run("LimpiarRateLimiter persiste lo sucio y no borra la ventana activa", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.11"
		CheckRateLimit(ip) // marca rlDirty
		LimpiarRateLimiter()
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM rate_limits WHERE ip=?", ip).Scan(&count)
		if count == 0 {
			t.Error("LimpiarRateLimiter debió persistir las peticiones recientes")
		}
	})
}

// TestRateLimiterSinDuplicados cubre el fix deuda #5: con el índice único,
// persistir 100 peticiones deja exactamente 100 filas (antes se duplicaban y
// tras un reinicio el límite se alcanzaba antes de tiempo).
func TestRateLimiterSinDuplicados(t *testing.T) {
	t.Run("100 peticiones persistidas == 100 filas", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.20"
		for i := 0; i < 100; i++ {
			if !CheckRateLimit(ip) {
				t.Fatalf("rechazada en la petición %d", i+1)
			}
		}
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM rate_limits WHERE ip=?", ip).Scan(&count)
		if count != 100 {
			t.Errorf("filas en DB = %d; want 100 exactas (sin duplicados)", count)
		}
	})

	t.Run("simulación de reinicio: el límite se respeta con el recuento exacto", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.21"
		for i := 0; i < 100; i++ {
			CheckRateLimit(ip)
		}
		// Vaciar SOLO la memoria (equivale a reiniciar el proceso)
		rlMu.Lock()
		delete(peticionesMem, ip)
		rlMu.Unlock()

		if CheckRateLimit(ip) {
			t.Error("con 100 peticiones persistidas, la 101 debe rechazarse tras el reinicio")
		}
	})

	t.Run("persistencia incremental: no reinserta timestamps ya guardados", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.22"
		for i := 0; i < 30; i++ {
			CheckRateLimit(ip) // persiste en 10, 20 y 30
		}
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM rate_limits WHERE ip=?", ip).Scan(&count)
		if count != 30 {
			t.Errorf("filas = %d; want 30 (cada petición, una fila)", count)
		}
	})
}
