package security

import (
	"testing"
	"time"

	"regio/internal/db"
)

// TestRateLimiterContract cubre CheckRateLimit/loadFromDB/loadGlobalFromDB/
// persistIP/LimpiarRateLimiter (0% pkg-local en el baseline).
func TestRateLimiterContract(t *testing.T) {
	t.Run("límite exacto: 100 permitidas por servicio, la 101 rechazada", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.7"
		for i := 0; i < 100; i++ {
			if !CheckRateLimit(ip, "app.test") {
				t.Fatalf("rechazada en la petición %d (want 101)", i+1)
			}
		}
		if CheckRateLimit(ip, "app.test") {
			t.Error("la petición 101 debe rechazarse")
		}
	})

	t.Run("servicios independientes: agotar uno no bloquea al otro", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.12"
		for i := 0; i < 100; i++ {
			if !CheckRateLimit(ip, "ruidoso.test") {
				t.Fatalf("servicio ruidoso rechazó en %d", i+1)
			}
		}
		if CheckRateLimit(ip, "ruidoso.test") {
			t.Error("el servicio ruidoso debe agotarse a las 100")
		}
		// El mismo IP con otro servicio conserva su presupuesto completo
		for i := 0; i < 100; i++ {
			if !CheckRateLimit(ip, "tranquilo.test") {
				t.Fatalf("servicio tranquilo bloqueado en %d: el límite no es por servicio", i+1)
			}
		}
	})

	t.Run("techo global por IP: 300 entre todos los servicios", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.13"
		for _, svc := range []string{"a.test", "b.test", "c.test"} {
			for i := 0; i < 100; i++ {
				if !CheckRateLimit(ip, svc) {
					t.Fatalf("%s rechazó en %d antes de llegar al techo", svc, i+1)
				}
			}
		}
		// 300 consumidas: un cuarto servicio con presupuesto propio libre
		// debe rechazarse por el techo global de la IP
		if CheckRateLimit(ip, "d.test") {
			t.Error("el techo global (300 req/min por IP) no se aplicó")
		}
		// Otra IP no está afectada por el techo de la anterior
		if !CheckRateLimit("198.51.100.14", "d.test") {
			t.Error("el techo global debe ser por IP, no global del servidor")
		}
	})

	t.Run("carga persistida: 100 filas recientes en DB ya agotan el límite", func(t *testing.T) {
		ResetRateLimiter() // limpia memoria Y DB
		ip := "198.51.100.8"
		base := time.Now().Add(-30 * time.Second)
		for i := 0; i < 100; i++ {
			// Timestamps distintos (nanosegundos consecutivos) y dentro de la
			// ventana: el índice único (ip,host,timestamp) rechaza duplicados exactos
			ts := base.Add(time.Duration(i))
			if _, err := db.DB.Exec("INSERT INTO rate_limits (ip, host, timestamp) VALUES (?, ?, ?)", ip, "app.test", ts); err != nil {
				t.Fatalf("seed rate_limits: %v", err)
			}
		}
		// Primera consulta de este IP+servicio -> loadFromDB debe recuperar las 100
		if CheckRateLimit(ip, "app.test") {
			t.Error("loadFromDB no aplicó las 100 peticiones persistidas")
		}
	})

	t.Run("techo global persistido: carga de TODOS los servicios tras reinicio", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.15"
		base := time.Now().Add(-30 * time.Second)
		// 300 filas repartidas en 3 servicios distintos, todas recientes
		for svc, desde := range map[string]int{"a.test": 0, "b.test": 100, "c.test": 200} {
			for i := 0; i < 100; i++ {
				ts := base.Add(time.Duration(desde+i))
				if _, err := db.DB.Exec("INSERT INTO rate_limits (ip, host, timestamp) VALUES (?, ?, ?)", ip, svc, ts); err != nil {
					t.Fatalf("seed rate_limits %s: %v", svc, err)
				}
			}
		}
		// Servicio nuevo (sin filas propias): loadGlobalFromDB debe agotar el techo
		if CheckRateLimit(ip, "nuevo.test") {
			t.Error("el techo global persistido no se aplicó tras el reinicio")
		}
	})

	t.Run("ventana de 1 minuto: filas antiguas no cuentan", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.9"
		viejo := time.Now().Add(-5 * time.Minute)
		for i := 0; i < 100; i++ {
			db.DB.Exec("INSERT INTO rate_limits (ip, host, timestamp) VALUES (?, ?, ?)", ip, "app.test", viejo)
		}
		if !CheckRateLimit(ip, "app.test") {
			t.Error("las filas fuera de la ventana no deben contar")
		}
	})

	t.Run("ResetRateLimiter purga memoria y DB", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.10"
		for i := 0; i < 100; i++ {
			CheckRateLimit(ip, "app.test")
		}
		ResetRateLimiter()
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM rate_limits WHERE ip=?", ip).Scan(&count)
		if count != 0 {
			t.Errorf("quedan %d filas tras reset", count)
		}
		if !CheckRateLimit(ip, "app.test") {
			t.Error("tras reset debe volver a permitir")
		}
	})

	t.Run("LimpiarRateLimiter persiste lo sucio y no borra la ventana activa", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.11"
		CheckRateLimit(ip, "app.test") // marca rlDirty
		LimpiarRateLimiter()
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM rate_limits WHERE ip=? AND host=?", ip, "app.test").Scan(&count)
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
			if !CheckRateLimit(ip, "app.test") {
				t.Fatalf("rechazada en la petición %d", i+1)
			}
		}
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM rate_limits WHERE ip=? AND host=?", ip, "app.test").Scan(&count)
		if count != 100 {
			t.Errorf("filas en DB = %d; want 100 exactas (sin duplicados)", count)
		}
	})

	t.Run("simulación de reinicio: el límite se respeta con el recuento exacto", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.21"
		for i := 0; i < 100; i++ {
			CheckRateLimit(ip, "app.test")
		}
		// Vaciar SOLO la memoria (equivale a reiniciar el proceso)
		rlMu.Lock()
		delete(peticionesMem, ip)
		delete(globalMem, ip)
		rlMu.Unlock()

		if CheckRateLimit(ip, "app.test") {
			t.Error("con 100 peticiones persistidas, la 101 debe rechazarse tras el reinicio")
		}
	})

	t.Run("persistencia incremental: no reinserta timestamps ya guardados", func(t *testing.T) {
		ResetRateLimiter()
		ip := "198.51.100.22"
		for i := 0; i < 30; i++ {
			CheckRateLimit(ip, "app.test") // persiste en 10, 20 y 30
		}
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM rate_limits WHERE ip=? AND host=?", ip, "app.test").Scan(&count)
		if count != 30 {
			t.Errorf("filas = %d; want 30 (cada petición, una fila)", count)
		}
	})
}
