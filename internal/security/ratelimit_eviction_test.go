package security

import (
	"fmt"
	"testing"
	"time"
)

// TestRateLimiterAcotaMemoriaSinDegradar es la regresión del DoS que había en el
// guard de "memory exhaustion".
//
// El guard anterior llamava a LimpiarRateLimiter() por cada IP nueva al superar
// 10.000 entradas, y como LimpiarRateLimiter solo borra IPs con 10 minutos de
// inactividad, un atacante que rotase IPs de origen mantenía todas las entradas
// como activas: la limpieza no borraba nada y cada petición pagaba un volcado
// completo de las 10.000 entradas a SQLite. Medido: 165 ms por petición frente a
// 2–18 µs antes del umbral, sin recuperación posible.
//
// Lo que se fija aquí es que el guard acote la MEMORIA sin rechazar tráfico:
// ese era el fallo real, porque convertir un límite de memoria en un rechazo
// permite tumbar el proxy solo con rotar IPs de origen.
func TestRateLimiterAcotaMemoriaSinDegradar(t *testing.T) {
	if testing.Short() {
		t.Skip("genera >10.000 IPs; omitido en modo -short")
	}
	ResetRateLimiter()
	defer ResetRateLimiter()

	// Dos veces el techo: si el guard funciona, hay que expulsar de verdad.
	const total = maxTrackedIPs * 2
	const svc = "evict.test"

	t0 := time.Now()
	for i := 0; i < total; i++ {
		ip := fmt.Sprintf("203.0.%d.%d", i/254, i%254+1)
		if !CheckRateLimit(ip, svc) {
			// Cada IP es nueva y solo ha hecho una petición: el guard de memoria
			// no puede rechazar por cuota. Si falla aquí, el DoS ha vuelto.
			t.Fatalf("CheckRateLimit rechazó la petición %d de una IP nueva; el guard "+
				"de memoria no debe convertirse en un rechazo de tráfico", i+1)
		}
	}
	elapsed := time.Since(t0)

	rlMu.Lock()
	size := 0
	for _, hosts := range peticionesMem {
		size += len(hosts)
	}
	rlMu.Unlock()

	if size > maxTrackedIPs {
		t.Errorf("el mapa quedó en %d entradas; el techo es %d", size, maxTrackedIPs)
	}

	// Techo de latencia holgado (el de referencia antes del arreglo era 165 ms,
	// ~5.000× más): solo queremos que un futuro cambio no reintroduzca el cliff,
	// no medir el rendimiento con precisión de laboratorio.
	if porPeticion := elapsed / total; porPeticion > time.Millisecond {
		t.Errorf("coste medio de %.1f ms/petición al cruzar el techo de IPs; "+
			"el guard está pagando un barrido O(n) por petición", float64(porPeticion.Microseconds())/1000)
	}
	t.Logf("%d IPs nuevas en %s (%.1f µs/petición), mapa final: %d entradas",
		total, elapsed.Round(time.Millisecond),
		float64(elapsed.Microseconds())/float64(total), size)
}

// TestRateLimiterExpulsaLoMaisViejo comprueba la propiedad que de verdad importa
// para la seguridad: la expulsión es por último uso, así que un cliente legítimo
// que SIGUE activo conserva su cuota aunque un atacante rote IPs sin parar.
//
// El escenario es el real: un cliente navegando mientras el mapa se llena de IPs
// desechables. Si la expulsión fuese por antigüedad de creación, ese cliente
// perdería su cuota y el atacante se llevaría las de los demás.
func TestRateLimiterExpulsaLoMaisViejo(t *testing.T) {
	if testing.Short() {
		t.Skip("genera >10.000 IPs; omitido en modo -short")
	}
	ResetRateLimiter()
	defer ResetRateLimiter()

	// Cliente legítimo: agota su cuota y sigue pidiendo durante todo el llenado.
	const legitimo = "198.51.100.250"
	const svcLegit = "legit.test"
	const svc = "evict.test"
	for i := 0; i < maxPeticiones; i++ {
		if !CheckRateLimit(legitimo, svcLegit) {
			t.Fatalf("el cliente legítimo fue rechazado en la petición %d", i+1)
		}
	}

	// Llenado por encima del techo con IPs desechables, con el cliente legítimo
	// intercalado para que siga siendo "el más reciente".
	for i := 0; i < maxTrackedIPs+500; i++ {
		CheckRateLimit(fmt.Sprintf("203.0.%d.%d", i/254, i%254+1), svc)
		if i%50 == 0 {
			CheckRateLimit(legitimo, svcLegit) // rejected, pero refresca su LRU
		}
	}

	rlMu.Lock()
	_, sigue := peticionesMem[legitimo][svcLegit]
	rlMu.Unlock()
	if !sigue {
		t.Error("el cliente legítimo fue expulsado pese a seguir activo; la expulsión " +
			"debe ser por último uso")
	}

	// Su cuota debe seguir agotada: si se le hubiera olvidado el historial, el
	// rate limit se desactivaría justo para quien sí respetaba el límite.
	if CheckRateLimit(legitimo, svcLegit) {
		t.Error("el cliente legítimo perdió su cuota al expulsar otras entradas")
	}
}
