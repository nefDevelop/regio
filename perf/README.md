# Rendimiento de reGIO

Instrumentación de rendimiento del proxy inverso: micro-benchmarks del camino
caliente, prueba de carga contra el proceso real y consumo de RSS.

## Comandos

```bash
make seed SEED_N=10000        # dataset de perf (rate_limits + events a escala)
make bench                    # micro-benchmarks (existente)
make test-load                # carga: 10/50/100/200 de concurrencia
make perf-report              # agrega bench + carga + RSS -> perf/report-*.txt|.md
make perf                     # PUERTA PRINCIPAL: seed + bench + carga + informe
make perf-gate                # falla ante regresión vs perf/load-baseline.json
make perf-baseline            # regenera la referencia del gate
```

Ajustes útiles:

```bash
make perf SEED_N=100000                        # dataset grande
make test-load PERF_LEVELS=50,100              # solo esos niveles
make test-load PERF_DURATION=30s               # ventanas más largas
make test-load PERF_PROFILES=proxy             # un solo perfil
make perf-gate PERF_RSS_MAX_MIB=400            # techo absoluto de RSS
make perf-gate PERF_P95_MAX_MS=50              # techo absoluto de p95
```

## Qué mide cada target

| Target | Qué mide | Dónde |
| --- | --- | --- |
| `perf-seed` | Volumen del dataset | `cmd/seed` (`-rate-limits`, `-events`) |
| `bench` / `bench-file` | ns/op, B/op, allocs/op del camino caliente | `internal/security`, `handlers`, `auth`, `db` |
| `test-load` | RPS, p50/p95/p99, RSS pico y delta | `scripts/perf/loadgen.go` |
| `perf-report` | Todo lo anterior en un informe | `scripts/perf/report.sh` |
| `perf-gate` | Regresión de RSS / p95 / RPS | `scripts/perf_gate.sh` |

## Los tres perfiles de carga

reGIO es un proxy inverso: no tiene endpoints propios, así que la carga se hace
pasar **a través** del proxy hacia un upstream dummy. Los perfiles separan tres
cosas que si se mezclan no significan nada:

| Perfil | Petición | Qué aísla |
| --- | --- | --- |
| `health` | `GET /health` | Suelo de HTTP puro. `MainHandler` responde antes del `SecurityEngine`, así que por diferencia con `proxy` sale el coste de la capa de seguridad. |
| `proxy` | `GET /` con `Host: perf.local` | Stack completo: geo + fail2ban + rate limit + WAF + proxy + dial anti-SSRF + logging. Servicio `is_public=1`, sin login. |
| `auth` | `POST /REGIO-login` con `user`/`pass` válidos | Argon2 (`VerifyPassword`) más la escritura en `events` y `sessions` de cada intento. **No es una medida de throughput**: mide el KDF. |

## Dataset: qué escala y qué no

`make seed SEED_N=N` escala **rate_limits** y **events**, que están en el camino
caliente de cada petición (`CheckRateLimit` las lee y escribe, `LogEvent` las
escribe).

Lo que **no** escala, a propósito:

| Tabla | Filas | Por qué |
| --- | --- | --- |
| `users` | 3 | Un proxy inverso real tiene decenas de usuarios, no un millón. |
| `sessions` | 3 | Igual: el volumen de clientes se representa con IPs virtuales. |
| `servicios` | 6 | Puentes configurados, no datos. |
| `rate_limits` | `SEED_N` | Ventana del rate limiter + persistencia. |
| `events` | `SEED_N` | Log de auditoría. |

Un `SEED_N=1000000` de usuarios no mediría el proxy: mediría el coste de
construir un fichero de usuarios que un proxy real jamás tendría.

Costes medidos en esta máquina (Ryzen 5 5600X, NVMe):

| `SEED_N` | Tiempo de seed | Tamaño de DB |
| ---: | ---: | ---: |
| 10.000 | 0,2 s | 2,9 MiB |
| 100.000 | 0,9 s | 29,2 MiB |
| 1.000.000 | 11,8 s | 294,1 MiB |

Los 70 `rate_limits` y 20 `events` del seed original se conservan tal cual con
los valores por defecto, para no alterar `make run-dbtest`.

## Protocolo de medición

Sin esto los números no son comparables entre sí:

1. **Un proyecto a la vez.** Nada más corriendo: una sesión de navegador o un
   `cargo build` en segundo plano contaminan la latencia.
2. **Secuencial, nunca en paralelo.** Con 6,9 GiB de swap en uso y 15 GiB
   libres de 31, las mediciones de RSS son especialmente sensibles.
3. **Tres repeticiones, mediana.** Para comparar dos versiones, lo mínimo
   razonable es `-duration 30s` por fase.
4. **El warmup no se contabiliza** (`PERF_WARMUP`), pero sí consume presupuesto
   del rate limiter: por eso el generador da un bloque de IPs nuevo a cada fase.
5. **Anota siempre la cabecera de entorno.** `perf-report` la incluye sola: CPU,
   núcleos, RAM, kernel, versión de Go, `GOMAXPROCS` y tamaño del dataset.

## Por qué hay IPs virtuales

`CheckRateLimit` limita a **100 peticiones por minuto y por IP**. Sin IPs
virtuales el 99,9 % de la carga recibiría 429 y estaríamos midiendo el rate
limiter en vez del proxy.

El generador manda `X-Forwarded-For` con una IP del rango `198.18.0.0/15`
(RFC 2544, nunca enrutable) y arranca el servidor con `TRUSTED_PROXIES=127.0.0.1`
para que `getRealIP` confíe en ese header.

Dos ajustes que no son negociables:

- **Bloques de IP disjuntos por fase.** La ventana del rate limiter son 60 s y
  las fases duran menos, así que sin bloques separados la fase 2 heredaría el
  consumo de la fase 1.
- **Techo de ~10.000 IPs.** `CheckRateLimit` aborta con "demasiadas peticiones"
  cuando hay más de 10.000 IPs registradas, y la limpieza solo borra IPs con 10
  minutos de inactividad. Es un techo del diseño de regio, no del generador;
  `-ip-pool` avisa si lo acercas.

## RSS: cómo se mide

El generador lee `/proc/<pid>/status` del servidor cada 50 ms:

- `VmRSS` —resident set actual.
- `VmHWM` —pico desde el arranque del proceso. Se mide **antes** de la carga
  para tener el RSS en reposo, sin el cual "180 MiB" no dice nada.

Un `ΔRSS` positivo y sostenido entre fases indica **memoria retenida**, no fuga
confirmada. Antes de acusar a una fuga: `make test-race`, y repetir tras un
`LimpiarRateLimiter()` (cada 10 min el servidor ya purga `rate_limits` y
`peticionesMem`).

## Gates

Dos gates, con alcances distintos:

- `make bench-gate` — `allocs/op` +10 %, `B/op` +20 % contra
  `bench/baseline.txt`. **Independiente de la máquina**, por eso es el único
  que tendría sentido en CI.
- `make perf-gate` — RSS pico +15 %, p95 +25 %, RPS −10 % contra
  `perf/load-baseline.json`, más techos absolutos opcionales. **Solo local**: RPS,
  p95 y RSS dependen de la CPU y de la carga de la máquina.

## Ficheros

```
scripts/perf/loadgen.go     # generador + lector de RSS (main aparte, //go:build ignore)
scripts/perf/report.sh      # agregador del informe
scripts/perf_gate.sh        # gate de carga
perf/                       # informes y referencias (generado)
```

`loadgen.go` lleva `//go:build ignore` a propósito: así queda fuera de
`./...` y no aparece en `make test`, `make audit` ni `go vet ./...`. No toca
ninguna ruta de código de producción.