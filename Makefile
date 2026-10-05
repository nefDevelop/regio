# ⚠️  MASTER_KEY en este Makefile: SOLO para tests locales / seed de prueba.
#    Nunca uses estas claves en producción. Genera tu propia clave con:
#      openssl rand -base64 32
#    y defínela en tu archivo .env (ver .env.example).

.PHONY: build run run-dbtest seed test test-unit test-integration test-contract \
	test-cover test-race test-e2e test-smoke test-fuzz bench bench-baseline \
	bench-gate test-load perf perf-report perf-baseline perf-gate perf-seed perf-clean audit ci \
	clean docker-build help

BINARY_NAME=REGIO

# Clave de test compartida por todos los targets de prueba
TEST_KEY=MASTER_KEY=test-master-key-32-bytes-length-!!!

help:
	@echo "Comandos disponibles:"
	@echo "  make build         - Compila la aplicación"
	@echo "  make run           - Ejecuta la aplicación (requiere .env o variables de entorno)"
	@echo "  make run-dbtest    - Ejecuta con datos de prueba (seed + run, SOLO desarrollo)"
	@echo "  make seed          - Genera DB de prueba en /tmp/regio_test.db"
	@echo ""
	@echo "  Pruebas (todo se orquesta vía make):"
	@echo "  make test          - PUERTA PRINCIPAL: unitarios rápidos + suite completa con gate de cobertura"
	@echo "  make test-unit     - Suite en modo -short (sin integración pesada)"
	@echo "  make test-integration - Suite completa in-process (DB/proxy/auth)"
	@echo "  make test-contract - Solo matrices de contrato y caracterización"
	@echo "  make test-cover    - Suite completa + gate de cobertura por umbral"
	@echo "  make test-race     - Tests con detector de race conditions"
	@echo "  make test-e2e      - E2E contra el binario real (-tags e2e)"
	@echo "  make test-smoke    - Subconjunto E2E rápido (smoke + CLI)"
	@echo "  make test-fuzz     - Fuzzing nativo de Go con budget de tiempo (requiere plataforma con -fuzz)"
	@echo "  make bench         - Benchmarks de los caminos calientes"
	@echo "  make bench-gate    - Falla si hay regresión de allocs/B/op vs bench/baseline.txt"
	@echo ""
	@echo "  Rendimiento (ver perf/README.md para el protocolo):"
	@echo "  make perf-seed SEED_N=100000 - Dataset de perf (rate_limits + events a escala)"
	@echo "  make test-load              - Carga contra el proceso real (10/50/100/200)"
	@echo "  make perf-report            - Agrega bench + carga + RSS en perf/report-*.txt"
	@echo "  make perf                   - PUERTA PRINCIPAL: seed + bench + carga + informe"
	@echo ""
	@echo "  make audit         - go vet + gosec (falla ante hallazgos)"
	@echo "  make ci            - Exactamente lo que ejecuta CI: test + race + e2e + audit"
	@echo "  make clean         - Limpia binarios y archivos temporales"
	@echo "  make docker-build  - Compila la imagen Docker"
	@echo ""
	@echo "📖  Antes de desplegar, lee .env.example y genera tu propia MASTER_KEY."

build:
	go build -o $(BINARY_NAME) ./cmd/regio

run: build
	@echo "Usa: ADMIN_DOMAIN=tudominio.com MASTER_KEY=tu_clave ./$(BINARY_NAME)"
	@echo "O crea un archivo .env basado en .env.example"
	./$(BINARY_NAME)

# ⚠️  Claves de prueba — NO USAR EN PRODUCCIÓN
# PERF_DB es siempre una BD aparte: el seed de perf nunca toca data/REGIO.db.
PERF_DB=./data/perf/regio_perf.db
# Volumen del dataset de perf. 10k para iterar rápido, 100k para medir el
# crecimiento de rate_limits/events, 1M para el techo. Ver perf/README.md.
SEED_N?=10000

seed:
	REGIO_DB_PATH=/tmp/regio_test.db \
	MASTER_KEY=seed-master-key-for-testing-only-123 \
	go run ./cmd/seed --force

# Seed de rendimiento: escala las tablas del camino caliente de cada petición
# (rate_limits lo lee/escribe CheckRateLimit, events lo escribe LogEvent).
perf-seed:
	@mkdir -p $(dir $(PERF_DB))
	REGIO_DB_PATH=$(PERF_DB) \
	MASTER_KEY=seed-master-key-for-testing-only-123 \
	go run ./cmd/seed --force -rate-limits $(SEED_N) -events $(SEED_N)

run-dbtest: seed build
	REGIO_DB_PATH=/tmp/regio_test.db \
	MASTER_KEY=seed-master-key-for-testing-only-123 \
	ADMIN_DOMAIN=localhost \
	PORT=9090 \
	./$(BINARY_NAME)

# ---------------------------------------------------------------------------
# Pruebas — punto de entrada único `make test` con targets granulares
# ---------------------------------------------------------------------------

# PUERTA PRINCIPAL: unitarios rápidos + suite completa con gate de cobertura
test: test-unit test-cover
	@echo "✔ make test: unit + suite completa con gate de cobertura"

# Rápido: excluye los tests marcados con testing.Short() (backends, Argon2)
test-unit:
	@mkdir -p data
	$(TEST_KEY) go test -short -count=1 ./...
	@rm -rf data

# Suite completa in-process (unit + integración), sin cobertura
test-integration:
	@mkdir -p data
	$(TEST_KEY) go test -count=1 ./...
	@rm -rf data

# Solo matrices de contrato y caracterización (red de seguridad de refactorizaciones)
test-contract:
	@mkdir -p data
	$(TEST_KEY) go test -count=1 -run 'Contract|Characterization' ./internal/...
	@rm -rf data

# Suite completa con perfil de cobertura + gate por umbrales (scripts/cover_gate.sh)
test-cover:
	@mkdir -p data
	$(TEST_KEY) go test -count=1 -covermode=atomic -coverpkg=./... -coverprofile=cover.out ./...
	@sh scripts/cover_gate.sh cover.out
	@rm -f cover.out
	@rm -rf data

test-race:
	@mkdir -p data
	$(TEST_KEY) go test -race -count=1 ./...
	@rm -rf data

# E2E: compila y arranca el binario real (requiere plataforma con bind local;
# el tag mantiene estos tests fuera de `go test ./...` normal)
test-e2e:
	$(TEST_KEY) go test -count=1 -tags e2e ./e2e/

test-smoke:
	$(TEST_KEY) go test -count=1 -tags e2e -run 'TestE2ESmoke|TestE2ECLI' ./e2e/

# Fuzzing nativo (solo plataformas con soporte -fuzz; en CI linux funciona)
test-fuzz:
	$(TEST_KEY) go test -run=^$$ -fuzz=FuzzCheckWAF -fuzztime=30s ./internal/security/
	$(TEST_KEY) go test -run=^$$ -fuzz=FuzzParseCountries -fuzztime=20s ./internal/security/
	$(TEST_KEY) go test -run=^$$ -fuzz=FuzzIsValidTarget -fuzztime=20s ./internal/security/
	$(TEST_KEY) go test -run=^$$ -fuzz=FuzzIsPrivateIP -fuzztime=20s ./internal/security/
	$(TEST_KEY) go test -run=^$$ -fuzz=FuzzSanitizeLogURI -fuzztime=20s ./internal/handlers/

bench:
	$(TEST_KEY) go test -run=^$$ -bench=. -benchmem ./internal/security/ ./internal/handlers/

# --- Gate de rendimiento (B3a, aprobado) -----------------------------------
# Compara allocs/op y B/op (plataforma-independientes) contra el baseline con
# benchstat; ns/op solo es informativo. Count=6 para significancia estadística.
BENCH_COUNT=6
BENCH_PKGS=./internal/security/ ./internal/handlers/ ./internal/auth/ ./internal/db/

# Regenera bench/baseline.txt (manual; revisar el diff antes de commitear)
bench-baseline:
	BENCH_COUNT=$(BENCH_COUNT) sh scripts/bench_gate.sh baseline

# Falla si hay regresión significativa de allocs (>10%) o bytes (>20%)
bench-gate:
	BENCH_COUNT=$(BENCH_COUNT) sh scripts/bench_gate.sh gate

# ---------------------------------------------------------------------------
# Rendimiento — ver perf/README.md
# ---------------------------------------------------------------------------

# Carga contra el proceso real. El generador es un main aparte
# (scripts/perf/loadgen.go): no toca código de producción y lee el RSS del
# servidor por /proc/<pid>/status.
#
#   make test-load                       # rampa 10/50/100/200, dataset de 10k
#   make test-load SEED_N=100000         # con dataset grande
#   make test-load PERF_LEVELS=50,100    # niveles concretos
PERF_LEVELS?=10,50,100,200
PERF_DURATION?=10s
PERF_WARMUP?=3s
PERF_PROFILES?=health,proxy,auth
PERF_PORT?=19090
PERF_OUT?=perf/load-$(shell date +%Y%m%d-%H%M%S).json

test-load: build
	@mkdir -p perf
	go run scripts/perf/loadgen.go \
		-binary ./$(BINARY_NAME) \
		-db $(PERF_DB) \
		-port $(PERF_PORT) \
		-profiles $(PERF_PROFILES) \
		-levels $(PERF_LEVELS) \
		-duration $(PERF_DURATION) \
		-warmup $(PERF_WARMUP) \
		-out $(PERF_OUT)

# Micro-benchmarks a fichero: es la entrada que consume report.sh.
BENCH_OUT?=perf/bench.txt
bench-file:
	@mkdir -p perf
	$(TEST_KEY) go test -run=^$$ -bench=. -benchmem -benchtime=200ms -count=$(BENCH_COUNT) \
		$(BENCH_PKGS) | tee $(BENCH_OUT)

# Informe agregado. NO ejecuta las mediciones: use `make perf` para eso.
#   make perf-report BENCH_FILE=perf/bench.txt LOAD_JSON=perf/load-*.json
PERF_REPORT_STAMP?=$(shell date +%Y%m%d-%H%M%S)
PERF_REPORT_BASE?=perf/report-$(PERF_REPORT_STAMP)
BENCH_FILE?=perf/bench.txt
LOAD_JSON?=$(shell ls -t perf/load-*.json 2>/dev/null | head -1)

perf-report:
	@mkdir -p perf
	sh scripts/perf/report.sh "$(BENCH_FILE)" "$(LOAD_JSON)" "$(PERF_REPORT_BASE)"

# Genera (o regenera) la referencia local de carga contra la que compara
# perf-gate. Es una copia del JSON de la última corrida considerada buena.
perf-baseline:
	@mkdir -p perf
	@if [ -z "$(LOAD_JSON)" ] || [ ! -r "$(LOAD_JSON)" ]; then \
		echo "perf-baseline: no hay JSON de carga. Ejecuta primero: make test-load"; exit 1; \
	fi
	@cp "$(LOAD_JSON)" perf/load-baseline.json
	@echo "perf-baseline: referencia en perf/load-baseline.json"

# Gate local de rendimiento. NO se ejecuta en CI a propósito: RPS y p95 dependen
# de la CPU y de la carga de la máquina, así que solo valdría en la máquina que
# lo generó.
#
#   make perf-gate                       # usa el último perf/load-*.json
#   make perf-gate PERF_RSS_MAX_MIB=400  # techo absoluto de RSS
#   make perf-gate PERF_P95_MAX_MS=50    # techo absoluto de p95
PERF_RSS_MAX_MIB?=
PERF_P95_MAX_MS?=
perf-gate:
	@sh scripts/perf_gate.sh "$(LOAD_JSON)" "$(PERF_RSS_MAX_MIB)" "$(PERF_P95_MAX_MS)"

# PUERTA PRINCIPAL de rendimiento: dataset + micro-benchmarks + carga + informe.
perf: perf-seed bench-file test-load perf-report
	@echo "✔ make perf: informe en perf/report-*.txt y perf/report-*.md"

# ---------------------------------------------------------------------------
# Auditoría de código
# ---------------------------------------------------------------------------

# gosec SIN -no-fail (aprobado en fase 2). Baseline ENDURECIDO tras la
# auditoría de seguridad: solo se excluye G104 (errores no manejados — deuda
# de estilo histórica del repo). Todo lo demás se vigila; los FPs y decisiones
# puntuales están anotados #nosec en su línea con justificación:
#   G101 (DDL de SQL), G703/G304 (rutas desde env del operador),
#   G706 (logs con SanitizeLog o valores de entorno),
#   G710 (redirect limitado a hosts conocidos + e2e),
#   G124 (Secure condicional en cookie de logout, criterio de setSessionCookie).
GosecExcludes=G104

audit:
	go vet ./...
	@command -v gosec >/dev/null 2>&1 || { echo "gosec no instalado: go install github.com/securego/gosec/v2/cmd/gosec@latest"; exit 1; }
	gosec -exclude=$(GosecExcludes) -fmt text ./cmd/... ./internal/...
	@command -v govulncheck >/dev/null 2>&1 || { echo "govulncheck no instalado: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1; }
	govulncheck ./...

# Exactamente lo que ejecuta CI (jobs: quality/coverage/race/e2e/security)
ci: test test-race test-e2e audit
	@echo "✔ make ci: suite completa + race + e2e + auditoría"

# perf-clean quita solo los artefactos generados; no toca perf/load-baseline.json
# ni perf/README.md, que sí están versionados. El glob empieza por dígito a
# propósito: 'load-*.json' también se llevaría 'load-baseline.json'.
perf-clean:
	rm -f perf/bench.txt perf/load-[0-9]*.json
	rm -f perf/report-*.txt perf/report-*.md
	@echo "perf-clean: artefactos de rendimiento borrados (baseline conservado)"

clean:
	rm -f $(BINARY_NAME)
	rm -rf data cover.out
	$(MAKE) perf-clean
	go clean

docker-build:
	docker build -t regio:latest .
