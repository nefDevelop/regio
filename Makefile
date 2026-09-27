# ⚠️  MASTER_KEY en este Makefile: SOLO para tests locales / seed de prueba.
#    Nunca uses estas claves en producción. Genera tu propia clave con:
#      openssl rand -base64 32
#    y defínela en tu archivo .env (ver .env.example).

.PHONY: build run run-dbtest seed test test-unit test-integration test-contract \
	test-cover test-race test-e2e test-smoke test-fuzz bench bench-baseline \
	bench-gate audit ci clean docker-build help

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
seed:
	REGIO_DB_PATH=/tmp/regio_test.db \
	MASTER_KEY=seed-master-key-for-testing-only-123 \
	go run ./cmd/seed --force

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

clean:
	rm -f $(BINARY_NAME)
	rm -rf data cover.out
	go clean

docker-build:
	docker build -t regio:latest .
