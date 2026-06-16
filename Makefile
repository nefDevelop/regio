# ⚠️  MASTER_KEY en este Makefile: SOLO para tests locales / seed de prueba.
#    Nunca uses estas claves en producción. Genera tu propia clave con:
#      openssl rand -base64 32
#    y defínela en tu archivo .env (ver .env.example).

.PHONY: build run run-dbtest seed test test-race audit clean docker-build help

BINARY_NAME=REGIO

help:
	@echo "Comandos disponibles:"
	@echo "  make build         - Compila la aplicación"
	@echo "  make run           - Ejecuta la aplicación (requiere .env o variables de entorno)"
	@echo "  make run-dbtest    - Ejecuta con datos de prueba (seed + run, SOLO desarrollo)"
	@echo "  make seed          - Genera DB de prueba en /tmp/regio_test.db"
	@echo "  make test          - Ejecuta todos los tests"
	@echo "  make test-race     - Tests con detector de race conditions"
	@echo "  make audit         - Ejecuta go vet + gosec"
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

# ⚠️  Clave de test — SOLO para la suite de tests
test:
	@mkdir -p data
	MASTER_KEY=test-master-key-32-bytes-length-!!! go test -v ./...
	@rm -rf data

test-race:
	@mkdir -p data
	MASTER_KEY=test-master-key-32-bytes-length-!!! go test -race -v ./...
	@rm -rf data

audit:
	go vet ./...
	# Requiere gosec: go install github.com/securego/gosec/v2/cmd/gosec@latest
	-gosec -no-fail -fmt text ./...

clean:
	rm -f $(BINARY_NAME)
	rm -rf data
	go clean

docker-build:
	docker build -t regio:latest .
