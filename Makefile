.PHONY: build run test test-race audit clean docker-build help

BINARY_NAME=REGIO

help:
	@echo "Comandos disponibles:"
	@echo "  make build         - Compila la aplicación"
	@echo "  make run           - Ejecuta la aplicación localmente (requiere MASTER_KEY y ADMIN_DOMAIN)"
	@echo "  make test          - Ejecuta todos los tests"
	@echo "  make test-race     - Tests con detector de race conditions"
	@echo "  make audit         - Ejecuta go vet + gosec"
	@echo "  make clean         - Limpia binarios y archivos temporales"
	@echo "  make docker-build  - Compila la imagen Docker"

build:
	go build -o $(BINARY_NAME) ./cmd/regio

run: build
	./$(BINARY_NAME)

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
