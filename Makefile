.PHONY: build run test audit clean docker-build help

BINARY_NAME=REGIO

help:
	@echo "Comandos disponibles:"
	@echo "  make build         - Compila la aplicación"
	@echo "  make run           - Ejecuta la aplicación localmente (requiere MASTER_KEY y ADMIN_DOMAIN)"
	@echo "  make test          - Ejecuta todos los tests"
	@echo "  make audit         - Ejecuta auditoría de seguridad y linter"
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

audit:
	go vet ./...
	# Requiere gosec: go install github.com/securego/gosec/v2/cmd/gosec@latest
	-gosec ./...

clean:
	rm -f $(BINARY_NAME)
	rm -rf data
	go clean

docker-build:
	docker build -t regio:latest .
