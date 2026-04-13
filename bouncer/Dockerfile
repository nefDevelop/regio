# Etapa 1: Compilación
FROM golang:1.21-alpine AS builder
# Instalar dependencias para CGO (necesario para go-sqlite3)
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY main.go .
# Inicializar módulo y descargar dependencias
RUN go mod init bouncer && \
    go get github.com/mattn/go-sqlite3 && \
    go get golang.org/x/crypto/argon2 && \
    go mod tidy && \
    CGO_ENABLED=1 GOOS=linux go build -a -o bouncer main.go

# Etapa 2: Imagen final minimalista
FROM alpine:latest
# Necesitamos dependencias básicas y librerías C compatibles para SQLite
RUN apk add --no-cache ca-certificates tzdata sqlite-libs libc6-compat
WORKDIR /root/
# Copiamos el binario compilado
COPY --from=builder /app/bouncer .
# Crear carpeta para montar la base de datos SQLite
RUN mkdir data
EXPOSE 80
CMD ["./bouncer"]
