# Etapa 1: Compilación
FROM golang:alpine AS builder
WORKDIR /app
COPY . .
# Descargar dependencias y compilar desde la nueva estructura
RUN go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o REGIO ./cmd/regio

# Etapa 2: Imagen final minimalista
FROM alpine:latest
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 regio
WORKDIR /home/regio
COPY --from=builder --chown=regio:regio /app/REGIO .
# Crear carpeta para montar la base de datos SQLite
RUN mkdir data && chown regio:regio data
USER regio
EXPOSE 80
CMD ["./REGIO"]
