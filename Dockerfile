# Etapa 1: Compilación
FROM golang:alpine AS builder
WORKDIR /app
COPY . .
# Inicializar módulo y descargar dependencias
RUN go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -a -o REGIO .

# Etapa 2: Imagen final minimalista
FROM alpine:latest
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates tzdata
WORKDIR /root/
# Copiamos el binario compilado
COPY --from=builder /app/REGIO .
# Crear carpeta para montar la base de datos SQLite
RUN mkdir data
EXPOSE 80
CMD ["./REGIO"]
