# Etapa 1: Compilación
FROM golang:alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o REGIO ./cmd/regio

# Etapa 2: Imagen final minimalista
FROM alpine:latest

LABEL org.opencontainers.image.title="reGIO" \
      org.opencontainers.image.description="Reverse Gateway for Internal Operations" \
      org.opencontainers.image.source="https://github.com/user/regio"

RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates tzdata libcap mailcap && \
    adduser -D -u 1000 regio && \
    rm -rf /var/cache/apk/*

WORKDIR /home/regio
COPY --from=builder --chown=regio:regio /app/REGIO .

RUN setcap 'cap_net_bind_service=+ep' /home/regio/REGIO && \
    mkdir data && chown regio:regio data

USER regio

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost/REGIO-login || exit 1

CMD ["./REGIO"]
