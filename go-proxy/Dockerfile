FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o certmagic-proxy

FROM alpine:3.20

RUN addgroup -S proxy && adduser -S proxy -G proxy
WORKDIR /srv

COPY --from=builder /app/certmagic-proxy /usr/local/bin/certmagic-proxy
RUN mkdir -p /srv/certmagic-cache && chown proxy:proxy /srv/certmagic-cache

USER proxy

ENV CERTMAGIC_DOMAINS="" \
    UPSTREAM_URL="" \
    CERTMAGIC_EMAIL="" \
    CERTMAGIC_STORAGE="/srv/certmagic-cache" \
    HTTP_PORT="80" \
    HTTPS_PORT="443" \
    ACME_DIRECTORY=""

EXPOSE 80 443

ENTRYPOINT ["/usr/local/bin/certmagic-proxy"]
