FROM golang:1.24 AS builder

WORKDIR /app

COPY go.mod go.sum /app/
COPY controllers /app/controllers
COPY main.go /app/main.go

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /app/manager main.go

FROM gcr.io/distroless/static-debian13:nonroot
WORKDIR /app
COPY --from=builder /app/manager /app/manager
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532

ENTRYPOINT ["/app/manager"]
