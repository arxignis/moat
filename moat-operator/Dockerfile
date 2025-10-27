FROM golang:1.22 AS builder

WORKDIR /workspace

COPY go.mod ./
COPY go.sum ./
COPY controllers ./controllers
COPY main.go ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /manager main.go

FROM gcr.io/distroless/base-debian12
WORKDIR /
COPY --from=builder /manager /manager
USER 65532:65532

ENTRYPOINT ["/manager"]
