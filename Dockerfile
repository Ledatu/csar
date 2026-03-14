# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN sed -i '/^replace /d' go.mod && go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.Version=docker" -o /csar ./cmd/csar

# ---
FROM alpine:3.21
RUN apk add --no-cache ca-certificates
RUN adduser -D -u 10001 csar
COPY --from=builder /csar /usr/local/bin/csar
USER csar
ENTRYPOINT ["csar"]
CMD ["-config", "/etc/csar/config.yaml"]
