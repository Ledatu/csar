# syntax=docker/dockerfile:1
FROM golang:1.26.11-alpine AS builder

ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.Version=${VERSION}" -o /csar ./cmd/csar

# ---
FROM alpine:3.24.4
RUN apk add --no-cache --upgrade ca-certificates zlib
RUN adduser -D -u 10001 csar
COPY --from=builder /csar /usr/local/bin/csar
USER csar
ENTRYPOINT ["csar"]
CMD ["-config-file", "/etc/csar/config.yaml"]
