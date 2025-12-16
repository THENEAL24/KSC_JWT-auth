FROM golang:1.24-alpine AS builder
WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go install github.com/pressly/goose/v3/cmd/goose@latest
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o user-service ./cmd/user-service/main.go

FROM alpine:latest
WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=builder /go/bin/goose /usr/local/bin/goose
COPY --from=builder /app/user-service .
COPY migrations ./migrations

EXPOSE 8080
CMD ["./user-service"]
