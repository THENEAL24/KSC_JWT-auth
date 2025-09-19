FROM golang:1.24-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

RUN apk add --no-cache ca-certificates git build-base

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o user-service ./cmd/user-service/main.go

FROM alpine:latest
WORKDIR /root/

COPY --from=builder /app/user-service .

EXPOSE 8080

CMD ["./user-service"]
