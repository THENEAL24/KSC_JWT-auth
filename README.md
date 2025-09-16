# User Service (JWT Auth)

Minimal Go user service with JWT authentication, simple repository via sqlc, and role management. Logs are emitted to stdout using zap.

## Overview
- Go HTTP server (no router) with handlers:
  - POST `/register` – create user, returns JWT
  - POST `/login` – authenticate, returns JWT
  - GET `/me` – current user info (JWT required)
  - POST `/users/{id}/roles` – assign role to user (requires `admin` role)
- PostgreSQL schema: `users`, `roles`, `user_roles` (seeded with `user`, `admin`)
- Passwords hashed with bcrypt
- JWT HS256 with claims: `user_id`, `roles`, `exp`

## Stack
- Go, stdlib `net/http`
- `github.com/jackc/pgx/v5` (DB), `sqlc` (repository gen)
- `github.com/golang-jwt/jwt/v5` (JWT)
- `go.uber.org/zap` (logging)
- Docker Compose (Postgres)

## Quick start
1) Start Postgres
```bash
docker compose up -d
```

2) Apply migrations (inside the DB container)
```bash
docker exec -i user-service-db psql -U postgres -d usersdb < migrations/20250915162552_init.sql
```

3) Run service
```bash
export JWT_SECRET=verysecret   # optional (defaults to devsecret)
go run ./cmd/user-service
```
Server listens on `:8080`.

## Environment
- `JWT_SECRET` – HMAC secret for tokens (default: `devsecret`)
- (Optional) `PORT`, `DATABASE_URL` – not wired by default; can be added easily

## API
- POST `/register`
  - Body: `{ "email": string, "password": string(min 6) }`
  - 201: `{ "token": string }`
- POST `/login`
  - Body: `{ "email": string, "password": string }`
  - 200: `{ "token": string }`
- GET `/me`
  - Header: `Authorization: Bearer <token>`
  - 200: `{ "id": number, "email": string }`
- POST `/users/{id}/roles`
  - Header: `Authorization: Bearer <admin-token>`
  - Body: `{ "role_id": number }` (`1=user`, `2=admin`)
  - 204 No Content

## Examples
Register
```bash
curl -s -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"email":"u1@example.com","password":"secret12"}'
```

Login
```bash
curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"u1@example.com","password":"secret12"}'
```

Me
```bash
TOKEN=... # from register/login
curl -s http://localhost:8080/me -H "Authorization: Bearer $TOKEN"
```

Assign role (admin only)
```bash
ADMIN_TOKEN=...
curl -i -X POST http://localhost:8080/users/2/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role_id":2}'
```

## Development notes
- Logs use zap production config to stdout
- Simple middleware parses `Authorization: Bearer <token>` and injects claims into context
- `sqlc.yml` configured to generate repository code from `internal/db/queries.sql`
- To re-apply only Up migration lines with goose markers:
```bash
awk 'BEGIN{up=1} /\+goose Down/{up=0} up==1{print}' migrations/20250915162552_init.sql \
  | docker exec -i user-service-db psql -U postgres -d usersdb
```