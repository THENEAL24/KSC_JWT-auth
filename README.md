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

## Quick start (Kubernetes with kind)
1) Start Postgres locally (Docker Compose)
```bash
docker compose up -d
```

2) Apply migrations (inside the DB container)
```bash
docker exec -i user-service-db psql -U postgres -d usersdb < migrations/20250915162552_init.sql
```

3) Create a local Kubernetes cluster with kind and map port 8080
```bash
kind create cluster --name user-service --config kind-config.yml
```

4) Build the Docker image and load it into kind
```bash
docker build -t user-service:latest .
kind load docker-image user-service:latest --name user-service
```

5) Apply Kubernetes manifests
```bash
kubectl apply -f deploy/configmap.yml
kubectl apply -f deploy/secret.yml
kubectl apply -f deploy/deployment.yml
kubectl apply -f deploy/service.yml
```

6) Wait until it's ready
```bash
kubectl get pods -w
```

The service is available at `http://localhost:8080` (`kind-config.yml` maps NodePort `30000` to host port 8080). If you use another access method (minikube tunnel/port-forward), adjust the URL accordingly.

## Environment
- `JWT_SECRET` – HMAC secret for tokens (default: `devsecret`) — set in `deploy/secret.yml`
- `PORT` – HTTP server port (default: `8080`) — set in `deploy/configmap.yml`
- `DATABASE_URL` – Postgres DSN — by default `deploy/configmap.yml` uses `postgres://postgres:postgres@host.docker.internal:5432/usersdb?sslmode=disable`.

Database notes:
- With kind, `host.docker.internal` is typically reachable from cluster nodes (Docker Desktop on Windows/macOS). If DB connection fails, deploy Postgres inside the cluster or configure alternative access (e.g., Service/Endpoint or port-forwarding).

## Kubernetes
Main manifests in `deploy/`:
- `configmap.yml` — app parameters (`PORT`, `DATABASE_URL`, etc.)
- `secret.yml` — secrets (`JWT_SECRET`)
- `deployment.yml` — `user-service` Deployment (port 8080, `/healthz` and `/readyz` probes)
- `service.yml` — `NodePort` Service (30000 → 8080)

Useful commands:
```bash
# Inspect resources
kubectl get all

# Pod logs
kubectl logs deploy/user-service

# Delete resources
kubectl delete -f deploy/service.yml \
  -f deploy/deployment.yml \
  -f deploy/secret.yml \
  -f deploy/configmap.yml

# Delete kind cluster
kind delete cluster --name user-service
```

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