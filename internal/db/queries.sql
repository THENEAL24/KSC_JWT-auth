-- name: CreateUser :one
INSERT INTO users (email, password) VALUES ($1, $2)
RETURNING id, email;

-- name: GetUserByEmail :one
SELECT id, email, password FROM users WHERE email = $1;

-- name: AssignRole :exec
INSERT INTO user_roles (user_id, role_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: GetRolesByUserId :many
SELECT r.name
FROM roles r
JOIN user_roles ur ON r.id = ur.role_id
WHERE ur.user_id = $1;

-- name: GetUserById :one
SELECT * FROM users
WHERE id = $1;

-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (user_id, token, expires_at)
VALUES ($1, $2, $3)
RETURNING id, user_id, token, created_at, expires_at, revoked;

-- name: GetRefreshTokenByToken :one
SELECT id, user_id, token, created_at, expires_at, revoked
FROM refresh_tokens
WHERE token = $1 AND revoked = FALSE;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked = TRUE
WHERE token = $1;

-- name: RevokeAllUserTokens :exec
UPDATE refresh_tokens
SET revoked = TRUE
WHERE user_id = $1 AND revoked = FALSE;

-- name: DeleteExpiredTokens :exec
DELETE FROM refresh_tokens
WHERE expires_at < NOW();