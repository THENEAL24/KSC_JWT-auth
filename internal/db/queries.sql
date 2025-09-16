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