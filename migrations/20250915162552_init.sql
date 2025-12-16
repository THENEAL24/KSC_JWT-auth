-- +goose Up
-- +goose StatementBegin
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT,
    auth_provider TEXT DEFAULT 'local',
    verified_email BOOLEAN DEFAULT FALSE,
    name TEXT,
    picture TEXT
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE user_roles (
    user_id INT REFERENCES users(id),
    role_id INT REFERENCES roles(id),
    PRIMARY KEY (user_id, role_id)
);
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO roles (name) VALUES ('user'), ('admin');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE user_roles;
DROP TABLE roles;
DROP TABLE users;
-- +goose StatementEnd