-- +goose Up
-- +goose StatementBegin
CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,  
    revoked BOOLEAN DEFAULT FALSE
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_ref_user_id ON refresh_tokens(user_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_ref_token ON refresh_tokens(token);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_ref_user_id_revoked ON refresh_tokens(user_id, revoked);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_expiration ON refresh_tokens(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE refresh_tokens;
-- +goose StatementEnd
