-- +goose Up
-- +goose StatementBegin
CREATE TABLE oauth_accounts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    picture TEXT,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    token_expiry TIMESTAMP NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_oauth_user_id ON oauth_accounts(user_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_oauth_provider_user_id ON oauth_accounts(provider, provider_user_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_oauth_email ON oauth_accounts(email);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE oauth_accounts;
-- +goose StatementEnd
