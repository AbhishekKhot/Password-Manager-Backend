-- Baseline schema for the password manager.
-- Matches the entity definitions as of Phase 3.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    email varchar UNIQUE NOT NULL,
    auth_hash varchar NOT NULL,
    kdf_salt varchar NOT NULL,
    kdf_iterations integer NOT NULL DEFAULT 600000,
    created_at timestamp NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vault_items (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    iv varchar NOT NULL,
    encrypted_data text NOT NULL,
    created_at timestamp NOT NULL DEFAULT now(),
    updated_at timestamp NOT NULL DEFAULT now(),
    CONSTRAINT vault_items_encrypted_data_size CHECK (length(encrypted_data) <= 131072)
);

CREATE INDEX IF NOT EXISTS idx_vault_items_user_id ON vault_items(user_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash varchar(64) NOT NULL UNIQUE,
    expires_at timestamp NOT NULL,
    revoked_at timestamp,
    created_at timestamp NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
