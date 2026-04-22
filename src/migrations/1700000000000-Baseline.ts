import type { MigrationInterface, QueryRunner } from "typeorm";

/**
 * Baseline schema.
 *
 * Creates the three core tables — users, vault_items, refresh_tokens — plus
 * the indexes and check constraints the app relies on. Equivalent to the
 * previous `0001_baseline.sql` but expressed as a TypeORM migration so it
 * runs through the same `runMigrations()` pipeline at boot.
 *
 * The timestamp prefix (1700000000000) is a TypeORM convention — migrations
 * are sorted by this number, so newer migrations must use a larger value.
 */
export class Baseline1700000000000 implements MigrationInterface {
    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`);

        await queryRunner.query(`
            CREATE TABLE IF NOT EXISTS users (
                id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
                email varchar UNIQUE NOT NULL,
                auth_hash varchar NOT NULL,
                kdf_salt varchar NOT NULL,
                kdf_iterations integer NOT NULL DEFAULT 600000,
                created_at timestamp NOT NULL DEFAULT now()
            )
        `);

        await queryRunner.query(`
            CREATE TABLE IF NOT EXISTS vault_items (
                id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
                user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                iv varchar NOT NULL,
                encrypted_data text NOT NULL,
                created_at timestamp NOT NULL DEFAULT now(),
                updated_at timestamp NOT NULL DEFAULT now(),
                CONSTRAINT vault_items_encrypted_data_size CHECK (length(encrypted_data) <= 131072)
            )
        `);

        await queryRunner.query(
            `CREATE INDEX IF NOT EXISTS idx_vault_items_user_id ON vault_items(user_id)`
        );

        await queryRunner.query(`
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
                user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash varchar(64) NOT NULL UNIQUE,
                expires_at timestamp NOT NULL,
                revoked_at timestamp,
                created_at timestamp NOT NULL DEFAULT now()
            )
        `);

        await queryRunner.query(
            `CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)`
        );
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP TABLE IF EXISTS refresh_tokens`);
        await queryRunner.query(`DROP TABLE IF EXISTS vault_items`);
        await queryRunner.query(`DROP TABLE IF EXISTS users`);
    }
}
