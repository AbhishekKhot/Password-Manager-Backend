import "reflect-metadata";
import { DataSource } from "typeorm";
import { config } from "./config.js";
import { User } from "./entities/User.js";
import { VaultItem } from "./entities/VaultItem.js";
import { RefreshToken } from "./entities/RefreshToken.js";
import { Baseline1700000000000 } from "./migrations/1700000000000-Baseline.js";

/**
 * TypeORM DataSource — single source of truth for DB access.
 *
 * Why this file is separate from `index.ts`:
 *   The TypeORM CLI (`typeorm migration:generate`, `migration:create`) needs
 *   a module that exports a DataSource *without* booting Fastify. Keeping the
 *   DataSource here means the CLI can import it, and so can the app.
 *
 * `synchronize: false` is critical — autosync would silently drop or alter
 * columns. All schema changes go through numbered migrations under
 * `src/migrations/`, which are run at boot via `runMigrations()` in index.ts.
 *
 * `migrationsRun: false` — we call `runMigrations()` explicitly in the boot
 * sequence so we can log it and fail fast with a clear error.
 */
export const AppDataSource = new DataSource({
    type: "postgres",
    url: config.DATABASE_URL,
    synchronize: false,
    logging: config.NODE_ENV === "development" ? true : ["error", "warn"],
    entities: [User, VaultItem, RefreshToken],
    // Static import (not glob) — ESM + NodeNext doesn't play well with
    // TypeORM's runtime glob loader, and a hand-maintained list is greppable.
    migrations: [Baseline1700000000000],
    migrationsTableName: "migrations",
    extra: {
        max: config.DB_POOL_MAX,
    },
});
