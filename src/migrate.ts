import "reflect-metadata";
import { readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "../node_modules/@types/pg/index.js";
import { config } from "./config.js";

/**
 * Plain-SQL migration runner.
 *
 * Use case:
 *   Applies every `*.sql` file under `migrations/` to the configured Postgres
 *   in lexicographic (i.e. numbered-filename) order, exactly once.
 *
 * Why we wrote our own instead of using `typeorm migration:run`:
 *   - TypeORM's CLI is painful under ESM + NodeNext + decorators. It expects
 *     a specific tsconfig and ts-node loader setup.
 *   - Plain .sql files are code-reviewable, greppable, and can be tested by
 *     pasting into psql. TypeORM-generated JS migrations hide the SQL behind
 *     QueryRunner API calls.
 *   - A 40-line runner is easier to reason about than a framework.
 *
 * Concept — "idempotent, transactional migrations":
 *   Every migration is wrapped in BEGIN/COMMIT. If the SQL throws mid-run,
 *   we ROLLBACK and rethrow — the filename is NOT recorded as applied, so
 *   the next invocation retries cleanly. The `schema_migrations` table is
 *   the "journal" that tracks which files have been successfully applied.
 */

// __dirname is not available in ESM — we derive it from import.meta.url.
const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "migrations");

async function run() {
    // Plain `pg` client (not the TypeORM pool) — migrations run once, during
    // deploy/CI, and shouldn't tie up a pool slot or require the full DataSource.
    const client = new pg.Client({ connectionString: config.DATABASE_URL });
    await client.connect();

    // Bootstrap the journal table on first run. Using IF NOT EXISTS makes this
    // migration-runner itself idempotent.
    await client.query(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
            name varchar PRIMARY KEY,
            applied_at timestamp NOT NULL DEFAULT now()
        )
    `);

    // Load the set of already-applied migration filenames. Using a Set gives
    // O(1) membership checks in the loop below.
    const { rows: appliedRows } = await client.query<{ name: string }>(
        "SELECT name FROM schema_migrations"
    );
    const applied = new Set<string>(appliedRows.map((r: { name: string }) => r.name));

    // Sort lexicographically. Files are named `0001_`, `0002_`, etc. so
    // lexical sort === numeric sort, guaranteeing deterministic order.
    const files = readdirSync(MIGRATIONS_DIR)
        .filter((f) => f.endsWith(".sql"))
        .sort();

    for (const file of files) {
        if (applied.has(file)) {
            console.log(`  skip ${file}`);
            continue;
        }
        const sql = readFileSync(join(MIGRATIONS_DIR, file), "utf8");
        console.log(`apply ${file}`);
        // Transactional wrapper — either the whole migration commits, or nothing does.
        // This prevents half-applied schemas that would wedge future migrations.
        await client.query("BEGIN");
        try {
            await client.query(sql);
            await client.query("INSERT INTO schema_migrations (name) VALUES ($1)", [file]);
            await client.query("COMMIT");
        } catch (err) {
            await client.query("ROLLBACK");
            console.error(`  failed: ${file}`);
            throw err;
        }
    }

    await client.end();
    console.log("migrations up-to-date");
}

// Top-level catch so an uncaught rejection gives a non-zero exit code
// (important for CI pipelines that decide "did migrate succeed?").
run().catch((err) => {
    console.error(err);
    process.exit(1);
});
