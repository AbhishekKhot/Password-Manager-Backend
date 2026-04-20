import "dotenv/config";
import { z } from "zod";

/**
 * Typed, validated runtime configuration.
 *
 * Use case:
 *   Every other module in the backend imports `config` from this file instead
 *   of reaching into `process.env` directly. That gives us a single place where
 *   env vars are parsed, coerced to the right types, and validated.
 *
 * Why it's written this way:
 *   - `process.env.X` is always `string | undefined`. Callers would otherwise
 *     have to remember to check for `undefined`, `parseInt`, clamp, etc. at
 *     every call site. Centralising the parsing means a typo in one variable
 *     fails fast at boot, not at 3 a.m. in production.
 *   - zod's `safeParse` collects *all* errors in one pass so a misconfigured
 *     deploy sees every missing/invalid field at once, not one-at-a-time.
 *   - `z.coerce.number()` turns the string "3000" into the number 3000 —
 *     env vars are always strings on the wire; we coerce once here.
 *
 * Concept — "fail fast configuration":
 *   A service that starts with missing secrets and only crashes on first
 *   request is strictly worse than one that refuses to boot. We call
 *   `process.exit(1)` on invalid config so container orchestrators (k8s,
 *   docker) see the failure immediately and can restart / alert.
 */
const schema = z.object({
    DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
    // JWT secrets shorter than 32 chars are brute-forceable for HS256 — we hard-require length.
    JWT_SECRET: z.string().min(32, "JWT_SECRET must be at least 32 characters"),
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    PORT: z.coerce.number().int().positive().default(3000),
    FRONTEND_ORIGIN: z.string().url().default("http://localhost:5173"),
    // 600k is OWASP 2023 guidance for PBKDF2-SHA256 with a 256-bit derived key.
    PBKDF2_ITERATIONS: z.coerce.number().int().min(100_000).default(600_000),
    DB_POOL_MAX: z.coerce.number().int().positive().default(20),
    LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
    REQUEST_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
});

const parsed = schema.safeParse(process.env);

if (!parsed.success) {
    // Print every validation issue before exiting so operators fix them all at once.
    console.error("Invalid environment configuration:");
    for (const issue of parsed.error.issues) {
        console.error(`  - ${issue.path.join(".")}: ${issue.message}`);
    }
    process.exit(1);
}

export const config = parsed.data;
