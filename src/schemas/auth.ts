import { z } from "zod";

/**
 * Auth request-body schemas.
 *
 * Use case:
 *   Shared zod schemas for /auth/register, /auth/login, and /auth/salt.
 *   Imported by the route handlers AND by unit tests.
 *
 * Why they live in their own file:
 *   If we defined them inside `routes/auth.ts`, importing that file from
 *   a test would also import `../index.js`, which triggers TypeORM
 *   DataSource initialization and tries to connect to Postgres. Tests
 *   for pure schema validation should not require a live DB — so the
 *   schemas are extracted here to a zero-side-effect module.
 */

/**
 * Email schema.
 *
 * - `.email()` — RFC 5322 validation (zod uses a sensible subset).
 * - `.max(254)` — the hard limit on valid email-address length per RFC 5321.
 *   Anything longer is definitely junk and a potential DoS vector on the DB.
 * - `.toLowerCase()` — normalises so `User@Example.com` and `user@example.com`
 *   resolve to the same row. Email addresses are case-insensitive in the local
 *   part per SMTP convention.
 */
export const emailSchema = z.string().email().max(254).toLowerCase();

/**
 * Fixed-length hex string schema factory.
 *
 * Use case:
 *   Validates hex encodings of fixed-byte-count values (a 16-byte salt
 *   encodes to exactly 32 hex chars, a 32-byte hash to 64 hex chars).
 *
 * Why it's a factory:
 *   We need schemas for several different byte-lengths (16-byte salts,
 *   32-byte auth hashes). A factory lets us write one implementation and
 *   call it with the required length.
 *
 * Why we validate encoded format strictly:
 *   The server never parses the bytes — it just stores them. But accepting
 *   `"hello"` as a "salt" would let clients pollute the DB with garbage,
 *   and crash decryption paths later. Tight schemas push the failure as
 *   close to the request boundary as possible.
 */
export const hexSchema = (bytes: number) =>
    z.string().regex(new RegExp(`^[0-9a-f]{${bytes * 2}}$`), `must be ${bytes * 2} hex chars`);

/** Body for POST /auth/register — includes the client-generated salt. */
export const registerBody = z.object({
    email: emailSchema,
    auth_hash: hexSchema(32),
    kdf_salt: hexSchema(16),
});

/** Body for POST /auth/login — no salt needed; the server already has it. */
export const loginBody = z.object({
    email: emailSchema,
    auth_hash: hexSchema(32),
});

/** Query for GET /auth/salt — used by the client to fetch its own salt before deriving the key. */
export const saltQuery = z.object({ email: emailSchema });
