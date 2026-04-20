import { describe, it, expect } from "vitest";
import { registerBody, loginBody, saltQuery, emailSchema, hexSchema } from "../src/schemas/auth.js";

/**
 * Auth schema tests.
 *
 * Use case:
 *   Pure-function tests that prove the zod schemas accept well-formed
 *   payloads and reject malformed ones. No DB, no HTTP — just parse/throw.
 *
 * Why schemas live in `src/schemas/` (not in the route files):
 *   Importing a route file pulls in AppDataSource, which tries to connect
 *   to Postgres at module-load time. Tests for parsing logic shouldn't need
 *   a running DB, so the schemas are extracted for side-effect-free import.
 */
describe("auth schemas", () => {
    // Exactly 64 hex chars = 32 bytes = the expected auth_hash length.
    const validHash32 = "a".repeat(64);
    // Exactly 32 hex chars = 16 bytes = the expected salt length.
    const validSalt16 = "b".repeat(32);

    it("accepts a well-formed registration payload", () => {
        const parsed = registerBody.parse({
            email: "user@example.com",
            auth_hash: validHash32,
            kdf_salt: validSalt16,
        });
        expect(parsed.email).toBe("user@example.com");
    });

    // `.toLowerCase()` on emailSchema is a correctness requirement — without it,
    // `User@Example.COM` would create a different row from `user@example.com`
    // and the user wouldn't be able to log in with different casing.
    it("lowercases email on parse", () => {
        const parsed = registerBody.parse({
            email: "MiXeD@Example.COM",
            auth_hash: validHash32,
            kdf_salt: validSalt16,
        });
        expect(parsed.email).toBe("mixed@example.com");
    });

    it("rejects a too-short auth_hash", () => {
        expect(() =>
            registerBody.parse({ email: "u@e.com", auth_hash: "a".repeat(10), kdf_salt: validSalt16 })
        ).toThrow();
    });

    // `z`, not `0-9a-f`, so this salt is not hex → must throw.
    it("rejects a non-hex salt", () => {
        expect(() =>
            registerBody.parse({ email: "u@e.com", auth_hash: validHash32, kdf_salt: "z".repeat(32) })
        ).toThrow();
    });

    it("rejects an invalid email in login payload", () => {
        expect(() => loginBody.parse({ email: "not-an-email", auth_hash: validHash32 })).toThrow();
    });

    it("rejects missing email in salt query", () => {
        expect(() => saltQuery.parse({})).toThrow();
    });

    // RFC 5321 caps email length at 254 chars. Anything longer is
    // (a) invalid by spec, and (b) a payload-size DoS vector on the DB.
    it("emailSchema caps length at 254", () => {
        const tooLong = "a".repeat(250) + "@ex.com";
        expect(() => emailSchema.parse(tooLong)).toThrow();
    });

    // `hexSchema(n)` must accept exactly 2n chars — off-by-one in either
    // direction is rejected. This guards against hex strings with a
    // stray byte (24 → 23 or 25 chars) slipping through.
    it("hexSchema enforces exact byte length", () => {
        const s = hexSchema(12);
        expect(s.safeParse("a".repeat(24)).success).toBe(true);
        expect(s.safeParse("a".repeat(23)).success).toBe(false);
        expect(s.safeParse("a".repeat(25)).success).toBe(false);
    });
});
