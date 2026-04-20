import { z } from "zod";

/**
 * Vault request-shape schemas.
 *
 * Use case:
 *   Shared zod schemas for /vault endpoints. Consumed by the controller
 *   (at the HTTP boundary) and — in the future — by integration tests.
 *
 * Why they live in their own file (same reason as schemas/auth.ts):
 *   Importing them must be side-effect-free so tests can load them
 *   without triggering TypeORM DataSource initialisation.
 */

/**
 * Max size of ciphertext payload. 64 KiB of ciphertext ≈ 32 KiB plaintext,
 * which is far more than a single credential needs. Anything larger is
 * almost certainly an attempt to eat DB space.
 */
const MAX_ENCRYPTED_BYTES = 64 * 1024;

const DEFAULT_PAGE_LIMIT = 100;
const MAX_PAGE_LIMIT = 500;

/** AES-GCM IV is exactly 12 bytes → 24 hex chars. Tight schema = early failure. */
export const ivSchema = z
    .string()
    .regex(/^[0-9a-f]{24}$/, "iv must be 12 bytes / 24 hex chars");

/** Hex-only ciphertext, bounded length. `*2` because each byte is two hex chars. */
export const ciphertextSchema = z
    .string()
    .regex(/^[0-9a-f]+$/)
    .max(MAX_ENCRYPTED_BYTES * 2);

export const createBody = z.object({
    iv: ivSchema,
    encrypted_data: ciphertextSchema,
});

/**
 * Partial-update schema.
 *
 * `.refine()` enforces "at least one of iv or encrypted_data must be set"
 * — accepting an empty `{}` is meaningless work.
 *
 * Why both fields often update together:
 *   AES-GCM requires a fresh IV on every re-encryption. Updating the
 *   ciphertext without the IV would yield a row that can't be decrypted.
 */
export const updateBody = z
    .object({
        iv: ivSchema.optional(),
        encrypted_data: ciphertextSchema.optional(),
    })
    .refine((v) => v.iv !== undefined || v.encrypted_data !== undefined, {
        message: "At least one of iv or encrypted_data must be provided",
    });

export const idParam = z.object({ id: z.string().uuid() });

/**
 * Cursor-pagination query.
 *
 * `after` is the ID returned by the previous page. The service uses
 * `id > after` to generate the next slice — see VaultService.list.
 */
export const listQuery = z.object({
    limit: z.coerce
        .number()
        .int()
        .positive()
        .max(MAX_PAGE_LIMIT)
        .default(DEFAULT_PAGE_LIMIT),
    after: z.string().uuid().optional(),
});
