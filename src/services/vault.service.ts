import type { Repository } from "typeorm";
import { VaultItem } from "../entities/VaultItem.js";
import { ConflictError, NotFoundError } from "../errors/AppError.js";

/**
 * Vault service — per-user CRUD over encrypted blobs.
 *
 * ── Design pattern: Service Layer ─────────────────────────────────────────
 * All business rules live here: per-user quota, cursor pagination, the
 * "update-with-returning" trick. The controller does nothing but parse
 * input and forward it.
 *
 * ── Design pattern: Repository pattern (TypeORM) ──────────────────────────
 * `Repository<VaultItem>` is the seam between the service and SQL. The
 * service only speaks in entity terms; switching to a different ORM
 * would be an isolated change.
 *
 * Zero-knowledge reminder:
 *   This service never parses ciphertext. It's a dumb per-user blob store.
 *   Do NOT add endpoints that read, search, or transform vault contents —
 *   the server literally cannot, the key lives only in the client browser.
 */

const MAX_ITEMS_PER_USER = 10_000;
const DEFAULT_PAGE_LIMIT = 100;
const MAX_PAGE_LIMIT = 500;

export interface ListArgs {
    userId: string;
    limit?: number;
    after?: string;
}

export interface ListResult {
    items: VaultItem[];
    nextCursor: string | null;
}

export interface CreateArgs {
    userId: string;
    iv: string;
    encrypted_data: string;
}

export interface UpdateArgs {
    userId: string;
    id: string;
    iv?: string;
    encrypted_data?: string;
}

export interface DeleteArgs {
    userId: string;
    id: string;
}

export class VaultService {
    constructor(private readonly vaultRepository: Repository<VaultItem>) { }

    /**
     * List a user's encrypted vault items, cursor-paginated.
     *
     * Concept — "cursor pagination" (a.k.a. keyset pagination):
     *   We return rows with `id > after`. This is stable under concurrent
     *   inserts — unlike offset pagination which skips or repeats rows
     *   when the underlying set mutates between pages.
     *
     * Trick — "limit + 1":
     *   We request one row more than the page size. If we get it, another
     *   page exists and we emit the last-included row's ID as the next
     *   cursor. If not, we're on the last page (`nextCursor: null`). This
     *   avoids a second `count(*)` query.
     */
    async list({ userId, limit = DEFAULT_PAGE_LIMIT, after }: ListArgs): Promise<ListResult> {
        const effectiveLimit = Math.min(limit, MAX_PAGE_LIMIT);

        const qb = this.vaultRepository
            .createQueryBuilder("v")
            .where("v.user_id = :userId", { userId })
            .orderBy("v.id", "ASC")
            .limit(effectiveLimit + 1);

        if (after) qb.andWhere("v.id > :after", { after });

        const rows = await qb.getMany();
        const hasMore = rows.length > effectiveLimit;
        const items = hasMore ? rows.slice(0, effectiveLimit) : rows;
        // Intermediate `last` keeps `noUncheckedIndexedAccess` happy.
        const last = items[items.length - 1];
        const nextCursor = hasMore && last ? last.id : null;

        return { items, nextCursor };
    }

    /**
     * Create a new encrypted item for the user.
     *
     * Why we `count` before insert:
     *   Enforces MAX_ITEMS_PER_USER. There is a theoretical TOCTOU race
     *   (two concurrent inserts could both observe count=9999 and both
     *   win at 10000) but it is not exploitable in practice — hitting
     *   this quota is already an anomalous signal worth investigating.
     *
     * Why the service does not validate hex format:
     *   That's the controller's zod-schema job. By the time args reach
     *   the service, shape and size are already guaranteed. Re-validating
     *   here would duplicate responsibility and drift over time.
     */
    async create({ userId, iv, encrypted_data }: CreateArgs): Promise<VaultItem> {
        const count = await this.vaultRepository.count({ where: { user_id: userId } });
        if (count >= MAX_ITEMS_PER_USER) {
            throw new ConflictError("Vault item limit reached");
        }

        const item = this.vaultRepository.create({ user_id: userId, iv, encrypted_data });
        return this.vaultRepository.save(item);
    }

    /**
     * Update an existing vault item, enforcing per-user ownership.
     *
     * Why one UPDATE with RETURNING instead of SELECT + UPDATE:
     *   Single round-trip. The `WHERE id = :id AND user_id = :userId`
     *   clause is also implicit authorisation — a user cannot touch
     *   another user's row even if they guess a UUID, because the WHERE
     *   won't match.
     *
     * Why we build `updates` step-by-step:
     *   `exactOptionalPropertyTypes` in tsconfig makes `{ iv: undefined }`
     *   a type error (it's not the same as omitting `iv`). Conditional
     *   assignment produces an object with only the set keys.
     *
     * Why `updated_at: () => "now()"`:
     *   TypeORM treats function values as raw SQL expressions. We want
     *   the DB clock to stamp the row (consistent, atomic with the
     *   UPDATE), not Node's `Date.now()` which drifts between replicas.
     */
    async update({ userId, id, iv, encrypted_data }: UpdateArgs): Promise<VaultItem> {
        const updates: { iv?: string; encrypted_data?: string; updated_at: () => string } = {
            updated_at: () => "now()",
        };
        if (iv !== undefined) updates.iv = iv;
        if (encrypted_data !== undefined) updates.encrypted_data = encrypted_data;

        const result = await this.vaultRepository
            .createQueryBuilder()
            .update(VaultItem)
            .set(updates)
            .where("id = :id AND user_id = :userId", { id, userId })
            .returning("*")
            .execute();

        const row = result.raw?.[0] as VaultItem | undefined;
        if (!row) throw new NotFoundError("Vault item not found");
        return row;
    }

    /**
     * Delete a vault item the user owns.
     *
     * `.delete({ id, user_id })` is an implicit authorisation check:
     *   if the row belongs to someone else, `affected` is 0. We return
     *   404 (not 403) on the miss branch to avoid leaking the existence
     *   of an ID that isn't theirs.
     */
    async remove({ userId, id }: DeleteArgs): Promise<void> {
        const result = await this.vaultRepository.delete({ id, user_id: userId });
        if (!result.affected) throw new NotFoundError("Vault item not found");
    }
}
