import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn, CreateDateColumn, Index } from "typeorm";
import { User } from "./User.js";

/**
 * `refresh_tokens` table.
 *
 * Use case:
 *   Powers the rotating-refresh-token auth model. A row per issued refresh
 *   token; the client holds the raw token in an httpOnly cookie and sends it
 *   back on `POST /auth/refresh`, which verifies + rotates it.
 *
 * Why refresh tokens exist at all:
 *   The access token (JWT) is short-lived (15 min). If a user's access token
 *   is stolen, the attacker has at most 15 minutes of use. A long-lived
 *   refresh token lets the user stay "logged in" for days without us having
 *   to make the access token long-lived too.
 *
 * Why we store a HASH, not the raw token:
 *   If the DB leaks, the attacker gets sha256(tokenSecret), not tokenSecret
 *   itself. SHA-256 is not reversible, so the leak cannot be replayed.
 *   We use plain SHA-256 (not argon2) because:
 *     1. The input is a 32-byte random value — already high-entropy — so
 *        slow hashing provides no additional brute-force protection.
 *     2. Refresh endpoints are hot-path; argon2 would add 100-500 ms per call.
 *
 * Rotation:
 *   Each use of a refresh token sets `revoked_at` on the old row and issues
 *   a brand-new token. If an attacker ever replays a revoked token we
 *   detect it (revoked_at != null) and can invalidate the whole session.
 */
@Entity("refresh_tokens")
export class RefreshToken {
    @PrimaryGeneratedColumn("uuid")
    id!: string;

    // Indexed because we may want to revoke all tokens for a user (e.g. on
    // "sign out everywhere") — that query filters by user_id.
    @Index()
    @Column({ type: "uuid" })
    user_id!: string;

    @ManyToOne(() => User, { onDelete: "CASCADE" })
    @JoinColumn({ name: "user_id" })
    user!: User;

    // SHA-256(tokenSecret). We never store the raw token.
    // Unique index: lets us look up a refresh token by hash in O(log n)
    // during /auth/refresh AND prevents duplicate hashes (collision defense).
    @Index({ unique: true })
    @Column({ type: "varchar", length: 64 })
    token_hash!: string;

    @Column({ type: "timestamp" })
    expires_at!: Date;

    // Null = still valid. Non-null = rotated or explicitly revoked on logout.
    @Column({ type: "timestamp", nullable: true })
    revoked_at!: Date | null;

    @CreateDateColumn()
    created_at!: Date;
}
