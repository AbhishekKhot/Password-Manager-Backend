import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from "typeorm";

/**
 * `users` table.
 *
 * Use case:
 *   One row per account. Stores *only* what the server needs to prove identity
 *   at login time — never plaintext passwords, never derived encryption keys.
 *
 * Zero-knowledge contract:
 *   - `auth_hash` is `argon2id(SHA-256(encryptionKey))`. The client sends the
 *     SHA-256 hash; we hash it a second time with argon2 before storing.
 *     That means even a full DB dump does not yield a value that can be
 *     replayed against /auth/login — the attacker would have to brute-force
 *     argon2 first, then brute-force the user's master password through PBKDF2.
 *   - `kdf_salt` is a 16-byte random value generated in the browser at
 *     registration. It's public (returned by GET /auth/salt) because its job
 *     is to defeat rainbow tables, not to be secret.
 *   - `kdf_iterations` is stored per-user so we can raise the floor (e.g.
 *     600k → 1M) without forcing re-enrollment — old users keep their
 *     original iteration count until they rotate their password.
 */
@Entity("users")
export class User {
    // UUIDs (not auto-increment integers) so user IDs are not enumerable and
    // don't leak "how many users we have" through ID values in logs/tokens.
    @PrimaryGeneratedColumn("uuid")
    id!: string;

    @Column({ type: "varchar", unique: true })
    email!: string;

    // Server-side argon2id hash of the client's auth_hash. Never reversed.
    @Column({ type: "varchar" })
    auth_hash!: string;

    // Hex-encoded 16-byte salt, per user. Required by the client on every login
    // to re-derive the same AES key from the master password.
    @Column({ type: "varchar" })
    kdf_salt!: string;

    // PBKDF2 iteration count the client used to derive this user's key.
    // Per-user so we can bump the default without invalidating old accounts.
    @Column({ type: "integer", default: 600000 })
    kdf_iterations!: number;

    @CreateDateColumn({ type: "timestamp" })
    created_at!: Date
}
