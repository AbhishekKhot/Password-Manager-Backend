import argon2 from "argon2";
import type { Repository } from "typeorm";
import { User } from "../entities/User.js";
import { config } from "../config.js";
import {
    ConflictError,
    NotFoundError,
    UnauthorizedError,
} from "../errors/AppError.js";
import type { IssuedTokens, TokenService } from "./token.service.js";

/**
 * Authentication service — register, login, refresh, logout.
 *
 * ── Design pattern: Service Layer ─────────────────────────────────────────
 * Pure business logic around user accounts and sessions. Returns plain
 * objects and throws typed domain errors (`errors/AppError.ts`). No
 * FastifyRequest, no reply, no cookies — the controller owns all of that.
 *
 * ── Design pattern: Facade ────────────────────────────────────────────────
 * The service hides the argon2 / PBKDF2 / JWT plumbing behind a handful of
 * verbs (`register`, `login`, `refresh`, `logout`). The caller doesn't
 * need to know argon2id exists.
 *
 * ── Design pattern: Dependency Injection ──────────────────────────────────
 * Repository and TokenService are injected via constructor for testability.
 *
 * Zero-knowledge reminder (see [CLAUDE.md](../../../CLAUDE.md)):
 *   The master password and the derived AES key never reach this server.
 *   We store argon2id(sha256(encryptionKey)) — two layers deep from the
 *   original password. A DB leak does not expose a replayable credential.
 */

/**
 * Pre-computed dummy argon2id hash used for timing-attack mitigation on
 * login (see `login()` below). It's a syntactically valid encoding so
 * `argon2.verify` runs the full KDF; it just happens never to match
 * anything real.
 */
const DUMMY_ARGON2_HASH =
    "$argon2id$v=19$m=65536,t=3,p=4$ZHVtbXlzYWx0ZHVtbXk$NpaP5K0jXNlmr5Bq2jyQWL2mT1KBxQsWqfNz0WjNt8E";

export interface SaltResponse {
    salt: string;
    iterations: number;
}

export interface LoginResult extends IssuedTokens {
    user: { id: string; email: string };
}

export class AuthService {
    constructor(
        private readonly userRepository: Repository<User>,
        private readonly tokens: TokenService,
    ) { }

    /**
     * Return the stored salt + iteration count for a given email.
     *
     * Use case:
     *   The client needs both values to re-run PBKDF2 and arrive at the
     *   same AES key that was derived at registration. Called by /login
     *   and /unlock flows.
     *
     * Known enumeration trade-off:
     *   A 404 here tells an attacker "this email is not registered". We
     *   accept that because: (a) the salt has to be stable per user —
     *   returning a random one per call would break real logins; and
     *   (b) /auth/* is rate-limited to 5/min/IP.
     */
    async getSalt(email: string): Promise<SaltResponse> {
        const user = await this.userRepository.findOneBy({ email });
        if (!user) throw new NotFoundError("User not found");
        return { salt: user.kdf_salt, iterations: user.kdf_iterations };
    }

    /**
     * Create a new user account.
     *
     * Inputs:
     *   - `email`            — normalised (lowercased) by the zod schema.
     *   - `authHash`         — client's SHA-256(encryptionKey), 32 hex bytes.
     *   - `kdfSalt`          — client-generated 16-byte CSPRNG salt.
     *
     * Why argon2id on top of a SHA-256 hash:
     *   argon2id is memory-hard, so brute-forcing it requires both CPU
     *   and RAM — unlike plain SHA-256 which is GPU-friendly. We cannot
     *   pick our own PBKDF2 parameters here because PBKDF2 happened on
     *   the client; argon2id is our server-side defence against DB leaks.
     */
    async register(input: {
        email: string;
        authHash: string;
        kdfSalt: string;
    }): Promise<void> {
        const existing = await this.userRepository.findOneBy({ email: input.email });
        if (existing) throw new ConflictError("Email already exists");

        const hashed = await argon2.hash(input.authHash, { type: argon2.argon2id });

        const user = this.userRepository.create({
            email: input.email,
            auth_hash: hashed,
            kdf_salt: input.kdfSalt,
            kdf_iterations: config.PBKDF2_ITERATIONS,
        });
        await this.userRepository.save(user);
    }

    /**
     * Verify credentials and issue a fresh token pair.
     *
     * Timing-attack defence:
     *   If the user doesn't exist we'd normally skip argon2.verify and
     *   return 401 much faster than for a real user — leaking
     *   "this email is registered" via response-time side channel.
     *   We run `argon2.verify` against `DUMMY_ARGON2_HASH` on the miss
     *   branch to equalise latency. The comma operator discards the
     *   return value and forces `valid` to `false`.
     */
    async login(input: { email: string; authHash: string }): Promise<LoginResult> {
        const user = await this.userRepository.findOneBy({ email: input.email });

        const valid = user
            ? await argon2.verify(user.auth_hash, input.authHash)
            : (await argon2.verify(DUMMY_ARGON2_HASH, input.authHash).catch(() => false), false);

        if (!user || !valid) throw new UnauthorizedError("Invalid credentials");

        const issued = await this.tokens.issue(user.id, user.email);
        return { ...issued, user: { id: user.id, email: user.email } };
    }

    /**
     * Rotate a valid refresh token into a brand-new (access, refresh) pair.
     *
     * The token service verifies + revokes the presented token. We then
     * look up the user and issue a new pair. Note that we re-fetch the
     * user here (not cached in the refresh row) so that a deleted user
     * cannot keep refreshing tokens from an old valid refresh record.
     */
    async refresh(rawRefreshToken: string): Promise<IssuedTokens> {
        const { userId } = await this.tokens.rotate(rawRefreshToken);

        const user = await this.userRepository.findOneBy({ id: userId });
        if (!user) throw new UnauthorizedError("User no longer exists");

        return this.tokens.issue(user.id, user.email);
    }

    /**
     * Server-side revocation of the presented refresh token.
     *
     * Intentionally accepts an `undefined` token (cookie may be missing
     * if the browser state is partially cleared) and is a no-op in that
     * case — the caller clears cookies either way.
     */
    async logout(rawRefreshToken: string | undefined): Promise<void> {
        if (!rawRefreshToken) return;
        await this.tokens.revoke(rawRefreshToken);
    }
}
