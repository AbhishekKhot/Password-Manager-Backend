import type { FastifyReply, FastifyRequest } from "fastify";
import { config } from "../config.js";
import { ValidationError } from "../errors/AppError.js";
import type { AuthService } from "../services/auth.service.js";
import type { IssuedTokens } from "../services/token.service.js";
import { loginBody, registerBody, saltQuery } from "../schemas/auth.js";

/**
 * Auth controller — HTTP adapter over AuthService.
 *
 * ── Design pattern: Controller (MVC) / Adapter ────────────────────────────
 * The controller's only responsibilities:
 *   1. Parse and validate input (zod schemas from schemas/auth.ts).
 *   2. Call the right service method.
 *   3. Translate the result (or a domain error) into an HTTP response.
 *
 * It owns cookies, status codes, and the shape of JSON responses. It does
 * NOT contain business logic — "is this email taken?", "what's the KDF
 * iteration count?", "how do we hash credentials?" are all service
 * concerns and live in AuthService.
 *
 * ── Anti-pattern being avoided: Fat Controller ────────────────────────────
 * The pre-refactor `routes/auth.ts` bundled HTTP concerns, argon2 hashing,
 * token rotation and DB access in one file — a classic "fat controller"
 * (also known as "transaction script in the route handler"). Splitting
 * business logic into AuthService gives us testability and a single
 * source of truth for security-critical operations.
 */

const isProd = config.NODE_ENV === "production";

/**
 * Writes both auth cookies after login or refresh.
 *
 * Why these flags (defence-in-depth checklist):
 *   - `httpOnly`          — JS on the page (including XSS) cannot read the token.
 *   - `secure: isProd`    — dev is HTTP; prod requires HTTPS transport.
 *   - `sameSite: "strict"` — browser refuses cross-site sending → CSRF becomes moot.
 *   - refresh cookie `path: "/auth"` — never sent to /vault, so even a
 *     compromised vault handler can't exfiltrate it.
 *   - `maxAge` matched to token lifetime so the browser prunes at roughly
 *     the same time the server stops honouring.
 */
function setAuthCookies(reply: FastifyReply, tokens: IssuedTokens): void {
    reply.setCookie("access_token", tokens.accessToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: "strict",
        path: "/",
        maxAge: 15 * 60,
    });
    const refreshMaxAge = Math.floor((tokens.refreshExpiresAt.getTime() - Date.now()) / 1000);
    reply.setCookie("refresh_token", tokens.refreshToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: "strict",
        path: "/auth",
        maxAge: refreshMaxAge,
    });
}

/**
 * Clears both cookies. Must use the *same path* they were set under, or
 * the browser treats it as a no-op and the cookies linger.
 */
function clearAuthCookies(reply: FastifyReply): void {
    reply.clearCookie("access_token", { path: "/" });
    reply.clearCookie("refresh_token", { path: "/auth" });
}

/**
 * AuthController — factory returning route handlers.
 *
 * Factory pattern (vs class with methods):
 *   We could have exposed a class with bound methods, but Fastify handlers
 *   are plain functions — a factory avoids `this`-binding footguns when
 *   the handler is passed by reference to `fastify.get(...)`.
 */
export function createAuthController(service: AuthService) {
    return {
        /** GET /auth/salt?email=... */
        async salt(request: FastifyRequest, reply: FastifyReply) {
            const parsed = saltQuery.safeParse(request.query);
            if (!parsed.success) throw new ValidationError("Invalid email");

            const result = await service.getSalt(parsed.data.email);
            return reply.send(result);
        },

        /** POST /auth/register */
        async register(request: FastifyRequest, reply: FastifyReply) {
            const parsed = registerBody.safeParse(request.body);
            if (!parsed.success) throw new ValidationError("Invalid input", parsed.error.issues);

            await service.register({
                email: parsed.data.email,
                authHash: parsed.data.auth_hash,
                kdfSalt: parsed.data.kdf_salt,
            });
            return reply.status(201).send({ message: "Registration successful" });
        },

        /** POST /auth/login */
        async login(request: FastifyRequest, reply: FastifyReply) {
            const parsed = loginBody.safeParse(request.body);
            if (!parsed.success) throw new ValidationError("Invalid input");

            const result = await service.login({
                email: parsed.data.email,
                authHash: parsed.data.auth_hash,
            });
            setAuthCookies(reply, result);
            return reply.send({ message: "Login successful" });
        },

        /** POST /auth/refresh */
        async refresh(request: FastifyRequest, reply: FastifyReply) {
            const raw = request.cookies.refresh_token;
            if (!raw) {
                // Not a ValidationError — the missing cookie is the error
                // shape the client expects (401, not 400).
                clearAuthCookies(reply);
                return reply.status(401).send({ error: "Missing refresh token" });
            }

            try {
                const issued = await service.refresh(raw);
                setAuthCookies(reply, issued);
                return reply.send({ message: "Refreshed" });
            } catch (err) {
                // Any failure in rotation → cookies must be cleared so the
                // browser stops retrying with a now-burned token.
                clearAuthCookies(reply);
                throw err;
            }
        },

        /** POST /auth/logout */
        async logout(request: FastifyRequest, reply: FastifyReply) {
            await service.logout(request.cookies.refresh_token);
            clearAuthCookies(reply);
            return reply.send({ message: "Logged out" });
        },
    };
}

export type AuthController = ReturnType<typeof createAuthController>;
