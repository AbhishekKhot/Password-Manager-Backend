import type { FastifyInstance } from "fastify";
import { AppDataSource } from "../index.js";
import { User } from "../entities/User.js";
import { RefreshToken } from "../entities/RefreshToken.js";
import { AuthService } from "../services/auth.service.js";
import { createTokenService } from "../services/token.service.js";
import { createAuthController } from "../controllers/auth.controller.js";

/**
 * Auth routes — URL-to-controller wiring.
 *
 * ── Layering (top → bottom of the call stack) ─────────────────────────────
 *   routes/      — Fastify URL wiring + auth-plugin registration (this file).
 *   controllers/ — HTTP adapter: parses input, calls service, shapes reply.
 *   services/    — business logic, zero HTTP knowledge.
 *   entities/    — ORM mapping.
 *
 * ── Design pattern: Composition Root ──────────────────────────────────────
 * This function is where services and controllers are *constructed and
 * wired together*, once, at process start. Elsewhere, the controller is
 * handed to the route by reference. Keeping construction here (rather
 * than using a DI container) is the simplest working option for a small
 * codebase — see Mark Seemann's "Composition Root" concept.
 *
 * Note on the purge sweep at the bottom:
 *   We run `tokens.purgeExpired()` at plugin boot to trim old refresh
 *   rows. `.catch(() => undefined)` keeps a transient DB hiccup from
 *   blocking server startup.
 */
export default async function authRoutes(fastify: FastifyInstance) {
    // Build the composition graph: repos → services → controller.
    const userRepository = AppDataSource.getRepository(User);
    const refreshRepository = AppDataSource.getRepository(RefreshToken);

    const tokens = createTokenService(fastify, refreshRepository);
    const service = new AuthService(userRepository, tokens);
    const controller = createAuthController(service);

    // Thin route wiring — no logic here beyond URL → handler.
    fastify.get("/auth/salt", controller.salt);
    fastify.post("/auth/register", controller.register);
    fastify.post("/auth/login", controller.login);
    fastify.post("/auth/refresh", controller.refresh);
    fastify.post("/auth/logout", controller.logout);

    // Opportunistic cleanup of expired refresh tokens on plugin boot.
    await tokens.purgeExpired();
}
