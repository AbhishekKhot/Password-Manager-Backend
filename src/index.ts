// `reflect-metadata` must be imported before any file that uses TypeORM decorators.
// TypeORM's decorators (@Entity, @Column, …) call Reflect.metadata() at class-
// definition time; without this side-effect import the metadata shim is undefined
// and entities silently fail to register.
import "reflect-metadata";
import Fastify, { type FastifyError, type FastifyRequest, type FastifyReply } from "fastify";
import fastifyJwt from "@fastify/jwt";
import cookie from "@fastify/cookie";
import helmet from "@fastify/helmet";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import { DataSource } from "typeorm";
import { config } from "./config.js";
import { User } from "./entities/User.js";
import { VaultItem } from "./entities/VaultItem.js";
import { RefreshToken } from "./entities/RefreshToken.js";
import authRoutes from "./routes/auth.js";
import vaultRoutes from "./routes/vault.js";
import { AppError, ValidationError } from "./errors/AppError.js";

/**
 * Fastify application instance.
 *
 * Use case:
 *   The HTTP entry point. Handles every inbound request: auth endpoints,
 *   vault CRUD, health probes.
 *
 * Why these options:
 *   - `bodyLimit: 256 KiB` — vault items are capped at 64 KiB of ciphertext;
 *     256 KiB leaves headroom for request wrappers but still rejects
 *     payload-bomb attacks early.
 *   - `connectionTimeout` / `requestTimeout` — slow-loris protection. A client
 *     that opens a connection but never finishes a request will be dropped.
 *   - `pino-pretty` transport only in dev — in prod we emit raw JSON logs so
 *     log aggregators (Datadog, CloudWatch) can parse them.
 */
const fastify = Fastify({
    logger: {
        level: config.LOG_LEVEL,
        ...(config.NODE_ENV === "development"
            ? { transport: { target: "pino-pretty", options: { singleLine: true } } }
            : {}),
    },
    bodyLimit: 256 * 1024,
    connectionTimeout: config.REQUEST_TIMEOUT_MS,
    requestTimeout: config.REQUEST_TIMEOUT_MS,
    disableRequestLogging: false,
});

/**
 * Global error handler — single place that maps thrown errors to HTTP.
 *
 * ── Design pattern: Centralised Error Translation ─────────────────────────
 * Controllers and services throw typed errors (see `errors/AppError.ts`).
 * This handler is the *one place* that decides the HTTP status code and
 * response shape. Benefits:
 *   - Consistency: every 4xx across the API looks the same on the wire.
 *   - Auditability: "what leaks to the client?" has one answer.
 *   - Services stay transport-agnostic — they know nothing of HTTP.
 *
 * Mapping order matters:
 *   1. `AppError` subclasses carry their own status + `expose` flag and
 *      optionally a `details` payload (for validation errors).
 *   2. Anything else with a `statusCode` is probably a Fastify error
 *      (e.g. body-limit, rate-limit, JSON parse) — honour it.
 *   3. Unknown throws are 500. We hide the message to avoid leaking
 *      framework / driver internals.
 */
fastify.setErrorHandler((error: FastifyError, request: FastifyRequest, reply: FastifyReply) => {
    request.log.error({ err: error, url: request.url }, "request failed");

    // Unwrap to plain `Error` — Fastify's FastifyError intersection strips
    // our subclass fields during narrowing, so we assign to a local first.
    const err: Error = error;

    if (err instanceof ValidationError) {
        const payload: { error: string; details?: unknown } = { error: err.message };
        if (err.details !== undefined) payload.details = err.details;
        return reply.status(err.statusCode).send(payload);
    }

    if (err instanceof AppError) {
        return reply.status(err.statusCode).send({ error: err.message });
    }

    const status = error.statusCode ?? 500;
    return reply.status(status).send({
        error: status >= 500 ? "Internal Server Error" : error.message,
    });
});

// Helmet sets security-relevant HTTP headers (X-Frame-Options, X-Content-Type-Options, HSTS, …).
// We disable CSP because this service is a pure JSON API — it never serves HTML,
// so a CSP header would be meaningless and would only confuse browsers that
// receive error pages.
await fastify.register(helmet, {
    contentSecurityPolicy: false,
});

// CORS is deliberately *strict*: only the configured FRONTEND_ORIGIN can call
// this API, and we enable credentials: true so the browser is permitted to
// send our httpOnly auth cookies on cross-origin requests.
await fastify.register(cors, {
    origin: config.FRONTEND_ORIGIN,
    credentials: true,
});

// Parses incoming Cookie headers and lets us call `reply.setCookie(...)`.
await fastify.register(cookie);

// Global rate-limit default: 100 requests / minute / IP. Auth endpoints
// register a stricter 5/min limit inside a scoped block below. `global: false`
// means the 100 default is only applied when a route doesn't opt into its own.
await fastify.register(rateLimit, {
    global: false,
    max: 100,
    timeWindow: "1 minute",
});

/**
 * TypeORM DataSource.
 *
 * `synchronize: false` is critical — TypeORM's autosync can drop or alter
 * columns it doesn't recognise. We use hand-rolled SQL migrations
 * (see migrate.ts + migrations/*.sql) so schema changes are explicit,
 * code-reviewable, and reversible.
 *
 * `extra.max` caps the PG connection pool. Exceeding Postgres's max_connections
 * under load causes "too many clients already" — pool size × replicas must
 * stay below the DB's limit.
 */
export const AppDataSource = new DataSource({
    type: "postgres",
    url: config.DATABASE_URL,
    synchronize: false,
    logging: config.NODE_ENV === "development" ? true : ["error", "warn"],
    entities: [User, VaultItem, RefreshToken],
    extra: {
        max: config.DB_POOL_MAX,
    },
});

// JWT verification reads the `access_token` cookie instead of the Authorization
// header. Cookies are httpOnly, so JavaScript on the page (including any XSS)
// cannot read the token — it's only sent by the browser on same-site requests.
// `signed: false` means we rely on the JWT's own HMAC signature for tamper
// detection rather than @fastify/cookie's signing layer.
await fastify.register(fastifyJwt, {
    secret: config.JWT_SECRET,
    cookie: {
        cookieName: "access_token",
        signed: false,
    },
});

/**
 * `authenticate` preHandler.
 *
 * Use case:
 *   Attached to routes via `{ onRequest: [fastify.authenticate] }`. Runs
 *   JWT verification and populates `request.user`.
 *
 * Why the try/catch:
 *   `jwtVerify` throws on a missing/expired/invalid token. We surface the
 *   underlying 401 response via `reply.send(err)` so the client (and the
 *   apiFetch wrapper) can trigger a single-flight refresh.
 */
fastify.decorate("authenticate", async function (request, reply) {
    try {
        await request.jwtVerify();
    } catch (err) {
        reply.send(err);
    }
});

// Legacy liveness endpoint kept for backwards compatibility.
fastify.get("/ping", async () => ({ status: "ok" }));

/**
 * Liveness probe.
 * Must be cheap and must NOT touch the DB — a container that returns 200 here
 * means "the process is alive"; orchestrators use it to decide whether to
 * restart the pod.
 */
fastify.get("/healthz", async () => ({ status: "ok" }));

/**
 * Readiness probe.
 * Does a trivial `SELECT 1` against Postgres. Returns 503 if the DB is
 * unreachable, which tells the load balancer to stop routing traffic to
 * this instance until the connection recovers.
 */
fastify.get("/readyz", async (_request, reply) => {
    try {
        await AppDataSource.query("SELECT 1");
        return { status: "ready" };
    } catch {
        return reply.status(503).send({ status: "not ready" });
    }
});

// Production-only: the service must sit behind a TLS-terminating proxy
// (nginx, ALB, Cloudflare). That proxy sets `X-Forwarded-Proto: https` on
// forwarded requests. If the header exists and is not "https", the client
// connected over plaintext HTTP somewhere upstream — we reject the request
// so auth cookies are never sent over an insecure hop.
if (config.NODE_ENV === "production") {
    fastify.addHook("onRequest", async (request, reply) => {
        const proto = request.headers["x-forwarded-proto"];
        if (proto && proto !== "https") {
            reply.status(400).send({ error: "HTTPS required" });
        }
    });
}

// Scoped registration: auth routes (register/login/refresh/logout) share a
// stricter 5-requests-per-minute rate limit. Fastify plugin scoping lets us
// apply rate-limit to a subset of routes without affecting /vault.
// Concept: brute-force defence — even if an attacker knows a user's email,
// 5 attempts/min/IP makes credential-stuffing impractical.
await fastify.register(async (scope) => {
    await scope.register(rateLimit, {
        max: 5,
        timeWindow: "1 minute",
        keyGenerator: (req) => req.ip,
    });
    await scope.register(authRoutes);
});

await fastify.register(vaultRoutes);

/**
 * Boot sequence.
 *
 * Order matters:
 *   1. Connect to Postgres first. If the DB is down the process should not
 *      begin accepting HTTP traffic — readiness would fail immediately.
 *   2. Only then call `fastify.listen` so requests never hit a half-initialised
 *      server.
 *
 * Any failure during boot → exit code 1 so the orchestrator restarts us
 * (and backs off on repeated failure rather than looping hot).
 */
const start = async () => {
    try {
        await AppDataSource.initialize();
        console.log("Database connection established");
        await fastify.listen({ port: config.PORT, host: "0.0.0.0" });
        console.log(`Server listening at http://localhost:${config.PORT}`);
    } catch (error) {
        fastify.log.error(error);
        process.exit(1);
    }
};

start();
