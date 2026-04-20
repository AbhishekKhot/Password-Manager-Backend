import type { FastifyReply, FastifyRequest } from "fastify";
import { ValidationError } from "../errors/AppError.js";
import type { VaultService } from "../services/vault.service.js";
import { createBody, idParam, listQuery, updateBody } from "../schemas/vault.js";

/**
 * Vault controller — HTTP adapter over VaultService.
 *
 * ── Design pattern: Controller (MVC) ──────────────────────────────────────
 * Parses request inputs (body / params / query) via zod, extracts
 * `request.user.id` from the JWT, and calls the service. Responses are
 * plain JSON — no cookies, no special headers.
 *
 * Why a factory (not a class):
 *   Fastify handlers are plain functions. A factory avoids `this`-binding
 *   surprises when we pass the handler by reference to `fastify.get(...)`.
 */
export function createVaultController(service: VaultService) {
    return {
        /** GET /vault — list authenticated user's items. */
        async list(request: FastifyRequest, reply: FastifyReply) {
            const parsed = listQuery.safeParse(request.query);
            if (!parsed.success) throw new ValidationError("Invalid query");

            const result = await service.list({
                userId: request.user.id,
                limit: parsed.data.limit,
                ...(parsed.data.after !== undefined ? { after: parsed.data.after } : {}),
            });
            return reply.send(result);
        },

        /** POST /vault — create a new encrypted item. */
        async create(request: FastifyRequest, reply: FastifyReply) {
            const parsed = createBody.safeParse(request.body);
            if (!parsed.success) throw new ValidationError("Invalid input", parsed.error.issues);

            const item = await service.create({
                userId: request.user.id,
                iv: parsed.data.iv,
                encrypted_data: parsed.data.encrypted_data,
            });
            return reply.status(201).send(item);
        },

        /** PUT /vault/:id — partial update of iv and/or encrypted_data. */
        async update(request: FastifyRequest, reply: FastifyReply) {
            const paramParsed = idParam.safeParse(request.params);
            if (!paramParsed.success) throw new ValidationError("Invalid id");

            const bodyParsed = updateBody.safeParse(request.body);
            if (!bodyParsed.success) throw new ValidationError("Invalid input", bodyParsed.error.issues);

            // `exactOptionalPropertyTypes`: build args omitting unset keys
            // rather than explicitly setting them to `undefined`.
            const args: Parameters<VaultService["update"]>[0] = {
                userId: request.user.id,
                id: paramParsed.data.id,
            };
            if (bodyParsed.data.iv !== undefined) args.iv = bodyParsed.data.iv;
            if (bodyParsed.data.encrypted_data !== undefined) {
                args.encrypted_data = bodyParsed.data.encrypted_data;
            }

            const item = await service.update(args);
            return reply.send(item);
        },

        /** DELETE /vault/:id — remove an item the user owns. */
        async remove(request: FastifyRequest, reply: FastifyReply) {
            const parsed = idParam.safeParse(request.params);
            if (!parsed.success) throw new ValidationError("Invalid id");

            await service.remove({ userId: request.user.id, id: parsed.data.id });
            return reply.send({ message: "Vault item deleted" });
        },
    };
}

export type VaultController = ReturnType<typeof createVaultController>;
