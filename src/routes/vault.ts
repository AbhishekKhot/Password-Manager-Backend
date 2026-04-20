import type { FastifyInstance } from "fastify";
import { AppDataSource } from "../index.js";
import { VaultItem } from "../entities/VaultItem.js";
import { VaultService } from "../services/vault.service.js";
import { createVaultController } from "../controllers/vault.controller.js";

/**
 * Vault routes — URL-to-controller wiring, JWT-gated.
 *
 * Layering: routes → controllers → services → entities.
 *
 * Design pattern: Composition Root.
 *   Services/controllers are constructed here once at plugin boot and
 *   passed to Fastify by reference. No globals, no DI container — just
 *   explicit wiring suitable for a small, focused codebase.
 *
 * Auth gating:
 *   Every route runs `fastify.authenticate` as an `onRequest` hook. That
 *   decorator is defined in [index.ts](../index.ts) and verifies the JWT
 *   access-token cookie, populating `request.user`. A failure there
 *   short-circuits to 401 before the controller runs.
 */
export default async function vaultRoutes(fastify: FastifyInstance) {
    const vaultRepository = AppDataSource.getRepository(VaultItem);
    const service = new VaultService(vaultRepository);
    const controller = createVaultController(service);

    const auth = { onRequest: [fastify.authenticate] };

    fastify.get("/vault", auth, controller.list);
    fastify.post("/vault", auth, controller.create);
    fastify.put("/vault/:id", auth, controller.update);
    fastify.delete("/vault/:id", auth, controller.remove);
}
