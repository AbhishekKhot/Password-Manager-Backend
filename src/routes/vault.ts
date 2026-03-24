import type { FastifyInstance } from "fastify";
import { AppDataSource } from "../index.js";
import { VaultItem } from "../entities/VaultItem.js";

export default async function vaultRoutes(fastify: FastifyInstance) {
    const vaultRepository = AppDataSource.getRepository(VaultItem);

    // Get all vault items for the authenticated user
    fastify.get("/vault", { onRequest: [fastify.authenticate] }, async (request, reply) => {
        const user_id = request.user.id;
        const items = await vaultRepository.find({ where: { user_id } });
        return items;
    });

    // Create a new vault item
    fastify.post("/vault", { onRequest: [fastify.authenticate] }, async (request, reply) => {
        const user_id = request.user.id;
        const { iv, encrypted_data } = request.body as any;

        if (!iv || !encrypted_data) {
            return reply.status(400).send({ error: "Missing iv or encrypted_data" });
        }

        const item = vaultRepository.create({ user_id, iv, encrypted_data });
        await vaultRepository.save(item);

        return reply.status(201).send(item);
    });

    // Update an existing vault item
    fastify.put("/vault/:id", { onRequest: [fastify.authenticate] }, async (request, reply) => {
        const user_id = request.user.id;
        const { id } = request.params as { id: string };
        const { iv, encrypted_data } = request.body as any;

        const item = await vaultRepository.findOne({ where: { id, user_id } });

        if (!item) {
            return reply.status(404).send({ error: "Vault item not found" });
        }

        if (iv) item.iv = iv;
        if (encrypted_data) item.encrypted_data = encrypted_data;

        await vaultRepository.save(item);
        return item;
    });

    // Delete a vault item
    fastify.delete("/vault/:id", { onRequest: [fastify.authenticate] }, async (request, reply) => {
        const user_id = request.user.id;
        const { id } = request.params as { id: string };

        const item = await vaultRepository.findOne({ where: { id, user_id } });

        if (!item) {
            return reply.status(404).send({ error: "Vault item not found" });
        }

        await vaultRepository.remove(item);
        return { message: "Vault item deleted" };
    });
}
