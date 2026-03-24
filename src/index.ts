import "reflect-metadata"
import Fastify from "fastify";
import fastifyJwt from "@fastify/jwt";
import cors from "@fastify/cors";
import { DataSource } from "typeorm";
import { User } from "./entities/User.js";
import { VaultItem } from "./entities/VaultItem.js"
import authRoutes from "./routes/auth.js";
import vaultRoutes from "./routes/vault.js";
import "dotenv/config"

const fastify = Fastify({ logger: true });

await fastify.register(cors, { origin: true });

export const AppDataSource = new DataSource({
    type: "postgres",
    url: process.env.DATABASE_URL!,
    synchronize: true, //Auto-creates tables (only for dev)
    logging: true,
    entities: [User, VaultItem]
});

fastify.get("/ping", async (request, reply) => {
    return { status: "ok", message: "Password Manager API is online!" };
});

fastify.register(fastifyJwt, {
    secret: process.env.JWT_SECRET!,
});

fastify.decorate("authenticate", async function (request, reply) {
    try {
        await request.jwtVerify();
    } catch (err) {
        reply.send(err);
    }
});

fastify.register(authRoutes);
fastify.register(vaultRoutes);

const start = async () => {
    try {
        await AppDataSource.initialize();
        console.log("Database connection established");
        await fastify.listen({ port: 3000, host: "0.0.0.0" });
        console.log("Server listening at http://localhost:3000")
    } catch (error) {
        fastify.log.error(error);
        process.exit(1);
    }
};

start();