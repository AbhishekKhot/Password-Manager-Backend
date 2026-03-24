import type { FastifyInstance } from "fastify";
import { AppDataSource } from "../index.js";
import { User } from "../entities/User.js";

export default async function authRoutes(fastify: FastifyInstance) {
    const userRepository = AppDataSource.getRepository(User);

    fastify.get("/auth/salt", async (request, reply) => {
        const { email } = request.query as { email: string }

        const user = await userRepository.findOneBy({ email });

        if (!user) {
            return reply.status(404).send({ error: "User not found" })
        }

        return { salt: user.kdf_salt }
    });

    fastify.post("/auth/register", async (request, reply) => {
        const { email, auth_hash, kdf_salt } = request.body as any;

        const existing = await userRepository.findOneBy({ email });

        if (existing) {
            return reply.status(400).send({ error: "Email already exists" });
        }

        const user = userRepository.create({ email, auth_hash, kdf_salt });

        await userRepository.save(user);

        return reply.status(201).send({ message: "Registraction successful" });
    });

    fastify.post("/auth/login", async (request, reply) => {
        const { email, auth_hash } = request.body as any;

        const user = await userRepository.findOneBy({ email });

        if (!user || user.auth_hash !== auth_hash) {
            return reply.status(401).send({ error: "Invalid credentials" });
        }

        const token = fastify.jwt.sign({ id: user.id, email: user.email }, { expiresIn: '1h' });

        return { token, message: "Login successful" }
    });
}