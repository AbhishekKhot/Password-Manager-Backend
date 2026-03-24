import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from "typeorm";

@Entity("users")
export class User {
    @PrimaryGeneratedColumn("uuid")
    id!: string;

    @Column({ type: "varchar", unique: true })
    email!: string;

    @Column({ type: "varchar" })
    auth_hash!: string;

    @Column({ type: "varchar" })
    kdf_salt!: string;

    @CreateDateColumn({ type: "timestamp" })
    created_at!: Date
}