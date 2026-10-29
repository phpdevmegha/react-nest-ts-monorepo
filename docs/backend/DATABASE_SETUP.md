---
layout: docs
title_meta: Backend Database Setup
description_meta: This document explains how to set up PostgreSQL with TypeORM in a NestJS monorepo
---
# 🗄 Database Setup (PostgreSQL + TypeORM + NestJS)

## 1. Install Dependencies
---
```md
Install TypeORM and PostgreSQL driver:
```bash
npm install --save @nestjs/typeorm typeorm pg
```

---

## 2. Create PostgreSQL DB

In terminal or pgAdmin:

```sql
CREATE DATABASE testdb;
```

---

## 3. Configure TypeORM in app.module.ts

Edit `app.module.ts`:

```ts
TypeOrmModule.forRoot({
  type: 'postgres',
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  autoLoadEntities: true,
  synchronize: false,
})
```

### 📌 Notes

- `autoLoadEntities: true` → automatically loads entities
- `synchronize: false` → recommended for production (prevents auto schema changes)

---

## 4. Configure .env File

Create `apps/backend/.env` (copy `apps/backend/.env.example`):

```env
DB_HOST=localhost
DB_PORT=5434
DB_USERNAME=megha
DB_PASSWORD=megha@123
DB_NAME=nestdb
```

- `5434` matches the host port published by `docker-compose.yml`.
- Use `5432` instead if you run PostgreSQL locally / natively.

---

## 5. Create Entities

Example: `src/users/entities/user.entity.ts`

```ts
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column()
  email: string;
}
```

---

## 6. Start PostgreSQL (Docker)

```bash
docker compose up -d postgres
docker compose ps          # expect: nest-postgres ... (healthy) 0.0.0.0:5434->5432/tcp
```

The compose service publishes Postgres on host port **5434** (5433 is usually
taken by other projects). Credentials/database come from `docker-compose.yml`:
`megha` / `megha@123` / `nestdb`.

To reset the database completely:

```bash
docker compose down -v
docker compose up -d postgres
npm run migration:run -w backend
```

---

## 7. Run Migrations

Schema changes are applied with TypeORM migrations (`synchronize: false`).
A fresh database only has the `migrations` table until you run:

```bash
npm run migration:run -w backend     # apply all pending migrations
npm run migration:revert -w backend  # roll back the last one
```

The scripts use `apps/backend/src/database/datasource/config.ts`, which reads the
same `DB_*` variables from `apps/backend/.env`.

---

## 8. Create the First User (seed)

There is no public registration endpoint, so the first user is created by the
seed script. It is **idempotent** — running it again updates the same email.

```bash
npm run seed -w backend -- \
  --email admin@syncboard.dev \
  --password password123 \
  --name Admin \
  --role ADMIN
```

| Flag | Default | Notes |
|---|---|---|
| `--email` | `admin@syncboard.dev` | Looked up case-insensitively |
| `--password` | `password123` | Min 6 chars, hashed with bcrypt (cost 8) |
| `--name` | `Admin` | Display name |
| `--role` | `ADMIN` | `ADMIN`, `MANAGER`, or `VENDOR` |

Every flag can also be provided through `SEED_ADMIN_EMAIL`,
`SEED_ADMIN_PASSWORD`, `SEED_ADMIN_NAME`, and `SEED_ADMIN_ROLE`.

Then log in through the frontend (`http://localhost:5173`) or directly:

```bash
curl -i -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@syncboard.dev","password":"password123"}'
```

---

## 9. Test Database Connection

Run NestJS app:

```bash
npm run dev:backend
```
---

# 🎉 DONE!
