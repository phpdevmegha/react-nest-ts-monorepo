# React + NestJS TypeScript Monorepo 🚀

A full-stack monorepo setup using **React** for the frontend and **NestJS** for the backend, written in **TypeScript** and containerized with **Docker**.

---

## 🚀 Quick Start (Docker — one command)

Requires only **Docker** (with Compose) and **git**.

```bash
git clone <this-repo-url> react-nest-ts-monorepo
cd react-nest-ts-monorepo

# one-time: create your local env file from the committed example
cp apps/backend/.env.example apps/backend/.env

# start everything: postgres + api (auto-migrated & seeded) + web UI
docker compose up -d
```

Then open **http://localhost:5173** and log in with the seeded admin:

| Email | Password | Role |
|---|---|---|
| `admin@syncboard.dev` | `password123` | `ADMIN` |

What happens on `up`:

- `postgres` — PostgreSQL 15 on host port **5434**
- `db-setup` — one-shot service that applies migrations and seeds the first admin (both idempotent; safe on every `up`)
- `api` — NestJS backend (watch mode) on **3000**, talks to postgres inside the compose network
- `web` — Vite dev server on **5173**, `/api` requests proxied to the api container

Reset everything from scratch:

```bash
docker compose down -v   # also removes the database volume
docker compose up -d
```

Customize the seeded admin before the first `up` (see `apps/backend/.env.example`):
`SEED_ADMIN_EMAIL`, `SEED_ADMIN_PASSWORD`, `SEED_ADMIN_NAME`, `SEED_ADMIN_ROLE`.

---

## 🛠 Local Development (without Docker for backend)

```bash
cp apps/backend/.env.example apps/backend/.env   # one-time
npm install
docker compose up -d postgres   # or run your own PostgreSQL on 5432
npm run dev                     # backend (watch) + frontend (Vite)
```

To run migrations or create users manually:

```bash
npm run migration:run -w backend
npm run seed -w backend -- --email you@example.com --password yourpassword --name "You" --role ADMIN
```

See `docs/backend/DATABASE_SETUP.md` and `docs/frontend/AUTHENTICATION.md` for details.

---

## 📦 Tech Stack

### Frontend
- React
- TypeScript
- Vite
- Axios

### Backend
- NestJS
- TypeScript
- PostgreSQL
- TypeORM
- JWT Authentication

### DevOps
- Docker & Docker Compose
- npm Workspaces

---

## 📁 Project Structure

```text
react-nest-ts-monorepo/
├─ apps/
│  ├─ backend/
│  │  ├─ src/
│  │  ├─ test/
│  │  ├─ Dockerfile
│  │  ├─ .env
│  │  ├─ package.json
│  │  └─ nest-cli.json
│  │
│  └─ frontend/
│     ├─ src/
│     ├─ public/
│     ├─ package.json
│     └─ vite.config.ts
│
├─ docker-compose.yml
├─ package.json
└─ README.md
