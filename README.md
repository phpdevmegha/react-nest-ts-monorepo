# React + NestJS TypeScript Monorepo 🚀

A full-stack monorepo setup using **React** for the frontend and **NestJS** for the backend, written in **TypeScript** and containerized with **Docker**.

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
