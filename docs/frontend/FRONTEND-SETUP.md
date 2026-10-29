---
layout: docs
title_meta: Frontend Setup (React)
description_meta: Create and start the React frontend inside the NestJS monorepo
---

# 📦 Frontend Setup (React)
---

## 🧱 1. Create Frontend Application

Navigate to the `apps` directory:

```bash
cd apps

```
Create React application using Vite:

```bash
npm create vite@latest frontend -- --template react-ts
```
---

## 📦 2. Install Dependencies
```bash
cd frontend
npm install
npm install react-router-dom axios
npm install -D @types/react-router-dom vitest @testing-library/react @testing-library/user-event jsdom
```
---

## ▶ 3. Start Development Server
```bash
npm run dev
```
---
## 🗂 4. Basic frontend structure
```plaintext
apps/frontend/
├── public/
├── src/
│   ├── assets/
│   ├── App.tsx
│   ├── main.tsx
│   └── index.css
├── index.html
├── package.json
├── tsconfig.json
└── vite.config.ts

```
---
# 🧱 5. Create basic project structure
``` bash    
cd src/
mkdir api components hooks pages types utils

```
Final structure:
```plaintext
apps/frontend/src/
├── api/          # API and axios setup
├── components/   # Reusable UI components
├── context/      # React context (auth)
├── hooks/        # Custom React hooks
├── pages/        # Application pages
├── styles/       # Shared CSS modules
├── types/        # TypeScript types
├── utils/        # Helper utilities
├── App.tsx
└── main.tsx

```
---
# 🎉 Frontend Setup Complete!

## 🔐 Authentication

The login flow, session handling, protected routes, and backend contract are
documented in [AUTHENTICATION.md](./AUTHENTICATION.md).