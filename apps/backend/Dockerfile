FROM node:20-alpine

WORKDIR /app
ENV NODE_ENV=development

# 1. Copy workspace manifests only — lets Docker layer-cache dependencies
#    across source changes. The build context is the monorepo root, so the
#    lockfile and workspace packages are available.
COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY apps/backend/package.json apps/backend/

# 2. Workspace-aware install: npm links @syncboard/shared from packages/shared
#    instead of requesting it from the public registry (where it 404s).
RUN npm ci --workspace backend --workspace @syncboard/shared

# 3. Copy sources for both workspaces the backend needs.
COPY packages/shared packages/shared
COPY apps/backend apps/backend

# 4. Production-style build (also validates the image compiles).
RUN npm run build -w backend

CMD ["npm", "run", "start:dev", "-w", "backend"]
