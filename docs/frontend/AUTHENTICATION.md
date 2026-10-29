# 🔐 Frontend Authentication

How login, the auth session, and protected routes work in the React app.

---

## 1. Flow

```text
LoginPage
   │  POST /api/auth/login { email, password }
   ▼
NestJS AuthController ──► AuthService ──► bcrypt.compare + JWT sign
   │
   │  200 { message, token, user }
   ▼
AuthProvider
   │  saves token + user in sessionStorage
   ▼
React Router
   │
   ├─ /            LoginPage (redirects to /dashboard if already signed in)
   ├─ /dashboard   ProtectedRoute → DashboardPage
   ├─ /products    ProtectedRoute → ProductsPage
   └─ *            redirect to /
```

Every API request made through `src/api/client.ts` automatically sends:

```http
Authorization: Bearer <token>
```

If the API answers `401`, the session is cleared and the user is sent back to `/`.

---

## 2. Backend contract

All routes are prefixed with `/api` (`app.setGlobalPrefix('api')` in `apps/backend/src/main.ts`).

### `POST /api/auth/login`

Request:

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

Response `200`:

```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "name": "Jane Doe",
    "email": "user@example.com",
    "role": "ADMIN"
  }
}
```

Errors:

| Status | Meaning |
|---|---|
| `400` | Validation failed (bad email, password shorter than 6 chars) |
| `401` | Invalid email or password |

The password hash is never returned. Roles are `ADMIN`, `MANAGER`, `VENDOR`.

---

## 3. Frontend structure

```text
apps/frontend/src/
├── api/
│   ├── client.ts          # axios instance, Bearer header, 401 handling
│   └── auth.ts            # loginRequest()
├── components/
│   ├── AppHeader.tsx      # top bar + logout
│   ├── AppHeader.module.css
│   └── ProtectedRoute.tsx # layout route guard
├── context/
│   ├── auth-context.ts    # createContext (kept separate for Fast Refresh)
│   ├── AuthContext.tsx    # AuthProvider (login/logout state)
│   └── useAuth.ts         # useAuth() hook
├── pages/
│   ├── LoginPage.tsx
│   ├── LoginPage.module.css
│   ├── DashboardPage.tsx
│   └── ProductsPage.tsx
├── styles/
│   └── page.module.css    # shared page layout
├── types/
│   └── auth.ts            # AuthUser, LoginResponse, AuthContextValue
└── utils/
    ├── api-error.ts       # extracts NestJS error messages
    └── auth-storage.ts    # sessionStorage read/write/expiry
```

### Session storage keys

| Key | Value |
|---|---|
| `syncboard.token` | JWT |
| `syncboard.user` | JSON `{ id, name, email, role }` |

`sessionStorage` is per-tab and disappears when the tab closes. The token is also
checked for `exp` before restoring a session, so an expired token does not show a
fake logged-in UI.

---

## 4. Configuration

`apps/frontend/.env.example`:

```env
VITE_API_URL=/api
```

- In development the default `/api` is proxied by Vite to `http://localhost:3000`.
- In production set `VITE_API_URL` to the deployed API URL.
- Do not commit `.env` / `.env.local`; only `.env.example` belongs in git.

Vite proxy (`apps/frontend/vite.config.ts`):

```ts
server: {
  proxy: {
    '/api': { target: 'http://localhost:3000', changeOrigin: true },
  },
}
```

---

## 5. Running

Start PostgreSQL on the Docker host port used by `apps/backend/.env` (`5434`):

```bash
docker compose up -d postgres
npm run migration:run -w backend   # first run only (or after new migrations)
npm run seed -w backend -- --email admin@syncboard.dev --password password123 --name Admin --role ADMIN
npm run dev:backend
```

Start the frontend:

```bash
npm run dev:frontend
# or both together
npm run dev
```

Open `http://localhost:5173/` and log in with the seeded account:

```text
admin@syncboard.dev / password123
```

The seed script is idempotent: re-running it with the same email updates that
user's password/name/role instead of creating a duplicate. Roles are `ADMIN`,
`MANAGER`, `VENDOR`. See `docs/backend/DATABASE_SETUP.md` for all options.

Quick API check:

```bash
curl -i -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@syncboard.dev","password":"password123"}'
```

---

## 6. Using auth in a new page

```tsx
import { useAuth } from '../context/useAuth'

export default function ExamplePage() {
  const { user, token, isAuthenticated, logout } = useAuth()
  // ...
}
```

To protect a new route, add it inside the `ProtectedRoute` layout in `App.tsx`:

```tsx
<Route element={<ProtectedRoute />}>
  <Route path="/dashboard" element={<DashboardPage />} />
  <Route path="/products" element={<ProductsPage />} />
  <Route path="/example" element={<ExamplePage />} />
</Route>
```

To call the API, always use the shared client so the Bearer token is attached:

```ts
import { api } from '../api/client'

const { data } = await api.get('/products')
```

---

## 7. Security notes (important)

This is a working development setup, not a production-hardened one.

1. **`sessionStorage` is readable by JavaScript.** Any XSS can steal the JWT.
   For production, prefer `httpOnly`, `Secure`, `SameSite` cookies plus CSRF
   protection, and short-lived access tokens with refresh tokens.
2. **The JWT secret is hardcoded** in `apps/backend/src/auth/constants.ts`.
   Move it to `JWT_SECRET` in `.env` before deploying anything real.
3. **Use HTTPS in production.** Tokens in plain HTTP can be intercepted.
4. **Do not log tokens** or include them in error reports.
5. **Logout is client-side only.** The JWT remains valid until `exp`; add a
   server-side revocation/refresh strategy if you need immediate invalidation.
6. **No password reset / registration flow exists yet.** Users are managed by
   the backend `UsersModule`.

---

## 8. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `404` on login | Wrong prefix. Use `/api/auth/login`, not `/auth/login` |
| `401 Invalid email or password` | User does not exist or wrong password |
| `Network Error` / `ERR_CONNECTION_REFUSED` | Backend is not running on port 3000 |
| `401` on every page after login | Token expired; sign in again |
| Login works but dashboard redirects back | `user` missing from login response — check backend `AuthService.login` |
| CORS error | Use the Vite proxy (`/api`) or enable CORS on the backend (`app.enableCors()`) |
