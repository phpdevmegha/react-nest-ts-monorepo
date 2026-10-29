# 📊 Dashboard & Products Pages

How the two data-driven pages work, the API layer behind them, and the backend
contract they rely on.

---

## 1. Structure

```text
apps/frontend/src/
├── api/
│   ├── client.ts          # axios instance: Bearer header + /api proxy + 401 handling
│   ├── products.ts        # listProducts(), createProduct(), updateProduct(), deleteProduct()
│   ├── orders.ts          # listOrders()
├── components/
│   ├── Modal.tsx / .module.css        # a11y dialog primitive (portal, ESC/backdrop)
│   ├── ConfirmDialog.tsx              # confirmation popup (used by Delete)
│   ├── ProductForm.tsx / .module.css  # ONE form for create AND edit (mode prop)
│   └── form/
│       ├── InputField.tsx             # label + input/textarea + inline error/hint
│       └── Button.tsx                 # variant primary/secondary/danger, busy state
├── pages/
│   ├── DashboardPage.tsx      # stats + recent orders
│   ├── DashboardPage.module.css
│   ├── ProductsPage.tsx       # catalog table + create/edit modal + delete confirm (ADMIN)
│   └── ProductsPage.module.css
├── types/
│   ├── api.ts            # ApiResponse, PaginatedResponse, Product, Order
│   └── auth.ts           # re-uses UserRole from types/api
└── utils/
    ├── api-error.ts           # NestJS error messages → text
    ├── format.ts               # ₹ / date / status formatting
    └── product-validation.ts   # field validators mirroring the backend DTO rules
```

Both pages are protected: they render inside the `<ProtectedRoute />` layout in
`App.tsx` and always show `AppHeader`.

---

## 2. Backend contract (summary)

Every list endpoint wraps payloads:

```json
{ "success": true, "message": "…", "data": [ … ], "pagination": { … } }
```

`listProducts()` / `listOrders()` unwrap `data` for the pages and treat a
missing/null `data` as an empty array, so an empty catalog never crashes the UI.

| Endpoint | Method | Roles | Notes |
|---|---|---|---|
| `/api/products` | `GET` | any authenticated | paginated envelope; `[]` when empty |
| `/api/products` | `POST` | `ADMIN` | full validation (see table below); `userId` optional → JWT `sub` |
| `/api/products/:id` | `GET` | any authenticated | |
| `/api/products/:id` | `PATCH` | `ADMIN` | partial update; same field rules as create — used by the **Edit** dialog |
| `/api/products/:id` | `DELETE` | `ADMIN` | UI always asks for confirmation first (`ConfirmDialog`) |
| `/api/orders` | `GET` | any authenticated | newest first when paginated |
| `/api/orders` | `POST` | any authenticated | requires `userId`, `productIds[]`, `status` |
| `/api/orders/:id/status` | `POST` | any authenticated | changes order status |

### Product fields & validation (create and edit)

| Field | Required (create) | Rules | Frontend form |
|---|---|---|---|
| `title` | yes | 3–255 chars, trimmed | text input |
| `price` | yes | positive, ≤ 2 decimals | **text input** (`inputMode="decimal"`) validated by regex |
| `description` | no | ≤ 1000 chars | textarea |
| `category` | no | ≤ 100 chars | text input |
| `stock` | no | integer 0–1,000,000 | text input (`inputMode="numeric"`) |

- Frontend rules live in `utils/product-validation.ts` and mirror
  `apps/backend/src/products/dto/create-product.dto.ts` — update both together.
- Failed validation returns `400` with `message: string[]`; the form shows them
  inline (or as a list via `getApiErrorMessage` when the backend rejects).

### Money: Indian Rupees

Prices store plain numbers end-to-end. Display formatting uses
`Intl.NumberFormat('en-IN', { currency: 'INR' })` (`utils/format.ts`), so
`1499.5` renders as **₹1,499.50** with Indian digit grouping. The form's price
field is `type="text"` (per design), accepts only `1234` or `1234.56`-style
input, and converts to a number just before calling the API.

Decimals come back as strings (`"price": "49.99"`); `formatPrice()` handles both
strings and numbers.

Non-admin users calling a write endpoint receive:

```json
{ "statusCode": 403, "message": "You do not have permission" }
```

The Products page hides write controls for non-admins based on `user.role`
instead of letting them hit errors, and still maps auth failures through
`getApiErrorMessage()`.

---

## 3. Data flow

```text
DashboardPage / ProductsPage
        │  load() — useCallback
        ▼
api/products.ts / api/orders.ts      (unwrap envelope)
        ▼
api/client.ts                        (adds Authorization: Bearer, base /api)
        ▼
Vite proxy  /api ──►  http://localhost:3000  ──►  NestJS
```

- `load()` is called on mount (and "Retry" after an error).
- After a successful add/delete on the Products page the list is refetched from
  the server — no optimistic updates, no stale counts.
- Dashboard stat cards (Products / Orders / Inventory value) and the 5 most
  recent orders are computed *client-side* from the two list responses.

Loading/error/empty states exist in both pages; errors retry-able via button.

---

## 4. Roles in the UI

| Role | Products page | Dashboard |
|---|---|---|
| `ADMIN` | full: create (modal), **edit (modal)**, delete (confirmation popup) | stats + recent orders |
| `MANAGER`, `VENDOR` | read-only table ("view-only" note) | stats + recent orders |

### How the dialogs compose

```text
ProductsPage
├── "+ Add product" ──► Modal ──► ProductForm mode="create" ──► POST /products
├── row "Edit"      ──► Modal ──► ProductForm mode="edit"   ──► PATCH /products/:id
└── row "Delete"    ──► ConfirmDialog                       ──► DELETE /products/:id
```

After every successful mutation the modal closes, a green success notice is
shown, and the table refetches from the server (single source of truth — no
optimistic list mutation).

---

## 5. Adding the next data-driven page

1. Add the endpoint functions + types in `src/api/<feature>.ts` and
   `src/types/api.ts`.
2. Build the page with a `load()` + `useEffect(() => { void load() }, [load])`
   pattern (see `ProductsPage.tsx`) — including loading, error and empty states.
3. Register the route inside `<Route element={<ProtectedRoute />}>` in `App.tsx`.
4. Add `AppHeader` so the page shares navigation and logout.

---

## 6. Notes

- `userId` is no longer required when creating products: the backend fills it
  from the authenticated JWT. Send it only to create a product **for another
  user** (still ADMIN-only).
- Related users in product/order payloads never include password hashes
  (enforced by column `select` in the backend repositories).
- No commit/push was performed for these changes; see the DAC pages under
  `docs/backend/` for the API reference.
