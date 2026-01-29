# 🧾 Environment Configuration

## 1. Create `.env` File

Create a `.env` file in your project root:

```env
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=username
DB_PASSWORD=password
DB_NAME=testdb

JWT_SECRET=your-secret-key
PORT=3000
```

---

## 2. Load .env in NestJS

Install dotenv:

```bash
npm i dotenv
```

Usage example:

```ts
import 'dotenv/config';
const port = process.env.PORT || 3000;
```
---

# 🎉 DONE!