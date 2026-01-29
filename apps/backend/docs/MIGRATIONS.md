# 🛠 Database Migrations (TypeORM)

## 📦 1. Install Migration Tool

```bash
npm i typeorm-ts-node-commonjs
```

---

## 🗂 2. Create DataSource Config

File: `src/database/datasource/config.ts`

```ts
import 'dotenv/config';
import { DataSource } from 'typeorm';

export default new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  entities: [__dirname + '/../entities/*.entity{.ts,.js}'],
  migrations: [__dirname + '/../migrations/*{.ts,.js}'],
});
```

---

## 📝 3. Generate Migration

```bash
npx typeorm-ts-node-commonjs migration:generate src/database/migrations/init -d src/database/datasource/config.ts
```

---

## 🧱 4. Run Migration

```bash
npx typeorm-ts-node-commonjs migration:run -d src/database/datasource/config.ts
```

---

## ▶ 5. Revert Migration

```bash
npx typeorm-ts-node-commonjs migration:revert -d src/database/datasource/config.ts
```

---

## 📁 6. Migration Folder Structure Example

```bash
src/
 └── database/
     ├── datasource/
     │   └── config.ts
     └── migrations/
         └── 1689999999999-init.ts
```

---

## 🧪 Example Generated Migration

A generated migration might look like:

```ts
import { MigrationInterface, QueryRunner } from 'typeorm';

export class Init1712345678900 implements MigrationInterface {
  name = 'Init1712345678900';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE TABLE "user" (
      "id" SERIAL NOT NULL,
      "name" character varying NOT NULL,
      "email" character varying NOT NULL,
      CONSTRAINT "PK_id" PRIMARY KEY ("id")
    )`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "user"`);
  }
}
```

---

## 🏁 Final Notes

| Setting     | Recommended              |
| ----------- | ------------------------ |
| synchronize | ❌ false (for production) |
| migrations  | ✔ true                   |
| entities    | ✔ required               |
| .env usage  | ✔ recommended            |

---

## 🎉 Summary of Commands

| Action             | Command                                                   |
| ------------------ | --------------------------------------------------------- |
| Generate migration | `npm run migration:generate src/database/migrations/init` |
| Run migration      | `npm run migration:run`                                   |
| Revert migration   | `npm run migration:revert`                                |

---

## 🧩 Related Docs

- DATABASE_SETUP.md
- AUTHENTICATION.md
- API_USAGE.md

---

# 🎉 DONE!
