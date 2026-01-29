# 🗄 Database Setup (PostgreSQL + TypeORM + NestJS)

## 1. Install Dependencies

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

Create a `.env` file in your root:

```env
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=your_password
DB_NAME=testdb
```

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

## 6. Test Database Connection

Run NestJS app:

```bash
npm run start:dev
```
---

# 🎉 DONE!
