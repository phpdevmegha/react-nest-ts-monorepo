# NestJS Fundamentals Notes

## 📌 Playlist Reference

freeCodeCamp NestJS YouTube Playlist

---

## 1. What is NestJS?

- NestJS is a backend framework for **Node.js**.
- Written in TypeScript.
- Built on top of Express.js.
- Used to build **scalable and maintainable** APIs.
- Inspired by Angular architecture.

### Key Points

- Written in **TypeScript**
- Built on **Express.js** (or Fastify)
- Modular architecture inspired by **Angular**
- Enterprise-ready

---

## 2. How to Set Up a NestJS Project

### Prerequisites

- Node.js installed
- npm installed

### Install NestJS CLI

```bash
npm install -g @nestjs/cli
```

---

## 3. Creating Your First NestJS Project

Create a new project using the Nest CLI:

```bash
nest new backend
cd backend
npm run start:dev
```

Application runs at: [http://localhost:3000](http://localhost:3000)

---

## 4. Project Structure Overview

Default project structure:

```
backend/
├── src/
│   ├── app.controller.ts
│   ├── app.controller.spec.ts
│   ├── app.module.ts
│   ├── app.service.ts
│   └── main.ts
├── test/
├── package.json
├── tsconfig.json
└── nest-cli.json
```

### File Roles

| File | Purpose |
|---|---|
| main.ts | Application entry point |
| app.module.ts | Root module that registers controllers and providers |
| app.controller.ts | Handles HTTP requests and routes |
| app.service.ts | Contains business logic |

---

## 5. Core NestJS Building Blocks

NestJS applications are built using:

| Component | Role |
|---|---|
| **Module** | Groups features |
| **Controller** | Handles requests (routes) |
| **Service (Provider)** | Business logic |
| **DTO** | Validates request data |

---

## 6. Modules

- Modules organize application features
- Created using the `@Module` decorator
- Each feature can have its own module
- Every app has a root AppModule

Generate a module:

```bash
nest g module users
```

Example Module:

```ts
@Module({
  controllers: [UsersController],
  providers: [UsersService],
})
export class UsersModule {}
```

---

## 7. Controllers

- Controllers handle incoming requests
- Define routes using decorators
- Common decorators:
  - `@Controller()`
  - `@Get()`
  - `@Post()`
  - `@Put()`
  - `@Delete()`

Generate:

```bash
nest g controller users
```

Example:

```ts
@Controller('users')
export class UsersController {
  @Get()
  findAll() {
    return 'Get Users';
  }
}
```

---

## 8. Services (Providers)

- Services contain business logic
- Decorated with `@Injectable()`
- Injected into controllers using constructor injection

Generate:

```bash
nest g service users
```

Example:

```ts
@Injectable()
export class UsersService {
  findAll() {
    return ['User 1', 'User 2'];
  }
}
```

---

## 9. Dependency Injection

- NestJS has built-in dependency injection
- Automatically provides services to controllers through constructors
- Improves code reusability and testability

Example:

```ts
constructor(private readonly appService: AppService) {}
```

Injected via constructor:

```ts
constructor(private usersService: UsersService) {}
```

---

## 10. NestJS Routing

- Routes are defined using decorators
- Common decorators:

| Decorator | Description |
|---|---|
| `@Get()` | Read |
| `@Post()` | Create |
| `@Patch()` | Update |
| `@Delete()` | Delete |
| `@Param()` | Route params |
| `@Body()` | Request body |
| `@Query()` | Query params |

---

## 11. DTOs (Data Transfer Objects) and Validation with Pipes

- DTOs define the structure of request data
- Implemented as TypeScript classes
- Used for validation and type safety
- Pipes validate incoming data
- Uses class-validator and class-transformer

Install validation:

```bash
npm i class-validator class-transformer
```

Example:

```ts
export class CreateUserDto {
  @IsString()
  name: string;
}
```

Enable global validation in `main.ts`:

```ts
app.useGlobalPipes(new ValidationPipe());
```

---

# 🗄 Database Integration (PostgreSQL + TypeORM)

---

## 12. Install TypeORM + PostgreSQL

```bash
npm install --save @nestjs/typeorm typeorm pg
```

---

## 13. Configure PostgreSQL Connection

Edit `app.module.ts`:

```ts
TypeOrmModule.forRoot({
  type: 'postgres',
  host: 'localhost',
  port: 5432,
  username: 'postgres',
  password: 'password',
  database: 'nestdb',
  autoLoadEntities: true,
  synchronize: false,
})
```

> **Note:** `synchronize: false` is recommended for production.

---

## 14. Data Source Config for Migrations

Create file: `src/database/datasource/config.ts`

Add content:

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
  entities: ['dist/**/*.entity.js'],
  migrations: ['dist/database/migrations/*.js'],
});
```

---

## 15. Create an Entity

```bash
nest g resource users
```

Choose:
- ✔ REST API
- ✔ TypeORM
- ✔ PostgreSQL

Example entity:

```ts
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

## 16. Database Migrations (TypeORM Migrations)

### Install helper

```bash
npm i typeorm-ts-node-commonjs
```

### Create migration

```bash
npx typeorm-ts-node-commonjs migration:generate src/database/migrations/init -d src/database/datasource/config.ts
```

### Run migration

```bash
npx typeorm-ts-node-commonjs migration:run -d src/database/datasource/config.ts
```

---

# 🧾 Configuration with `.env`

Create `.env`:

```env
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=password
DB_NAME=nestdb
```

Load using:

```bash
npm i dotenv
```

Example datasource:

```ts
import 'dotenv/config';
export default new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST,
  ...
});
```

---

# 🧰 Example CRUD REST API (PostgreSQL + TypeORM) - User Module

### Create User

```
POST /api/v1/users
```

Body:

```json
{
  "name": "John",
  "email": "john@mail.com"
}
```

### Get Users

```
GET /api/v1/users
```

### Update User

```
PATCH /api/v1/users/1
```

### Delete User

```
DELETE /api/v1/users/1
```

---

# 🐳 Docker + PostgreSQL Setup (Optional)

docker-compose.yml:

```yaml
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
      POSTGRES_DB: nestdb
    ports:
      - "5433:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

Start:

```bash
docker compose up -d
```

---

# 🎯 Summary

| Topic | Status |
|---|---|
| NestJS Basics | ✔ |
| Controllers & Services | ✔ |
| DTO Validation | ✔ |
| PostgreSQL Integration | ✔ |
| TypeORM | ✔ |
| Migrations | ✔ |
| `.env` configuration | ✔ |
| Docker Setup | ✔ |

---

# 📚 Useful Commands List

| Purpose | Command |
|---|---|
| Create project | `nest new project` |
| Generate module | `nest g mo users` |
| Generate controller | `nest g co users` |
| Generate service | `nest g s users` |
| Generate resource | `nest g resource users` |
| Run dev | `npm run start:dev` |
| Generate migration | `typeorm migration:generate` |
| Run migration | `typeorm migration:run` |
| Install TypeORM | `npm i @nestjs/typeorm typeorm pg` |

---

# 🎉 End of Notes

Happy Coding!
