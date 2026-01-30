# NestJS Fundamentals Notes
# Table of Contents
- [1. What is NestJS?](#1-what-is-nestjs)
- [2. How to Set Up a NestJS Project](#2-how-to-set-up-a-nestjs-project)
- [3. Creating Your First NestJS Project](#3-creating-your-first-nestjs-project)
- [4. Project Structure Overview](#4-project-structure-overview)
- [5. Core NestJS Building Blocks](#5-core-nestjs-building-blocks)
- [6. Modules](#6-modules)
- [7. Controllers](#7-controllers)
- [8. Services (Providers)](#8-services-providers)
- [9. Dependency Injection](#9-dependency-injection)
- [10. NestJS Routing](#10-nestjs-routing)
- [11. DTOs (Data Transfer Objects) and Validation with Pipes](#11-dtos-data-transfer-objects-and-validation-with-pipes)
- [🗄 Database Integration (PostgreSQL, MongoDB)](#🗄-database-integration-postgresql-mongodb)
  - [12. Install TypeORM + PostgreSQL](#12-install-typeorm--postgresql)
  - [13. Configure PostgreSQL Connection](#13-configure-postgresql-connection)
  - [14. Data Source Config for Migrations](#14-data-source-config-for-migrations)
  - [15. Create an Entity](#15-create-an-entity)
  - [16. Database Migrations (TypeORM Migrations)](#16-database-migrations-typeorm-migrations)
- [🧾 Configuration with `.env`](#🧾-configuration-with-env)  
- [🧰 Example CRUD REST API (PostgreSQL + TypeORM) - User Module](#🧰-example-crud-rest-api-postgresql--typeorm---user-module)
- [ 17. Authentication & Authorization (JWT)](#17-authentication--authorization-jwt)
  - [Install Packages](#install-packages)
  - [Key Concepts](#key-concepts)
  - [JWT Authentication Flow](#jwt-authentication-flow)
  - [Example: Generating JWT Token](#example-generating-jwt-token)
  - [Example: Validating JWT Token](#example-validating-jwt-token)
  - [JWT Payload Structure](#jwt-payload-structure)
  - [AuthGuard (Global)](#authguard-global)
  - [RolesGuard](#rolesguard)
  - [Custom Decorators](#custom-decorators)
  - [Password Hashing (bcrypt)](#password-hashing-bcrypt)
- [🐳 Docker + PostgreSQL Setup (Optional)](#🐳-docker--postgresql-setup-optional)
- [🎯 Summary](#🎯-summary)
- [📚 Useful Commands List](#📚-useful-commands-list)
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

Application runs at: [http://localhost:3000/api](http://localhost:3000/api)

---

## 4. Project Structure Overview

Default project structure:

```
apps/backend/
├── src/
│   ├── app.controller.ts
│   ├── app.controller.spec.ts
│   ├── app.module.ts
│   ├── app.service.ts
|   ├── users/
|   ├── products/
|   ├── orders/
|   ├── auth/
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
# 17. Authentication & Authorization (JWT)
## Install Packages

```bash
npm install --save @nestjs/jwt @nestjs/passport passport passport-jwt bcryptjs
```

```bash
npm install --save-dev @types/passport-jwt @types/bcryptjs
```
## Key Concepts
- **Authentication**: Verifying user identity (e.g., login).
- **Authorization**: Granting access to resources based on permissions. 

### ⚙ JWT Authentication Flow

1. User logs in with credentials.
2. Server verifies credentials.
3. Server issues a JWT token.
4. User includes JWT in subsequent requests.
5. Server validates JWT and grants access.
### Example: Generating JWT Token

```ts
import { JwtService } from '@nestjs/jwt';
const jwtService = new JwtService({ secret: 'yourSecretKey' });
const payload = { username: 'john_doe', sub: userId };      
const token = jwtService.sign(payload);
``` 

## Example: Validating JWT Token

```ts
import { JwtService } from '@nestjs/jwt';
const jwtService = new JwtService({ secret: 'yourSecretKey' }); 
try {
  const decoded = jwtService.verify(token);
} catch (e) {
  // Handle invalid token
}
```
### JWT Payload Structure
- Standard claims:
  - `sub`: Subject (user ID)
  - `iat`: Issued at (timestamp)
  - `exp`: Expiration time (timestamp)

```json
{
  "sub": "userId",
  "username": "john_doe",
  "iat": 1516239022,
  "exp": 1516242622
}
```
### AuthGuard (Global)
Responsibilities:
Check @Public()
Validate Bearer token
Verify JWT
Attach payload to request:
```md
```ts
req.user = decoded;
```


### RolesGuard
Responsibilities:
Check @Roles()
Compare user roles with required roles  
```bash
@Roles('ADMIN')
@Post('products')
```

- Reads role metadata
- Compares with req.user.role
- Throws 403 if not allowed

### Custom Decorators
- @Public() → Skip auth
- @Roles() → Role restriction

### Password Hashing (bcrypt)
```ts
import * as bcrypt from 'bcryptjs';   
const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
const isMatch = await bcrypt.compare(plainPassword, hashedPassword);
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
