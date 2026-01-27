# 🔐 Authentication & Authorization (JWT)

This project uses:

- JWT for authentication
- Guards for authorization
- `Bcrypt` (password hashing)

---

## 📦 1. Install Packages

```bash
npm install @nestjs/jwt @nestjs/passport passport passport-jwt bcrypt
npm install --save-dev @types/passport-jwt @types/bcrypt
```

---

## 🧱 2. Auth Module Structure Overview

```bash
src/auth/
 ├── auth.module.ts
 ├── auth.controller.ts
 ├── auth.service.ts
 ├── decorators/
 │     ├── public.decorator.ts
 │     └── roles.decorator.ts
 ├── guards/
 │     └── auth.guard.ts
 └── dto/
     └── login.dto.ts
```

---

## ⚙ 3. Auth Flow

1. User logs in → receives JWT
2. Client sends JWT in `Authorization: Bearer <token>` header
3. Guard validates token
4. Controller executes request

---

## 🧾 4. Login DTO

```ts
export class LoginDto {
  readonly email: string;
  readonly password: string;
}
```

---

## 👤 5. User Creation

Users are created via `POST /users` endpoint (not in auth module):

```ts
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "securePassword123",
  "role": "VENDOR"
}
```

---

## 🛂 6. Custom Decorators

### @Public() Decorator
Skip authentication for public routes (login, create user):

```ts
@Public()
@Post('login')
login(@Body() dto: LoginDto) {
  return this.authService.login(dto.email, dto.password);
}
```

### @Roles() Decorator
Restrict access to specific roles (e.g., ADMIN only):

```ts
@Roles('ADMIN')
@Post('products')
createProduct(@Body() dto: CreateProductDto) {
  return this.productsService.create(dto);
}
```

---

## 🛡️ 7. Guards Implementation

### AuthGuard (Global JWT Validation)

**Location:** `src/auth/guards/auth.guard.ts`

Validates JWT tokens for all protected routes. Applied globally in `app.module.ts`:

```ts
{
  provide: APP_GUARD,
  useClass: AuthGuard,
}
```

**How it works:**
1. Checks if route has `@Public()` decorator → allows access
2. Extracts token from `Authorization: Bearer <token>` header
3. Verifies token signature using JWT secret
4. Attaches decoded JWT payload to `req.user`
5. Throws `UnauthorizedException` if token is invalid or missing

**Example:**
```ts
// Route automatically protected - token required
@Get('profile')
getProfile(@Request() req) {
  console.log(req.user); // { id: 1, email: 'user@example.com', role: 'VENDOR' }
  return req.user;
}
```

### RolesGuard (Role-Based Access Control)

**Location:** `src/auth/guards/roles.guard.ts`

Restricts routes to specific user roles. Used with `@Roles()` decorator:

```ts
@Roles('ADMIN', 'MANAGER')
@Delete('products/:id')
deleteProduct(@Param('id') id: number) {
  return this.productsService.delete(id);
}
```

**How it works:**
1. Reads `@Roles()` metadata from the handler
2. Gets user role from `req.user.role`
3. Checks if user role is in allowed roles array
4. Throws `ForbiddenException` if user doesn't have required role
5. Returns `true` if no `@Roles()` decorator is present

**Role Examples:**
- `ADMIN` - Full system access
- `MANAGER` - Manage products and orders
- `VENDOR` - Can only manage own products/orders
- `USER` - Basic read access

---

## 🔑 8. Type Interfaces

### JwtPayload Interface

**Location:** `src/auth/interfaces/jwt-payload.ts`

Defines the structure of decoded JWT tokens:

```ts
export interface JwtPayload {
  id: number;
  email: string;
  role: string;
}
```

**Usage in Service:**
```ts
const payload: JwtPayload = {
  id: user.id,
  email: user.email,
  role: user.role
};
const token = this.jwtService.sign(payload);
```

### RequestWithUser Interface

**Location:** `src/auth/interfaces/request-with-user.ts`

Extends Express `Request` with typed user property:

```ts
import { Request } from 'express';
import { JwtPayload } from './jwt-payload';

export interface RequestWithUser extends Request {
  user?: JwtPayload;
}
```

**Usage in Controller:**
```ts
import { RequestWithUser } from './interfaces/request-with-user';

@Get('me')
getMe(@Request() req: RequestWithUser) {
  return req.user; // Typed access: req.user.id, req.user.email, req.user.role
}
```

---

## 💾 9. JWT Configuration

**Location:** `src/auth/constants.ts`

```ts
export const jwtConstants = {
  secret: process.env.JWT_SECRET || 'your-secret-key',
};
```

**Environment Variable:**
In `.env` file:
```
JWT_SECRET=your-super-secret-key-min-32-chars
```

**Module Setup in `auth.module.ts`:**
```ts
JwtModule.register({
  secret: jwtConstants.secret,
  signOptions: { expiresIn: '24h' },
})
```

---

## 🔄 10. Generating JWTs

Example:

```ts
const payload = { id: user.id, email: user.email, role: user.role };
return this.jwtService.sign(payload);
```

---

## 🛠 11. Password Hashing

Use bcrypt:

```ts
const salt = await bcrypt.genSalt();
const hashedPassword = await bcrypt.hash(password, salt);
const isMatch = await bcrypt.compare(plainPassword, hashedPassword); // For validating password
```

---

## 🧾 12. Line-by-Line Code Understanding

### AuthService Login Method

**Location:** `src/auth/auth.service.ts`

```ts
async login(email: string, password: string) {
  // Step 1: Find user by email from database
  const user = await this.usersService.findByEmail(email);
  if (!user) throw new UnauthorizedException('Invalid email or password');

  // Step 2: Compare provided password with stored bcrypt hash
  const match = await bcrypt.compare(password, user.password);
  if (!match) throw new UnauthorizedException('Invalid email or password');

  // Step 3: Create JWT payload with user information
  const token = this.jwt.sign({
    sub: user.id,      // 'sub' = subject (standard JWT field for user ID)
    email: user.email, // Include email in token
    role: user.role,   // Include role for authorization checks later
  });

  // Step 4: Return token to client
  return { message: 'Login successful', token };
}
```

**Key Concepts:**
- `bcrypt.compare()` - One-way comparison: password hash is never reversed
- `sub` field - Standard JWT convention for user ID/subject
- Token includes `role` to avoid database lookup during authorization

### AuthGuard - Detailed Flow

**Location:** `src/auth/guards/auth.guard.ts`

```ts
canActivate(context: ExecutionContext): boolean {
  // Step 1: Check @Public() decorator (routes that skip auth)
  const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
    context.getHandler(),    // Check method level decorator
    context.getClass(),      // Check controller level decorator
  ]);
  if (isPublic) return true;  // Skip token verification for @Public() routes

  // Step 2: Get the HTTP request object
  const req = context.switchToHttp().getRequest<RequestWithUser>();

  // Step 3: Extract Authorization header
  const authHeader = req.headers.authorization;
  // Expected format: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

  // Step 4: Validate header format (must start with "Bearer ")
  if (!authHeader?.startsWith('Bearer ')) {
    throw new UnauthorizedException('Login required');
  }

  // Step 5: Extract token by removing "Bearer " prefix
  const token = authHeader.split(' ')[1];
  // Example: "Bearer TOKEN" → ["Bearer", "TOKEN"] → TOKEN

  // Step 6: Verify JWT signature and expiration
  try {
    const decoded = this.jwtService.verify<JwtPayload>(token);
    // This checks:
    // - Token signature matches (secret key validation)
    // - Token hasn't expired (expiresIn check)
    // - Token structure is valid

    req.user = decoded;  // Attach decoded payload to request
    return true;         // Token valid, allow request to continue
  } catch {
    throw new UnauthorizedException('Invalid token');
    // Thrown if: token expired, wrong secret, corrupted, or invalid format
  }
}
```

### RolesGuard - Role Verification

**Location:** `src/auth/guards/roles.guard.ts`

```ts
canActivate(ctx: ExecutionContext): boolean {
  // Step 1: Extract @Roles() decorator metadata
  const requiredRoles = this.reflector.getAllAndOverride<string[]>(
    ROLES_KEY,
    [ctx.getHandler(), ctx.getClass()],
  );

  // Step 2: If no @Roles() specified, allow all authenticated users
  if (!requiredRoles) return true;
  // Example: @Get('profile') without @Roles() = accessible to any authenticated user

  // Step 3: Get user object from request (populated by AuthGuard)
  const req = ctx.switchToHttp().getRequest<RequestWithUser>();
  const userRole = req.user?.role;  // e.g., 'ADMIN', 'USER', 'MANAGER'

  // Step 4: Check if user's role is in allowed roles
  if (!requiredRoles.includes(userRole!)) {
    // Example of denied access:
    // @Roles('ADMIN', 'MANAGER')
    // user.role = 'USER'
    // 'USER' not in ['ADMIN', 'MANAGER'] → Forbidden
    throw new ForbiddenException('You do not have permission');
  }

  return true;  // User has required role, allow request
}
```

---

## 🔄 13. Complete Request Flow Diagram

```
┌─────────────────────────────────────────┐
│   User Request with JWT Token           │
│   GET /api/products                     │
│   Headers: { Authorization: "Bearer ..." }
└──────────────────┬──────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │   AuthGuard Checks   │
        └──────────┬───────────┘
                   │
       ┌───────────┴──────────────┐
       │                          │
       ▼                          ▼
    @Public()?              Check token
    YES → Pass              - Format correct?
    NO → Verify             - Signature valid?
                            - Not expired?
                                 │
                        ┌────────┴────────┐
                        │                 │
                     Valid            Invalid
                        │                 │
                        ▼                 ▼
                   Extract user    UnauthorizedException
                   Attach to req   (401 Unauthorized)
                        │
                        ▼
        ┌──────────────────────────┐
        │   RolesGuard Checks      │
        └──────────┬───────────────┘
                   │
       ┌───────────┴──────────────┐
       │                          │
       ▼                          ▼
    @Roles()            Check user role
    specified?          - Role in allowed?
    NO → Pass through   - If yes → Pass
                        - If no → Deny
                                 │
                        ┌────────┴────────┐
                        │                 │
                     Match            No Match
                        │                 │
                        ▼                 ▼
                   Continue          ForbiddenException
                   to handler        (403 Forbidden)
                        │
                        ▼
        ┌──────────────────────────┐
        │  Controller Executes     │
        │  Returns Data Response   │
        └──────────────────────────┘
```

---

## 14. Real-World Examples

### Example 1: Public Login Endpoint

```ts
@Controller('auth')
export class AuthController {
  @Public()                    // ← Bypass AuthGuard
  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto.email, dto.password);
  }
}

// Request:
// POST /api/auth/login
// { "email": "admin@test.com", "password": "password123" }

// Response:
// {
//   "message": "Login successful",
//   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
// }
```

### Example 2: Authenticated Endpoint (Any User)

```ts
@Controller('users')
export class UsersController {
  @Get('me')  // No @Roles() = any authenticated user allowed
  getMe(@Request() req: RequestWithUser) {
    return req.user;  // Returns: { id, email, role }
  }
}

// Request:
// GET /api/users/me
// Headers: { Authorization: "Bearer <token>" }

// Response:
// { "id": 1, "email": "user@test.com", "role": "USER" }
```

### Example 3: Role-Restricted Endpoint

```ts
@Controller('products')
@Roles('ADMIN')  // Only ADMIN role allowed
export class ProductsController {
  @Post()
  create(@Body() dto: CreateProductDto) {
    return this.productsService.create(dto);
  }
}

// Request from ADMIN:
// POST /api/products
// Headers: { Authorization: "Bearer <admin_token>" }
// Response: ✅ Product created

// Request from USER:
// POST /api/products
// Headers: { Authorization: "Bearer <user_token>" }
// Response: ❌ 403 Forbidden - "You do not have permission"
```

---

## 15. Security Best Practices

✅ **Implemented in Your Project:**
- Password hashing with bcrypt (8 salt rounds)
- JWT token expiration (24 hours)
- Global guards on all endpoints
- Role-based access control
- Exception handling for invalid tokens
- Input validation on DTOs

⚠️ **Production Recommendations:**
1. Store JWT secret in `.env` (not in code)
2. Implement refresh tokens for longer sessions
3. Add rate limiting on login endpoint
4. Implement logout/token blacklisting
5. Add password reset flow
6. Use HTTPS only
7. Add CSRF protection

---

## 16. JWT Token Structure

A JWT consists of three parts separated by dots:

```
Header.Payload.Signature
│      │       │
│      │       └─ HMACSHA256(header.payload, secret)
│      └──────── {"sub": 1, "email": "user@test.com", "role": "ADMIN"}
└──────────────── {"alg": "HS256", "typ": "JWT"}
```

**Decoded Example:**
```json
// Header
{
  "alg": "HS256",
  "typ": "JWT"
}

// Payload
{
  "sub": 1,
  "email": "user@test.com",
  "role": "ADMIN",
  "iat": 1674345600,
  "exp": 1674432000
}

// Signature
// Signed with your secret key
```

---

## 📚 17. Additional Resources

- [JWT Debugger](https://jwt.io/) - Inspect JWT tokens
- [Passport.js Documentation](http://www.passportjs.org/)
- [Bcrypt Documentation](https://www.npmjs.com/package/bcrypt)
- [NestJS Authentication](https://docs.nestjs.com/security/authentication)
- [NestJS Guards](https://docs.nestjs.com/guards)

---

# 🎉 Complete Authentication & Authorization System!
