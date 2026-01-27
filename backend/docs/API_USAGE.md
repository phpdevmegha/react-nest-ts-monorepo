# 📡 API Usage Documentation

## 🌍 Base URL

```
http://localhost:3000/api
```

---

## 🧾 Authentication

JWT token is required for most endpoints (except login).

Include the token in the request header like this:

```http
Authorization: Bearer <token>
```

---

## � Response Format

All API responses follow the `ApiResponse<T>` interface:

```ts
interface ApiResponse<T> {
  success: boolean;      // Whether the request succeeded
  message: string;       // Human-readable message
  data?: T | null;       // Response payload (optional, null on error)
}
```

**Success Example:**
```json
{
  "success": true,
  "message": "User created successfully",
  "data": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "role": "VENDOR"
  }
}
```

**Error Example:**
```json
{
  "success": false,
  "message": "User with this email already exists",
  "data": null
}
```

---

## �🔐 Authentication Module

### Login User

**Endpoint:**
```
POST /auth/login
```

**Description:** Authenticate user with email and password to receive JWT token

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response (200 OK):**
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Error Response (401 Unauthorized):**
```json
{
  "statusCode": 401,
  "message": "Invalid email or password",
  "error": "Unauthorized"
}
```

---

## 👤 Users Module

### Create a New User

**Endpoint:**
```
POST /users
```

**Description:** Create a new user in the system

**Request Body:**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "securePassword123",
  "role": "VENDOR"
}
```

**Available Roles:**
- `ADMIN` - Administrator role
- `MANAGER` - Manager role
- `VENDOR` - Vendor role

**Response (201 Created):**
```json
{
  "id": 1,
  "name": "John Doe",
  "email": "john@example.com",
  "password": "hashed_password_here",
  "role": "VENDOR"
}
```

---

### Get All Users

**Endpoint:**
```
GET /users
```

**Description:** Retrieve all users (supports role filtering)

**Headers:**
```http
Authorization: Bearer <your_jwt_token>
```

**Query Parameters:**
- `role` (optional, string) - Filter by user role (ADMIN, MANAGER, VENDOR)

**Example with Query:**
```
GET /users?role=VENDOR
```

**Response (200 OK):**
```json
[
  {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "password": "hashed_password",
    "role": "VENDOR"
  },
  {
    "id": 2,
    "name": "Jane Smith",
    "email": "jane@example.com",
    "password": "hashed_password",
    "role": "MANAGER"
  }
]
```

---

### Get User by ID

**Endpoint:**
```
GET /users/:id
```

**Description:** Retrieve a specific user by ID

**Path Parameters:**
- `id` (number) - The user ID

**Headers:**
```http
Authorization: Bearer <your_jwt_token>
```

**Response (200 OK):**
```json
{
  "id": 1,
  "name": "John Doe",
  "email": "john@example.com",
  "password": "hashed_password",
  "role": "VENDOR"
}
```

---

### Update User by ID

**Endpoint:**
```
POST /users/:id
```

**Description:** Update an existing user by ID

**Path Parameters:**
- `id` (number) - The user ID

**Request Body:**
```json
{
  "name": "John Updated",
  "email": "john.updated@example.com",
  "password": "newPassword789",
  "role": "MANAGER"
}
```

**Headers:**
```http
Authorization: Bearer <your_jwt_token>
```

**Response (200 OK):**
```json
{
  "id": 1,
  "name": "John Updated",
  "email": "john.updated@example.com",
  "password": "hashed_password",
  "role": "MANAGER"
}
```

---

### Delete User by ID

**Endpoint:**
```
DELETE /users/:id
```

**Description:** Delete a user by ID

**Path Parameters:**
- `id` (number) - The user ID

**Headers:**
```http
Authorization: Bearer <your_jwt_token>
```

**Response (200 OK):**
```json
{
  "message": "User deleted successfully"
}
```

---

## 📦 Products Module

> **Note:** Products endpoints require `ADMIN` role

### Create a New Product

**Endpoint:**
```
POST /products
```

**Description:** Create a new product (ADMIN only)

**Request Body:**
```json
{
  "title": "Laptop Pro M2",
  "price": 999.99,
  "userId": 1
}
```

**Headers:**
```http
Authorization: Bearer <admin_jwt_token>
```

**Response (201 Created):**
```json
{
  "id": 1,
  "title": "Laptop Pro M2",
  "price": 999.99,
  "userId": 1,
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "role": "VENDOR"
  }
}
```

---

### Get All Products

**Endpoint:**
```
GET /products
```

**Description:** Retrieve all products

**Response (200 OK):**
```json
[
  {
    "id": 1,
    "title": "Laptop Pro M2",
    "price": 999.99,
    "userId": 1,
    "user": {
      "id": 1,
      "name": "John Doe",
      "email": "john@example.com",
      "role": "VENDOR"
    }
  },
  {
    "id": 2,
    "title": "Wireless Mouse",
    "price": 29.99,
    "userId": 2,
    "user": {
      "id": 2,
      "name": "Jane Smith",
      "email": "jane@example.com",
      "role": "MANAGER"
    }
  }
]
```

---

### Get Product by ID

**Endpoint:**
```
GET /products/:id
```

**Description:** Retrieve a specific product by ID

**Path Parameters:**
- `id` (number) - The product ID

**Response (200 OK):**
```json
{
  "id": 1,
  "title": "Laptop Pro M2",
  "price": 999.99,
  "userId": 1,
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "role": "VENDOR"
  }
}
```

---

### Update Product by ID

**Endpoint:**
```
PATCH /products/:id
```

**Description:** Update a product by ID (ADMIN only)

**Path Parameters:**
- `id` (number) - The product ID

**Request Body:**
```json
{
  "title": "Laptop Pro M2 Max",
  "price": 1299.99
}
```

**Headers:**
```http
Authorization: Bearer <admin_jwt_token>
```

**Response (200 OK):**
```json
{
  "id": 1,
  "title": "Laptop Pro M2 Max",
  "price": 1299.99,
  "userId": 1,
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "role": "VENDOR"
  }
}
```

---

### Delete Product by ID

**Endpoint:**
```
DELETE /products/:id
```

**Description:** Delete a product by ID (ADMIN only)

**Path Parameters:**
- `id` (number) - The product ID

**Headers:**
```http
Authorization: Bearer <admin_jwt_token>
```

**Response (200 OK):**
```json
{
  "message": "Product deleted successfully"
}
```

---

## 📋 Orders Module

### Create a New Order

**Endpoint:**
```
POST /orders
```

**Description:** Create a new order with multiple products

**Request Body:**
```json
{
  "userId": 1,
  "productIds": [1, 2],
  "status": "pending"
}
```

**Available Order Statuses:**
- `pending` - Order is pending
- `confirmed` - Order is confirmed
- `shipped` - Order has been shipped
- `delivered` - Order has been delivered
- `cancelled` - Order has been cancelled

**Headers:**
```http
Authorization: Bearer <your_jwt_token>
```

**Response (201 Created):**
```json
{
  "id": 1,
  "orderNumber": "ORD-2024-0001",
  "userId": 1,
  "totalPrice": 1029.98,
  "status": "pending",
  "paidAt": null,
  "createdAt": "2024-01-01T00:00:00.000Z",
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "role": "VENDOR"
  },
  "products": [
    {
      "id": 1,
      "title": "Laptop Pro M2",
      "price": 999.99,
      "userId": 1
    },
    {
      "id": 2,
      "title": "Wireless Mouse",
      "price": 29.99,
      "userId": 2
    }
  ]
}
```

---

### Get All Orders

**Endpoint:**
```
GET /orders
```

**Description:** Retrieve all orders

**Headers:**
```http
Authorization: Bearer <your_jwt_token>
```

**Response (200 OK):**
```json
[
  {
    "id": 1,
    "orderNumber": "ORD-2024-0001",
    "userId": 1,
    "totalPrice": 1029.98,
    "status": "pending",
    "paidAt": null,
    "createdAt": "2024-01-01T00:00:00.000Z",
    "user": {
      "id": 1,
      "name": "John Doe",
      "email": "john@example.com",
      "role": "VENDOR"
    },
    "products": [
      {
        "id": 1,
        "title": "Laptop Pro M2",
        "price": 999.99,
        "userId": 1
      },
      {
        "id": 2,
        "title": "Wireless Mouse",
        "price": 29.99,
        "userId": 2
      }
    ]
  }
]
```

---

### Get Order by ID

**Endpoint:**
```
GET /orders/:id
```

**Description:** Retrieve a specific order by ID

**Path Parameters:**
- `id` (number) - The order ID

**Headers:**
```http
Authorization: Bearer <your_jwt_token>
```

**Response (200 OK):**
```json
{
  "id": 1,
  "orderNumber": "ORD-2024-0001",
  "userId": 1,
  "totalPrice": 1029.98,
  "status": "pending",
  "paidAt": null,
  "createdAt": "2024-01-01T00:00:00.000Z",
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "role": "VENDOR"
  },
  "products": [
    {
      "id": 1,
      "title": "Laptop Pro M2",
      "price": 999.99,
      "userId": 1
    },
    {
      "id": 2,
      "title": "Wireless Mouse",
      "price": 29.99,
      "userId": 2
    }
  ]
}
```

---

### Update Order Status

**Endpoint:**
```
POST /orders/:id/status
```

**Description:** Update the status of an existing order

**Path Parameters:**
- `id` (number) - The order ID

**Request Body:**
```json
{
  "status": "confirmed"
}
```

**Headers:**
```http
Authorization: Bearer <your_jwt_token>
```

**Response (200 OK):**
```json
{
  "id": 1,
  "orderNumber": "ORD-2024-0001",
  "userId": 1,
  "totalPrice": 1029.98,
  "status": "confirmed",
  "paidAt": null,
  "createdAt": "2024-01-01T00:00:00.000Z",
  "updatedAt": "2024-01-05T00:00:00.000Z",
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "role": "VENDOR"
  },
  "products": [
    {
      "id": 1,
      "title": "Laptop Pro M2",
      "price": 999.99,
      "userId": 1
    },
    {
      "id": 2,
      "title": "Wireless Mouse",
      "price": 29.99,
      "userId": 2
    }
  ]
}
```

---

## ⚠ HTTP Status Codes

| Code | Status | Meaning |
|------|--------|---------|
| 200 | OK | Request succeeded |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid request format or parameters |
| 401 | Unauthorized | Missing or invalid JWT token |
| 403 | Forbidden | Insufficient permissions (role-based) |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 500 | Server Error | Internal server error |

---

## 🔍 Error Response Format

All error responses follow this format:

```json
{
  "statusCode": 400,
  "message": "Error description",
  "error": "Bad Request"
}
```

---

## 📌 Important Notes

- **No Profile Endpoint**: There is no dedicated profile endpoint. User profile is retrieved via login response which contains the JWT token.
- **JWT Token**: Required for most endpoints (except login and create user)
- **Bearer Token**: Include the token in the `Authorization` header with the format: `Bearer <token>`
- **User Creation**: Use `POST /users` endpoint (not `/auth/register`)
- **Role-Based Access**: Products endpoints require `ADMIN` role
- **Request Body**: Always use `Content-Type: application/json` header
- **Response Format**: All responses are in JSON format
- **User Roles**: ADMIN, MANAGER, VENDOR
- **Order Statuses**: pending, confirmed, shipped, delivered, cancelled
- **Product Ownership**: Products are linked to users via `userId`

---

## 🎯 Complete API Flow Examples

### Example 1: Register User, Login, and Create Order

```bash
# Step 1: Create a new user
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "securePassword123",
    "role": "VENDOR"
  }'

# Step 2: Login to get JWT token
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securePassword123"
  }'

# Response will contain token:
# {
#   "message": "Login successful",
#   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
# }

# Step 3: Get all users (authenticated)
curl -X GET http://localhost:3000/api/users \
  -H "Authorization: Bearer <token_from_step_2>"

# Step 4: Get all products
curl -X GET http://localhost:3000/api/products \
  -H "Authorization: Bearer <token_from_step_2>"
```

---

### Example 2: Create Product (Admin) and Place Order

```bash
# Step 1: Create product as ADMIN user
curl -X POST http://localhost:3000/api/products \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Laptop Pro M2",
    "price": 999.99,
    "userId": 1
  }'

# Step 2: Get product ID from response, then create order
curl -X POST http://localhost:3000/api/orders \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": 1,
    "productIds": [1],
    "status": "pending"
  }'

# Step 3: Update order status
curl -X POST http://localhost:3000/api/orders/1/status \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"status": "confirmed"}'
```

---

### Example 3: User Management Workflow

```bash
# Step 1: Get all VENDOR users
curl -X GET "http://localhost:3000/api/users?role=VENDOR" \
  -H "Authorization: Bearer <token>"

# Step 2: Get specific user
curl -X GET http://localhost:3000/api/users/1 \
  -H "Authorization: Bearer <token>"

# Step 3: Update user
curl -X POST http://localhost:3000/api/users/1 \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Updated",
    "email": "john.updated@example.com",
    "role": "MANAGER"
  }'

# Step 4: Delete user
curl -X DELETE http://localhost:3000/api/users/1 \
  -H "Authorization: Bearer <token>"
```

---

## 📊 API Summary Table

| Module | Method | Endpoint | Protected | Role Required |
|--------|--------|----------|-----------|---------------|
| Auth | POST | `/auth/login` | No | - |
| Users | POST | `/users` | No | - |
| Users | GET | `/users` | Yes | - |
| Users | GET | `/users/:id` | Yes | - |
| Users | POST | `/users/:id` | Yes | - |
| Users | DELETE | `/users/:id` | Yes | - |
| Products | POST | `/products` | Yes | ADMIN |
| Products | GET | `/products` | No | - |
| Products | GET | `/products/:id` | No | - |
| Products | PATCH | `/products/:id` | Yes | ADMIN |
| Products | DELETE | `/products/:id` | Yes | ADMIN |
| Orders | POST | `/orders` | Yes | - |
| Orders | GET | `/orders` | Yes | - |
| Orders | GET | `/orders/:id` | Yes | - |
| Orders | POST | `/orders/:id/status` | Yes | - |

---

## 🎉 DONE!
