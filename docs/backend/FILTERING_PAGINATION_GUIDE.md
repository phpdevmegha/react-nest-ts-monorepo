# 🔍 Phase 1: Advanced Filtering & Pagination

## What You Can Do Now

✅ **Filter products** by price range
✅ **Search** in products, users, orders
✅ **Paginate** results (10 items per page by default)
✅ **Sort** products by price or title
✅ **Filter users** by role
✅ **Filter orders** by status

---

## 🎯 Quick Examples

### Search Products by Title

```bash
GET /api/products?search=laptop
```

**Response:**
```json
{
  "success": true,
  "message": "Products fetched successfully",
  "data": [
    {"id": 1, "title": "Gaming Laptop", "price": 999.99, "userId": 5}
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 1,
    "totalPages": 1,
    "hasMore": false
  }
}
```

### Filter Products by Price

```bash
GET /api/products?minPrice=100&maxPrice=500
```

Returns all products between $100-$500.

### Pagination

```bash
GET /api/products?page=2&limit=5
```

Gets page 2 with 5 items per page.

### Combine Filters

```bash
GET /api/products?search=phone&minPrice=200&maxPrice=800&page=1&limit=10&sortBy=price&order=ASC
```

---

## 📋 Query Parameters

### Pagination (All Endpoints)

| Parameter | Type | Default | Example |
|-----------|------|---------|---------|
| `page` | number | 1 | `?page=2` |
| `limit` | number | 10 | `?limit=20` |

### Products (`/api/products`)

| Parameter | Type | Example | Purpose |
|-----------|------|---------|---------|
| `search` | string | `?search=laptop` | Search by title |
| `minPrice` | number | `?minPrice=100` | Min price filter |
| `maxPrice` | number | `?maxPrice=999` | Max price filter |
| `sortBy` | string | `?sortBy=price` | Sort by: `price`, `title`, `newest` |
| `order` | string | `?order=ASC` | Order: `ASC` or `DESC` |

### Users (`/api/users`)

| Parameter | Type | Example | Purpose |
|-----------|------|---------|---------|
| `search` | string | `?search=john` | Search by name or email |
| `role` | string | `?role=ADMIN` | Filter by: `ADMIN`, `MANAGER`, `VENDOR` |

### Orders (`/api/orders`)

| Parameter | Type | Example | Purpose |
|-----------|------|---------|---------|
| `search` | string | `?search=ORD-123` | Search by order number |
| `status` | string | `?status=PENDING` | Filter by: `PENDING`, `PROCESSING`, `SHIPPED`, `DELIVERED` |

---

## 🧪 Real Test Examples

### Test 1: Get Products with Pagination

```bash
curl "http://localhost:3000/api/products?page=1&limit=5"
```

**Shows:**
- Items 1-5
- Total count
- Page number
- Has more pages?

### Test 2: Search Products by Name

```bash
curl "http://localhost:3000/api/products?search=laptop"
```

**Shows:**
- Only products with "laptop" in title
- Pagination info

### Test 3: Filter Products by Price

```bash
curl "http://localhost:3000/api/products?minPrice=100&maxPrice=500"
```

**Shows:**
- Only products between $100-$500
- Pagination info

### Test 4: Expensive Products, Sorted Ascending

```bash
curl "http://localhost:3000/api/products?minPrice=1000&sortBy=price&order=ASC&limit=5"
```

**Shows:**
- Products over $1000
- Sorted cheapest first
- 5 per page

### Test 5: Search Users by Name

```bash
curl "http://localhost:3000/api/users?search=john&role=VENDOR"
```

**Shows:**
- Users named "john" who are vendors
- Pagination info

### Test 6: Filter Orders by Status

```bash
curl "http://localhost:3000/api/orders?status=PENDING&page=1&limit=10"
```

**Shows:**
- Only pending orders
- 10 per page
- Pagination info

### Test 7: Complex Query (All Filters)

```bash
curl "http://localhost:3000/api/products?search=phone&minPrice=200&maxPrice=800&page=1&limit=10&sortBy=price&order=ASC"
```

**Shows:**
- Products with "phone" in name
- Price between $200-$800
- Sorted by price ascending
- Page 1, 10 items per page

---

## 📊 Response Format

**With Pagination:**
```json
{
  "success": true,
  "message": "Products fetched successfully",
  "data": [
    {"id": 1, "title": "Product 1", "price": 100},
    {"id": 2, "title": "Product 2", "price": 200}
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 25,
    "totalPages": 3,
    "hasMore": true
  }
}
```

**Pagination Info:**
- `page` - Current page number
- `limit` - Items per page
- `total` - Total items in database
- `totalPages` - How many pages total
- `hasMore` - Is there a next page?

---

## 💡 Use Cases

### E-commerce Store
```bash
# Show cheap products first
GET /api/products?sortBy=price&order=ASC&limit=20

# Show expensive products
GET /api/products?minPrice=500&sortBy=price&order=DESC

# Search for specific item
GET /api/products?search=iphone&page=1&limit=10
```

### Admin Dashboard
```bash
# All pending orders
GET /api/orders?status=PENDING

# All admin users
GET /api/users?role=ADMIN

# Users from page 5
GET /api/users?page=5&limit=50
```

### Customer Portal
```bash
# My orders (first 10)
GET /api/orders?page=1&limit=10

# Search in products
GET /api/products?search=laptop
```

---

## 🔧 How It Works (Behind the Scenes)

### 1. Create Query DTOs
```typescript
export class ProductFilterDto extends SearchDto {
  minPrice?: number;  // Optional min price
  maxPrice?: number;  // Optional max price
  sortBy?: 'price' | 'title' | 'newest';
  order?: 'ASC' | 'DESC';
}
```

### 2. Update Repository
```typescript
async findProductsWithFilters(filters: ProductFilterDto) {
  const query = this.createQueryBuilder('product');
  
  // Add search filter
  if (filters.search) {
    query.where('product.title ILIKE :search', {
      search: `%${filters.search}%`
    });
  }
  
  // Add price filter
  if (filters.minPrice && filters.maxPrice) {
    query.andWhere('product.price BETWEEN :min AND :max', {
      min: filters.minPrice,
      max: filters.maxPrice
    });
  }
  
  // Add pagination
  query.skip((page - 1) * limit).take(limit);
  
  // Get results
  return query.getMany();
}
```

### 3. Update Controller
```typescript
@Get()
findAll(@Query() filters: ProductFilterDto) {
  return this.productsService.findWithFilters(filters);
}
```

---

## ✨ Features

✅ **Fast Search** - Uses ILIKE for case-insensitive search
✅ **Flexible Filtering** - Optional parameters
✅ **Smart Pagination** - Shows "hasMore" flag
✅ **Type Safe** - All validated with DTOs
✅ **Reusable** - Works on all endpoints
✅ **Easy to Extend** - Add more filters easily

---

## 🚀 Next Level Features

Want to add more?

1. **Category Filtering** (if you add category to products)
2. **Date Range Filters** (orders by date)
3. **Advanced Search** (search multiple fields)
4. **Export to CSV** (pagination + export)
5. **Analytics** (pagination stats)

---

## 📚 Files Modified

- ✅ `src/common/dto/pagination.dto.ts` (NEW)
- ✅ `src/products/product.repository.ts`
- ✅ `src/products/products.service.ts`
- ✅ `src/products/products.controller.ts`
- ✅ `src/users/user.repository.ts`
- ✅ `src/users/users.service.ts`
- ✅ `src/users/users.controller.ts`
- ✅ `src/orders/order.repository.ts`
- ✅ `src/orders/orders.service.ts`
- ✅ `src/orders/orders.controller.ts`

---

## ✅ You're Ready!

Test it now:

```bash
# All products
curl http://localhost:3000/api/products

# Filtered products
curl "http://localhost:3000/api/products?search=laptop&minPrice=100&page=1&limit=10"

# Get users
curl "http://localhost:3000/api/users?search=john&role=VENDOR"

# Get orders
curl "http://localhost:3000/api/orders?status=PENDING"
```

**Phase 1 Complete!** 🎉
