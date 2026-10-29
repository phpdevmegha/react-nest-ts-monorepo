/**
 * Contracts matching the NestJS backend responses (see docs/backend/API_USAGE.md).
 * Every list endpoint wraps payloads in `ApiResponse` / `PaginatedResponse`.
 */

export interface ApiResponse<T> {
  success: boolean
  message: string
  data?: T | null
}

export interface Pagination {
  page: number
  limit: number
  total: number
  totalPages: number
  hasMore: boolean
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  data: T[]
  pagination: Pagination
}

export type UserRole = 'ADMIN' | 'MANAGER' | 'VENDOR'

/** Safe subset of a user the backend exposes in related data (never a password). */
export interface OwnerUser {
  id: number
  name: string
  email: string
  role: UserRole
}

/** Postgres `decimal` values arrive as strings. */
export interface Product {
  id: number
  title: string
  price: string
  description?: string | null
  category?: string | null
  stock: number
  userId: number
  user?: OwnerUser | null
}

export type OrderStatus =
  | 'pending'
  | 'confirmed'
  | 'shipped'
  | 'delivered'
  | 'cancelled'

export interface Order {
  id: number
  orderNumber: string
  totalPrice: string | number
  status: OrderStatus
  createdAt: string
  paidAt: string | null
  user?: OwnerUser | null
  products?: Product[]
}
