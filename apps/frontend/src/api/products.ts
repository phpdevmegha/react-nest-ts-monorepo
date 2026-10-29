import { api } from './client'
import type { ApiResponse, Product } from '../types/api'

export interface CreateProductPayload {
  title: string
  price: number
  description?: string
  category?: string
  stock?: number
}

export type UpdateProductPayload = Partial<CreateProductPayload>

export async function listProducts(): Promise<Product[]> {
  const { data } = await api.get<ApiResponse<Product[]>>('/products')
  return data.data ?? []
}

export async function createProduct(
  payload: CreateProductPayload,
): Promise<ApiResponse<Product>> {
  const { data: body } = await api.post<ApiResponse<Product>>(
    '/products',
    payload,
  )
  return body
}

export async function deleteProduct(id: number): Promise<ApiResponse<Product>> {
  const { data: body } = await api.delete<ApiResponse<Product>>(
    `/products/${id}`,
  )
  return body
}

export async function updateProduct(
  id: number,
  payload: UpdateProductPayload,
): Promise<ApiResponse<Product>> {
  const { data: body } = await api.patch<ApiResponse<Product>>(
    `/products/${id}`,
    payload,
  )
  return body
}
