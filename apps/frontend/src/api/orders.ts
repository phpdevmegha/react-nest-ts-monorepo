import { api } from './client'
import type { ApiResponse, Order } from '../types/api'

export async function listOrders(): Promise<Order[]> {
  const { data } = await api.get<ApiResponse<Order[]>>('/orders')
  return data.data ?? []
}
