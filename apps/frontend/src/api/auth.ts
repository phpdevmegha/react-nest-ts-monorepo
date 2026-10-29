import { api } from './client'
import type { LoginResponse } from '../types/auth'

export async function loginRequest(
  email: string,
  password: string,
): Promise<LoginResponse> {
  const { data } = await api.post<LoginResponse>('/auth/login', {
    email,
    password,
  })

  return data
}
