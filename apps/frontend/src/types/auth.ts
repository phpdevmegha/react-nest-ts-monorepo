export type UserRole = 'ADMIN' | 'MANAGER' | 'VENDOR'

export interface AuthUser {
  id: number
  name: string
  email: string
  role: UserRole
}

export interface LoginResponse {
  message: string
  token: string
  user: AuthUser
}

export interface AuthSession {
  token: string | null
  user: AuthUser | null
}

export interface AuthContextValue extends AuthSession {
  isAuthenticated: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => void
}
