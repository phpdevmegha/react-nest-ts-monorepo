import type { AuthSession, AuthUser } from '../types/auth'

const TOKEN_KEY = 'syncboard.token'
const USER_KEY = 'syncboard.user'

export const EMPTY_SESSION: AuthSession = { token: null, user: null }

interface JwtPayload {
  exp?: number
}

/**
 * Reads the persisted session and drops it when the token is missing,
 * malformed, or already expired.
 */
export function readSession(): AuthSession {
  try {
    const token = sessionStorage.getItem(TOKEN_KEY)
    const rawUser = sessionStorage.getItem(USER_KEY)

    if (!token || !rawUser) {
      return EMPTY_SESSION
    }

    if (isTokenExpired(token)) {
      clearSession()
      return EMPTY_SESSION
    }

    return { token, user: JSON.parse(rawUser) as AuthUser }
  } catch {
    clearSession()
    return EMPTY_SESSION
  }
}

export function saveSession(token: string, user: AuthUser): void {
  sessionStorage.setItem(TOKEN_KEY, token)
  sessionStorage.setItem(USER_KEY, JSON.stringify(user))
}

export function clearSession(): void {
  sessionStorage.removeItem(TOKEN_KEY)
  sessionStorage.removeItem(USER_KEY)
}

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY)
}

function isTokenExpired(token: string): boolean {
  const payload = decodeJwtPayload(token)
  if (!payload?.exp) {
    return false
  }
  return payload.exp * 1000 <= Date.now()
}

function decodeJwtPayload(token: string): JwtPayload | null {
  try {
    const payload = token.split('.')[1]
    if (!payload) {
      return null
    }

    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/')
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')
    return JSON.parse(atob(padded)) as JwtPayload
  } catch {
    return null
  }
}
