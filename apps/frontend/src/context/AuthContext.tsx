import { useCallback, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { loginRequest } from '../api/auth'
import type { AuthContextValue, AuthSession } from '../types/auth'
import {
  clearSession,
  EMPTY_SESSION,
  readSession,
  saveSession,
} from '../utils/auth-storage'
import { AuthContext } from './auth-context'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AuthSession>(readSession)

  const login = useCallback(async (email: string, password: string) => {
    const { token, user } = await loginRequest(email, password)
    saveSession(token, user)
    setSession({ token, user })
  }, [])

  const logout = useCallback(() => {
    clearSession()
    setSession(EMPTY_SESSION)
  }, [])

  const value = useMemo<AuthContextValue>(
    () => ({
      ...session,
      isAuthenticated: Boolean(session.token && session.user),
      login,
      logout,
    }),
    [session, login, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
