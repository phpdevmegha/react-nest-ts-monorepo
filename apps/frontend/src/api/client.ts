import axios from 'axios'
import { clearSession, getToken } from '../utils/auth-storage'

/**
 * Shared axios instance.
 *
 * In development VITE_API_URL defaults to `/api`, which Vite proxies to
 * http://localhost:3000 (see vite.config.ts).
 */
export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? '/api',
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  const token = getToken()

  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }

  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    // An expired/invalid token must not leave the app in a fake logged-in state.
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      clearSession()

      if (window.location.pathname !== '/') {
        window.location.assign('/')
      }
    }

    return Promise.reject(error)
  },
)
