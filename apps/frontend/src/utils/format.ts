import type { OrderStatus } from '../types/api'

/** Formats a decimal string/number coming from the API as Indian Rupees. */
export function formatPrice(value: string | number): string {
  const amount = typeof value === 'string' ? Number(value) : value

  return Number.isFinite(amount)
    ? new Intl.NumberFormat('en-IN', {
        style: 'currency',
        currency: 'INR',
        maximumFractionDigits: 2,
      }).format(amount)
    : '—'
}

/** Displays Postgres timestamps without machine-readable noise. */
export function formatDate(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)

  return Number.isNaN(date.getTime())
    ? '—'
    : date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      })
}

export function formatStatus(status: OrderStatus): string {
  return status.charAt(0).toUpperCase() + status.slice(1)
}
