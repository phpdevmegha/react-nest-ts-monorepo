import { useCallback, useEffect, useState } from 'react'
import AppHeader from '../components/AppHeader'
import { listOrders } from '../api/orders'
import { listProducts } from '../api/products'
import { useAuth } from '../context/useAuth'
import type { Order, Product } from '../types/api'
import { formatDate, formatPrice, formatStatus } from '../utils/format'
import { getApiErrorMessage } from '../utils/api-error'
import styles from '../styles/page.module.css'
import s from './DashboardPage.module.css'

interface DashboardStats {
  products: Product[]
  orders: Order[]
}

export default function DashboardPage() {
  const { user } = useAuth()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const [products, orders] = await Promise.all([
        listProducts(),
        listOrders(),
      ])
      setStats({ products, orders })
      setError('')
    } catch (err) {
      setError(getApiErrorMessage(err, 'Could not load dashboard data.'))
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    // Data fetching on mount is a legitimate effect usage here: the state is
    // written asynchronously from the API response, not derived from props.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load()
  }, [load])

  const productCount = stats?.products.length ?? 0
  const orderCount = stats?.orders.length ?? 0
  const inventoryValue = (stats?.products ?? []).reduce(
    (sum, product) => sum + Number(product.price),
    0,
  )
  const recentOrders = (stats?.orders ?? [])
    .slice()
    .sort(
      (a, b) =>
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    )
    .slice(0, 5)

  return (
    <div className={styles.page}>
      <AppHeader />
      <main className={styles.main}>
        <h1 className={styles.heading}>
          Welcome{user ? `, ${user.name}` : ''} 👋
        </h1>
        <p className={styles.muted}>Live data from the SyncBoard API.</p>

        {error && (
          <div className={s.error} role="alert">
            <p>{error}</p>
            <button type="button" onClick={() => void load()}>
              Retry
            </button>
          </div>        )}

        {isLoading && <p className={styles.muted}>Loading dashboard…</p>}

        {stats && !isLoading && (
          <>
            <section className={s.cards}>
              <article className={s.card} style={{ color: '#6d28d9' }}>
                <span className={s.value}>{productCount}</span>
                <span className={s.label}>Total Products</span>
              </article>
              <article className={s.card} style={{ color: '#0891b2' }}>
                <span className={s.value}>{orderCount}</span>
                <span className={s.label}>Total Orders</span>
              </article>
              <article className={s.card} style={{ color: '#b45309' }}>
                <span className={s.value}>{formatPrice(inventoryValue)}</span>
                <span className={s.label}>Inventory Value</span>
              </article>
            </section>

            <section className={styles.card}>
              <h2>Recent orders</h2>
              {recentOrders.length === 0 ? (
                <p className={styles.muted}>No orders yet.</p>
              ) : (
                <table className={s.table}>
                  <thead>
                    <tr>
                      <th>Order</th>
                      <th>Customer</th>
                      <th>Status</th>
                      <th>Total</th>
                      <th>Date</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentOrders.map((order) => (
                      <tr key={order.id}>
                        <td>{order.orderNumber}</td>
                        <td>{order.user?.name ?? '—'}</td>
                        <td>
                          <span className={`${s.badge} ${s[order.status]}`}>
                            {formatStatus(order.status)}
                          </span>
                        </td>
                        <td>{formatPrice(order.totalPrice)}</td>
                        <td>{formatDate(order.createdAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
          </>
        )}
      </main>
    </div>
  )
}
