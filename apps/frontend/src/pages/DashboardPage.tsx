import AppHeader from '../components/AppHeader'
import { useAuth } from '../context/useAuth'
import styles from '../styles/page.module.css'

export default function DashboardPage() {
  const { user } = useAuth()

  return (
    <div className={styles.page}>
      <AppHeader />
      <main className={styles.main}>
        <h1 className={styles.heading}>Welcome back{user ? `, ${user.name}` : ''}</h1>
        <p className={styles.muted}>
          Signed in as {user?.email} ({user?.role}).
        </p>

        <section className={styles.card}>
          <h2>Dashboard</h2>
          <p>Your dashboard widgets will go here.</p>
        </section>
      </main>
    </div>
  )
}
