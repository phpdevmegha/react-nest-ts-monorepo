import AppHeader from '../components/AppHeader'
import styles from '../styles/page.module.css'

export default function ProductsPage() {
  return (
    <div className={styles.page}>
      <AppHeader />
      <main className={styles.main}>
        <h1 className={styles.heading}>Products</h1>
        <p className={styles.muted}>This page is ready for development.</p>
      </main>
    </div>
  )
}
