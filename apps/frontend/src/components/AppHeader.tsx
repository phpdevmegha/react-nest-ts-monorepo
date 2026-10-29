import { Link, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/useAuth'
import styles from './AppHeader.module.css'

export default function AppHeader() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate('/', { replace: true })
  }

  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    isActive ? styles.active : styles.link

  return (
    <header className={styles.header}>
      <Link to="/dashboard" className={styles.brand}>
        SyncBoard
      </Link>

      <nav className={styles.nav}>
        <NavLink to="/dashboard" end className={navLinkClass}>
          Dashboard
        </NavLink>
        <NavLink to="/products" className={navLinkClass}>
          Products
        </NavLink>
      </nav>

      <div className={styles.user}>
        {user && (
          <span className={styles.userName}>
            {user.name} · {user.role}
          </span>
        )}
        <button type="button" className={styles.logout} onClick={handleLogout}>
          Log out
        </button>
      </div>
    </header>
  )
}
