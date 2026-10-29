import { useCallback, useEffect, useState } from 'react'
import AppHeader from '../components/AppHeader'
import ConfirmDialog from '../components/ConfirmDialog'
import Modal from '../components/Modal'
import ProductForm from '../components/ProductForm'
import Button from '../components/form/Button'
import { deleteProduct, listProducts } from '../api/products'
import { useAuth } from '../context/useAuth'
import type { Product } from '../types/api'
import { formatPrice } from '../utils/format'
import { getApiErrorMessage } from '../utils/api-error'
import styles from '../styles/page.module.css'
import s from './ProductsPage.module.css'

type ModalState =
  | { kind: 'closed' }
  | { kind: 'create' }
  | { kind: 'edit'; product: Product }
  | { kind: 'delete'; product: Product }

const EMPTY_STATE: ModalState = { kind: 'closed' }

export default function ProductsPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'ADMIN'

  const [products, setProducts] = useState<Product[]>([])
  const [modal, setModal] = useState<ModalState>(EMPTY_STATE)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [isLoading, setIsLoading] = useState(true)
  const [isDeleting, setIsDeleting] = useState(false)

  const load = useCallback(async () => {
    try {
      setProducts(await listProducts())
      setError('')
    } catch (err) {
      setError(getApiErrorMessage(err, 'Could not load products.'))
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

  const closeModal = useCallback(() => setModal(EMPTY_STATE), [])

  const handleSaved = useCallback(async (message: string) => {
    setNotice(message)
    setModal(EMPTY_STATE)
    await load()
  }, [load])

  const handleDelete = useCallback(
    async (product: Product) => {
      setError('')
      setNotice('')
      setIsDeleting(true)

      try {
        const response = await deleteProduct(product.id)
        setNotice(response.message)
        closeModal()
        await load()
      } catch (err) {
        setError(getApiErrorMessage(err, 'Could not delete product.'))
      } finally {
        setIsDeleting(false)
      }
    },
    [closeModal, load],
  )

  return (
    <div className={styles.page}>
      <AppHeader />
      <main className={styles.main}>
        <h1 className={styles.heading}>Products</h1>
        <p className={styles.muted}>
          {isAdmin
            ? 'Create, edit and manage the product catalog (prices in ₹).'
            : 'View-only — ask an ADMIN to create, edit or delete products.'}
        </p>

        {error && (
          <p className={s.alert} role="alert">
            {error}
          </p>
        )}
        {!error && notice && (
          <p className={s.notice} role="status">
            {notice}
          </p>
        )}

        {isAdmin && (
          <Button
            className={s.addButton}
            variant="primary"
            onClick={() => setModal({ kind: 'create' })}
            type="button"
          >
            + Add product
          </Button>
        )}

        <section className={styles.card}>
          {isLoading && <p className={styles.muted}>Loading products…</p>}

          {!isLoading && products.length === 0 && (
            <p className={styles.muted}>No products yet — add the first one.</p>
          )}

          {!isLoading && products.length > 0 && (
            <table className={s.table}>
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Category</th>
                  <th>Stock</th>
                  <th>Price</th>
                  <th>Owner</th>
                  {isAdmin && <th aria-label="Actions" />}
                </tr>
              </thead>
              <tbody>
                {products.map((product) => (
                  <tr key={product.id}>
                    <td className={s.titleCell}>
                      <span className={s.title}>{product.title}</span>
                      {product.description && (
                        <span className={s.description}>
                          {product.description}
                        </span>
                      )}
                    </td>
                    <td>{product.category ?? '—'}</td>
                    <td>{product.stock}</td>
                    <td>{formatPrice(product.price)}</td>
                    <td>
                      {product.user
                        ? `${product.user.name} (${product.user.role})`
                        : `User #${product.userId}`}
                    </td>
                    {isAdmin && (
                      <td className={s.actions}>
                        <button
                          type="button"
                          className={s.edit}
                          onClick={() => setModal({ kind: 'edit', product })}
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          className={s.delete}
                          onClick={() => setModal({ kind: 'delete', product })}
                        >
                          Delete
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </main>

      {isAdmin && (
        <>
          <Modal
            open={modal.kind === 'create'}
            title="Add product"
            onClose={closeModal}
          >
            <ProductForm
              mode="create"
              onCancel={closeModal}
              onSaved={handleSaved}
            />
          </Modal>

          <Modal
            open={modal.kind === 'edit'}
            title="Edit product"
            onClose={closeModal}
          >
            {modal.kind === 'edit' && (
              <ProductForm
                mode="edit"
                product={modal.product}
                onCancel={closeModal}
                onSaved={handleSaved}
              />
            )}
          </Modal>
        </>
      )}

      <ConfirmDialog
        open={modal.kind === 'delete'}
        title="Delete product"
        message={
          modal.kind === 'delete' ? (
            <>
              Delete <strong>“{modal.product.title}”</strong>? This action
              cannot be undone.
            </>
          ) : null
        }
        confirmLabel="Delete"
        busy={isDeleting}
        onConfirm={
          modal.kind === 'delete'
            ? () => void handleDelete(modal.product)
            : closeModal
        }
        onCancel={closeModal}
      />
    </div>
  )
}
