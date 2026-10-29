import { useState } from 'react'
import type { FormEvent } from 'react'
import { createProduct, updateProduct } from '../api/products'
import Button from './form/Button'
import { TextAreaField, TextInputField } from './form/InputField'
import type { Product } from '../types/api'
import {
  MAX_DESCRIPTION,
  MAX_TITLE,
  MAX_CATEGORY,
  type ProductFormErrors,
  type ProductFormValues,
  toProductPayload,
  validateProductForm,
} from '../utils/product-validation'
import { getApiErrorMessage } from '../utils/api-error'
import styles from './ProductForm.module.css'

export interface ProductFormProps {
  mode: 'create' | 'edit'
  product?: Product
  onCancel: () => void
  /** Called after a successful create/update; receives the API message. */
  onSaved: (message: string) => void | Promise<void>
}

function initialValues(product?: Product): ProductFormValues {
  return {
    title: product?.title ?? '',
    price: product ? String(product.price) : '',
    description: product?.description ?? '',
    category: product?.category ?? '',
    stock: product ? String(product.stock) : '',
  }
}

/**
 * One form for both creating and editing a product (mode prop).
 * Validation mirrors apps/backend/src/products/dto/create-product.dto.ts.
 */
export default function ProductForm({
  mode,
  product,
  onCancel,
  onSaved,
}: ProductFormProps) {
  const [values, setValues] = useState<ProductFormValues>(() =>
    initialValues(product),
  )
  const [errors, setErrors] = useState<ProductFormErrors>({})
  const [apiError, setApiError] = useState('')
  const [busy, setBusy] = useState(false)

  const setField =
    (field: keyof ProductFormValues) =>
    (event: { target: { value: string } }) => {
      const next = { ...values, [field]: event.target.value }
      setValues(next)
      // Re-validate just this field so errors clear as the user fixes them.
      const single = validateProductForm(next)[field]
      setErrors((prev) => ({ ...prev, [field]: single }))
    }

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setApiError('')

    const nextErrors = validateProductForm(values)
    setErrors(nextErrors)
    if (Object.keys(nextErrors).length > 0) {
      return
    }

    setBusy(true)
    try {
      const payload = toProductPayload(values)

      const response =
        mode === 'edit' && product
          ? await updateProduct(product.id, payload)
          : await createProduct(payload)

      await onSaved(response.message)
    } catch (err) {
      setApiError(
        getApiErrorMessage(err, 'Could not save the product. Try again.'),
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className={styles.form} onSubmit={handleSubmit} noValidate>
      {apiError && (
        <p className={styles.apiError} role="alert">
          {apiError}
        </p>
      )}

      <TextInputField
        label="Title"
        value={values.title}
        onChange={setField('title')}
        error={errors.title}
        hint="3–255 characters"
        maxLength={MAX_TITLE}
        required
      />

      <TextInputField
        label="Price (₹)"
        type="text"
        inputMode="decimal"
        value={values.price}
        onChange={setField('price')}
        error={errors.price}
        hint="Positive number, up to 2 decimals — shown as ₹ across the app"
        required
      />

      <TextAreaField
        label="Description"
        value={values.description}
        onChange={setField('description')}
        error={errors.description}
        hint="Optional"
        rows={3}
        maxLength={MAX_DESCRIPTION}
      />

      <TextInputField
        label="Category"
        type="text"
        value={values.category}
        onChange={setField('category')}
        error={errors.category}
        hint="Optional, e.g. Electronics"
        maxLength={MAX_CATEGORY}
      />

      <TextInputField
        label="Stock"
        type="text"
        inputMode="numeric"
        value={values.stock}
        onChange={setField('stock')}
        error={errors.stock}
        hint="Whole number — leave empty for 0"
      />

      <div className={styles.actions}>
        <Button type="button" variant="secondary" onClick={onCancel} busy={busy}>
          Cancel
        </Button>
        <Button type="submit" busy={busy}>
          {mode === 'edit' ? 'Save changes' : 'Add product'}
        </Button>
      </div>
    </form>
  )
}
