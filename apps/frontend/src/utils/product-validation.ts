/**
 * Frontend copies of the backend product validation rules
 * (apps/backend/src/products/dto). Keep the two in sync.
 */

export interface ProductFormValues {
  title: string
  price: string
  description: string
  category: string
  stock: string
}

export type ProductFormErrors = Partial<Record<keyof ProductFormValues, string>>

export const MAX_TITLE = 255
export const MAX_DESCRIPTION = 1000
export const MAX_CATEGORY = 100
export const MAX_STOCK = 1_000_000

/** Positive number, max 2 decimals — plain text must be checked by hand. */
const PRICE_PATTERN = /^\d+(\.\d{1,2})?$/
const STOCK_PATTERN = /^\d+$/

function validators(
  values: ProductFormValues,
): Array<[keyof ProductFormErrors, () => string | undefined]> {
  return [
    [
      'title',
      () => {
        const title = values.title.trim()
        if (!title) return 'Title is required'
        if (title.length < 3) return 'Title must be at least 3 characters long'
        if (title.length > MAX_TITLE) return `Title cannot exceed ${MAX_TITLE} characters`
        return undefined
      },
    ],
    [
      'price',
      () => {
        const price = values.price.trim()
        if (!price) return 'Price is required'
        if (!PRICE_PATTERN.test(price)) {
          return 'Enter a valid price in ₹, up to 2 decimals (e.g. 499.99)'
        }
        if (Number(price) <= 0) return 'Price must be greater than 0'
        return undefined
      },
    ],
    [
      'description',
      () => {
        const description = values.description.trim()
        if (description.length > MAX_DESCRIPTION) {
          return `Description cannot exceed ${MAX_DESCRIPTION} characters`
        }
        return undefined
      },
    ],
    [
      'category',
      () => {
        const category = values.category.trim()
        if (category.length > MAX_CATEGORY) {
          return `Category cannot exceed ${MAX_CATEGORY} characters`
        }
        return undefined
      },
    ],
    [
      'stock',
      () => {
        const stock = values.stock.trim()
        if (!stock) return undefined // empty keeps the backend default (0)
        if (!STOCK_PATTERN.test(stock)) return 'Stock must be a whole number'
        if (Number(stock) > MAX_STOCK) return `Stock cannot exceed ${MAX_STOCK}`
        return undefined
      },
    ],
  ]
}

/** Validates every field; used on submit and to clear single-field errors. */
export function validateProductForm(
  values: ProductFormValues,
): ProductFormErrors {
  const errors: ProductFormErrors = {}

  for (const [field, validate] of validators(values)) {
    const message = validate()
    if (message) {
      errors[field] = message
    }
  }

  return errors
}

/** Maps form values to the API payload (price → number, blank strings dropped). */
export function toProductPayload(values: ProductFormValues): {
  title: string
  price: number
  description?: string
  category?: string
  stock?: number
} {
  const payload: ReturnType<typeof toProductPayload> = {
    title: values.title.trim(),
    price: Number(values.price.trim()),
  }

  const description = values.description.trim()
  const category = values.category.trim()
  const stock = values.stock.trim()

  if (description) payload.description = description
  if (category) payload.category = category
  if (stock) payload.stock = Number(stock)

  return payload
}
