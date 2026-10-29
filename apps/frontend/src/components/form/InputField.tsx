import { useId } from 'react'
import type {
  ReactNode,
  TextareaHTMLAttributes,
  InputHTMLAttributes,
} from 'react'
import styles from './InputField.module.css'

interface BaseProps {
  label: string
  error?: string
  hint?: string
}

export function TextInputField({
  label,
  error,
  hint,
  ...input
}: BaseProps & InputHTMLAttributes<HTMLInputElement>) {
  const id = useId()
  const hintId = `${id}-hint`
  const errorId = `${id}-error`

  return (
    <div className={styles.field}>
      <FieldLabel label={label} htmlFor={id} error={error} />
      <input
        id={id}
        className={error ? `${styles.input} ${styles.invalid}` : styles.input}
        aria-invalid={Boolean(error)}
        aria-describedby={
          (error ? errorId : undefined) ?? (hint ? hintId : undefined)
        }
        {...input}
      />
      <FieldHint hint={hint} hintId={hintId} error={error} errorId={errorId} />
    </div>
  )
}

export function TextAreaField({
  label,
  error,
  hint,
  ...textarea
}: BaseProps & TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const id = useId()
  const hintId = `${id}-hint`
  const errorId = `${id}-error`

  return (
    <div className={styles.field}>
      <FieldLabel label={label} htmlFor={id} error={error} />
      <textarea
        id={id}
        className={error ? `${styles.input} ${styles.invalid}` : styles.input}
        aria-invalid={Boolean(error)}
        aria-describedby={
          (error ? errorId : undefined) ?? (hint ? hintId : undefined)
        }
        {...textarea}
      />
      <FieldHint hint={hint} hintId={hintId} error={error} errorId={errorId} />
    </div>
  )
}

function FieldLabel({
  label,
  htmlFor,
  error,
}: {
  label: string
  htmlFor: string
  error?: string
}) {
  return (
    <label className={`${styles.label} ${error ? styles.labelError : ''}`} htmlFor={htmlFor}>
      {label}
    </label>
  )
}

function FieldHint({
  hint,
  hintId,
  error,
  errorId,
}: {
  hint?: string
  hintId: string
  error?: string
  errorId: string
}): ReactNode {
  if (error) {
    return (
      <span id={errorId} className={styles.error} role="alert">
        {error}
      </span>
    )
  }
  if (hint) {
    return (
      <span id={hintId} className={styles.hint}>
        {hint}
      </span>
    )
  }
  return null
}
