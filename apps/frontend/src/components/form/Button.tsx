import type { ButtonHTMLAttributes } from 'react'
import styles from './Button.module.css'

type Variant = 'primary' | 'secondary' | 'danger'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  busy?: boolean
}

export default function Button({
  variant = 'primary',
  busy = false,
  children,
  disabled,
  className,
  ...rest
}: ButtonProps) {
  // Merge the variant styling with any caller-provided className (e.g. layout
  // classes like margin) instead of letting the spread overwrite the variant.
  const classes = [styles[variant], className].filter(Boolean).join(' ')

  return (
    <button
      type={rest.type ?? 'button'}
      className={classes}
      disabled={disabled || busy}
      {...rest}
    >
      {busy ? 'Working…' : children}
    </button>
  )
}
