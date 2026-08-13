import { forwardRef, type ButtonHTMLAttributes, type HTMLAttributes, type InputHTMLAttributes, type LabelHTMLAttributes, type ReactNode } from 'react'
import styles from './Primitives.module.css'

export type ButtonVariant = 'default' | 'primary' | 'danger'
export const Button = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }>(function Button({ className, variant = 'default', type = 'button', ...props }, ref) {
  return <button ref={ref} type={type} data-variant={variant} className={[styles.button, className].filter(Boolean).join(' ')} {...props} />
})
export function Badge({ tone = 'neutral', ...props }: HTMLAttributes<HTMLSpanElement> & { tone?: 'neutral' | 'success' | 'warning' | 'danger' }) { return <span data-tone={tone} className={styles.badge} {...props} /> }
export function Panel({ padding = 'md', ...props }: HTMLAttributes<HTMLElement> & { padding?: 'none' | 'sm' | 'md' | 'lg' }) { return <section data-padding={padding} className={[styles.panel, props.className].filter(Boolean).join(' ')} {...props} /> }
export function Field({ label, hint, children, ...props }: LabelHTMLAttributes<HTMLLabelElement> & { label: ReactNode; hint?: ReactNode }) { return <label className={styles.field} {...props}><span>{label}</span>{children}{hint ? <span className={styles.hint}>{hint}</span> : null}</label> }
export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input(props, ref) { return <input ref={ref} className={[styles.control, props.className].filter(Boolean).join(' ')} {...props} /> })
