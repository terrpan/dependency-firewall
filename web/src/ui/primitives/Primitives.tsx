import { forwardRef, type ButtonHTMLAttributes, type HTMLAttributes, type InputHTMLAttributes, type LabelHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from 'react'
import styles from './Primitives.module.css'

export type ButtonVariant = 'default' | 'primary' | 'danger'
export const Button = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }>(function Button({ className, variant = 'default', type = 'button', ...props }, ref) {
  return <button ref={ref} type={type} data-variant={variant} className={[styles.button, className].filter(Boolean).join(' ')} {...props} />
})
export const IconButton = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement> & { label: string }>(function IconButton({ className, label, ...props }, ref) {
  return <Button ref={ref} aria-label={label} title={label} className={[styles.iconButton, className].filter(Boolean).join(' ')} {...props} />
})
export function Badge({ tone = 'neutral', ...props }: HTMLAttributes<HTMLSpanElement> & { tone?: 'neutral' | 'success' | 'warning' | 'danger' }) { return <span data-tone={tone} className={styles.badge} {...props} /> }
export function Panel({ padding = 'md', ...props }: HTMLAttributes<HTMLElement> & { padding?: 'none' | 'sm' | 'md' | 'lg' }) { return <section data-padding={padding} className={[styles.panel, props.className].filter(Boolean).join(' ')} {...props} /> }
export function Field({ label, hint, children, ...props }: LabelHTMLAttributes<HTMLLabelElement> & { label: ReactNode; hint?: ReactNode }) { return <label className={styles.field} {...props}><span>{label}</span>{children}{hint ? <span className={styles.hint}>{hint}</span> : null}</label> }
export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input(props, ref) { return <input ref={ref} className={[styles.control, props.className].filter(Boolean).join(' ')} {...props} /> })
export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select(props, ref) { return <select ref={ref} className={[styles.control, props.className].filter(Boolean).join(' ')} {...props} /> })
export function Checkbox({ label, ...props }: InputHTMLAttributes<HTMLInputElement> & { label: ReactNode }) { return <label className={styles.checkbox}><input type="checkbox" {...props} /><span>{label}</span></label> }
export function Tabs({ tabs, active, onChange, label }: { tabs: readonly { id: string; label: string }[]; active: string; onChange: (id: string) => void; label: string }) { return <div className={styles.tabs} role="tablist" aria-label={label}>{tabs.map(tab => <button className={styles.tab} role="tab" aria-selected={tab.id === active} key={tab.id} onClick={() => onChange(tab.id)} type="button">{tab.label}</button>)}</div> }
export function Tooltip({ label, children }: { label: string; children: ReactNode }) { return <span title={label}>{children}</span> }
export function Dialog({ open, onClose, children, label }: { open: boolean; onClose: () => void; children: ReactNode; label: string }) { return <dialog className={styles.dialog} aria-label={label} open={open} onCancel={onClose}><div className={styles.dialogBody}>{children}</div></dialog> }
