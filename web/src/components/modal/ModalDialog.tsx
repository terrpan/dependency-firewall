import { useEffect, useId, useRef, type ReactNode, type RefObject } from 'react'
import { createPortal } from 'react-dom'
import styles from './ModalDialog.module.css'

const focusableSelector = [
  'a[href]',
  'area[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'iframe',
  'object',
  'embed',
  '[contenteditable="true"]',
  '[tabindex]:not([tabindex="-1"])',
].join(', ')

let lockedDialogCount = 0
let savedBodyOverflow = ''
let savedBodyPaddingRight = ''

function isVisible(element: HTMLElement) {
  const computedStyle = window.getComputedStyle(element)
  return computedStyle.display !== 'none' && computedStyle.visibility !== 'hidden'
}

function getFocusableElements(container: HTMLElement) {
  return Array.from(container.querySelectorAll<HTMLElement>(focusableSelector)).filter((element) => {
    if (element.getAttribute('aria-hidden') === 'true') {
      return false
    }

    return isVisible(element)
  })
}

function lockBodyScroll() {
  if (lockedDialogCount === 0) {
    savedBodyOverflow = document.body.style.overflow
    savedBodyPaddingRight = document.body.style.paddingRight

    const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth
    document.body.style.overflow = 'hidden'
    if (scrollbarWidth > 0) {
      document.body.style.paddingRight = `${scrollbarWidth}px`
    }
  }

  lockedDialogCount += 1
}

function unlockBodyScroll() {
  lockedDialogCount = Math.max(0, lockedDialogCount - 1)

  if (lockedDialogCount > 0) {
    return
  }

  document.body.style.overflow = savedBodyOverflow
  document.body.style.paddingRight = savedBodyPaddingRight
}

export type ModalDialogSize = 'narrow' | 'regular' | 'wide' | 'full'

export type ModalDialogProps = {
  open: boolean
  title: string
  description?: string
  eyebrow?: string
  headerMeta?: ReactNode
  footer?: ReactNode
  onClose: () => void
  children: ReactNode
  size?: ModalDialogSize
  initialFocusRef?: RefObject<HTMLElement | null>
  closeLabel?: string
  closeOnOverlayClick?: boolean
  closeOnEscape?: boolean
  dismissible?: boolean
}

const sizeClassNames: Record<ModalDialogSize, string> = {
  narrow: styles.sizeNarrow,
  regular: styles.sizeRegular,
  wide: styles.sizeWide,
  full: styles.sizeFull,
}

export function ModalDialog({
  open,
  title,
  description,
  eyebrow,
  headerMeta,
  footer,
  onClose,
  children,
  size = 'regular',
  initialFocusRef,
  closeLabel = 'Close dialog',
  closeOnOverlayClick = true,
  closeOnEscape = true,
  dismissible = true,
}: ModalDialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null)
  const restoreFocusRef = useRef<HTMLElement | null>(null)
  const titleId = useId()
  const descriptionId = useId()

  useEffect(() => {
    if (!open || typeof document === 'undefined') {
      return
    }

    restoreFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null

    lockBodyScroll()

    const focusFrame = window.requestAnimationFrame(() => {
      const dialog = dialogRef.current
      if (!dialog) {
        return
      }

      const nextFocusTarget = initialFocusRef?.current ?? getFocusableElements(dialog)[0] ?? dialog
      nextFocusTarget.focus()
    })

    return () => {
      window.cancelAnimationFrame(focusFrame)
      unlockBodyScroll()

      const restoreFocusTarget = restoreFocusRef.current
      if (restoreFocusTarget?.isConnected) {
        restoreFocusTarget.focus()
      }
      restoreFocusRef.current = null
    }
  }, [initialFocusRef, open])

  useEffect(() => {
    if (!open || typeof document === 'undefined') {
      return
    }

    function handleKeyDown(event: KeyboardEvent) {
      const dialog = dialogRef.current
      if (!dialog) {
        return
      }

      if (event.key === 'Escape' && dismissible && closeOnEscape) {
        event.preventDefault()
        onClose()
        return
      }

      if (event.key !== 'Tab') {
        return
      }

      const focusableElements = getFocusableElements(dialog)
      if (focusableElements.length === 0) {
        event.preventDefault()
        dialog.focus()
        return
      }

      const firstElement = focusableElements[0]
      const lastElement = focusableElements[focusableElements.length - 1]
      const activeElement = document.activeElement

      if (event.shiftKey && (activeElement === firstElement || activeElement === dialog)) {
        event.preventDefault()
        lastElement.focus()
        return
      }

      if (!event.shiftKey && activeElement === lastElement) {
        event.preventDefault()
        firstElement.focus()
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [closeOnEscape, dismissible, onClose, open])

  if (!open || typeof document === 'undefined') {
    return null
  }

  return createPortal(
    <div
      aria-label="Close dialog"
      className={styles.overlay}
      onClick={(event) => {
        if (!dismissible || !closeOnOverlayClick || event.target !== event.currentTarget) {
          return
        }

        onClose()
      }}
      onKeyDown={(event) => {
        if (!dismissible || !closeOnOverlayClick) {
          return
        }
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault()
          onClose()
        }
      }}
      role="button"
      tabIndex={0}
    >
      <div
        aria-describedby={description ? descriptionId : undefined}
        aria-labelledby={titleId}
        aria-modal="true"
        className={`${styles.dialog} ${sizeClassNames[size]}`}
        ref={dialogRef}
        role="dialog"
        tabIndex={-1}
      >
        <header className={styles.header}>
          <div className={styles.headerCopy}>
            {eyebrow ? <p className={styles.eyebrow}>{eyebrow}</p> : null}
            <div className={styles.titleRow}>
              <div className={styles.titleBlock}>
                <h2 className={styles.title} id={titleId}>
                  {title}
                </h2>
                {description ? (
                  <p className={styles.description} id={descriptionId}>
                    {description}
                  </p>
                ) : null}
              </div>
              {headerMeta ? <div className={styles.headerMeta}>{headerMeta}</div> : null}
            </div>
          </div>
          {dismissible ? (
            <button aria-label={closeLabel} className={styles.closeButton} onClick={onClose} type="button">
              ×
            </button>
          ) : null}
        </header>

        <div className={styles.body}>{children}</div>

        {footer ? <footer className={styles.footer}>{footer}</footer> : null}
      </div>
    </div>,
    document.body,
  )
}
