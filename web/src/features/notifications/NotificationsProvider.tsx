import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type PropsWithChildren,
} from 'react'
import {
  type Notification,
  type NotificationInput,
  NotificationsContext,
  type NotificationsContextValue,
} from './context.ts'

const notificationLifetimeMs = 4_000
const notificationLimit = 4

function createNotificationID() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }

  return `${Date.now()}-${Math.random().toString(16).slice(2)}`
}

export function NotificationsProvider({ children }: PropsWithChildren) {
  const [notifications, setNotifications] = useState<Notification[]>([])
  const timersRef = useRef(new Map<string, number>())

  const dismiss = useCallback((id: string) => {
    const timer = timersRef.current.get(id)
    if (timer !== undefined) {
      window.clearTimeout(timer)
      timersRef.current.delete(id)
    }

    setNotifications((currentNotifications) =>
      currentNotifications.filter((notification) => notification.id !== id),
    )
  }, [])

  const notify = useCallback(
    ({ title, description, tone = 'info' }: NotificationInput) => {
      const id = createNotificationID()
      setNotifications((currentNotifications) =>
        [...currentNotifications, { id, title, description, tone }].slice(-notificationLimit),
      )

      const timer = window.setTimeout(() => {
        dismiss(id)
      }, notificationLifetimeMs)
      timersRef.current.set(id, timer)
    },
    [dismiss],
  )

  useEffect(
    () => () => {
      for (const timer of timersRef.current.values()) {
        window.clearTimeout(timer)
      }
      timersRef.current.clear()
    },
    [],
  )

  const value = useMemo<NotificationsContextValue>(
    () => ({
      notify,
      notifySuccess: (title, description) => notify({ title, description, tone: 'success' }),
      notifyError: (title, description) => notify({ title, description, tone: 'error' }),
      notifyInfo: (title, description) => notify({ title, description, tone: 'info' }),
      dismiss,
    }),
    [dismiss, notify],
  )

  return (
    <NotificationsContext.Provider value={value}>
      {children}
      <div className="toast-stack" aria-atomic="true" aria-live="polite">
        {notifications.map((notification) => (
          <section
            key={notification.id}
            className={`toast toast-${notification.tone}`}
            role={notification.tone === 'error' ? 'alert' : 'status'}
          >
            <div className="toast-body">
              <strong>{notification.title}</strong>
              {notification.description ? <p>{notification.description}</p> : null}
            </div>
            <button
              className="toast-dismiss"
              onClick={() => dismiss(notification.id)}
              type="button"
            >
              Dismiss
            </button>
          </section>
        ))}
      </div>
    </NotificationsContext.Provider>
  )
}
