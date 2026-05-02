import { createContext } from 'react'

export type NotificationTone = 'success' | 'error' | 'info'

export type Notification = {
  id: string
  title: string
  description?: string
  tone: NotificationTone
}

export type NotificationInput = {
  title: string
  description?: string
  tone?: NotificationTone
}

export type NotificationsContextValue = {
  notify: (input: NotificationInput) => void
  notifySuccess: (title: string, description?: string) => void
  notifyError: (title: string, description?: string) => void
  notifyInfo: (title: string, description?: string) => void
  dismiss: (id: string) => void
}

export const NotificationsContext = createContext<NotificationsContextValue | null>(null)
