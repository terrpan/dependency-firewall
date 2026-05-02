import type { AuthSession } from './context.ts'

export function buildSessionHeaders(session: AuthSession | null): HeadersInit | undefined {
  if (!session) {
    return undefined
  }

  const headers = new Headers(session.headers)
  let hasHeaders = false

  headers.forEach(() => {
    hasHeaders = true
  })

  const accessToken = session.accessToken?.trim()
  if (accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`)
    hasHeaders = true
  }

  return hasHeaders ? headers : undefined
}
