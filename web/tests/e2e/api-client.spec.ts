import { expect, test } from '@playwright/test'
import { createControlPlaneApi } from '../../src/lib/api/client'

test('awaits and attaches provider-neutral bearer tokens', async () => {
  let headers = new Headers()
  let tokenResolved = false
  const api = createControlPlaneApi({
    baseUrl: 'https://control.example/api/v1',
    getAccessToken: async () => {
      await Promise.resolve()
      tokenResolved = true
      return 'short-lived-session-token'
    },
    fetch: async (_input, init) => {
      headers = new Headers(init?.headers)
      return new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } })
    },
  })

  await api.tenants.list()
  expect(tokenResolved).toBe(true)
  expect(headers.get('Authorization')).toBe('Bearer short-lived-session-token')
})

test('omits authorization when the adapter has no token', async () => {
  let headers = new Headers()
  const api = createControlPlaneApi({
    baseUrl: 'https://control.example/api/v1',
    getAccessToken: async () => null,
    fetch: async (_input, init) => {
      headers = new Headers(init?.headers)
      return new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } })
    },
  })

  await api.tenants.list()
  expect(headers.has('Authorization')).toBe(false)
})
