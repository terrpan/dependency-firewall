export class ApiError extends Error {
  readonly status: number
  readonly statusText: string
  readonly url: string
  readonly body: unknown

  constructor(options: {
    message: string
    status: number
    statusText: string
    url: string
    body?: unknown
    cause?: unknown
  }) {
    super(options.message, { cause: options.cause })
    this.name = 'ApiError'
    this.status = options.status
    this.statusText = options.statusText
    this.url = options.url
    this.body = options.body
  }
}

type ErrorPayload = {
  error?: string
  message?: string
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError
}

export function getErrorMessage(body: unknown, fallback: string): string {
  if (typeof body === 'string') {
    const trimmed = body.trim()
    return trimmed || fallback
  }

  if (body && typeof body === 'object') {
    const payload = body as ErrorPayload

    if (typeof payload.error === 'string' && payload.error.trim()) {
      return payload.error.trim()
    }

    if (typeof payload.message === 'string' && payload.message.trim()) {
      return payload.message.trim()
    }
  }

  return fallback
}
