import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

function telemetryProxyTargetFromEnv(env: Record<string, string>) {
  if (env.VITE_OTEL_DEV_PROXY_TARGET) {
    return env.VITE_OTEL_DEV_PROXY_TARGET
  }

  const exporterUrl = env.VITE_OTEL_EXPORTER_URL
  if (!exporterUrl) {
    return 'http://localhost:4318'
  }

  try {
    const parsed = new URL(exporterUrl)
    if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
      return parsed.origin
    }
  } catch {
    // Ignore malformed exporter URLs and fall back to the default.
  }

  return 'http://localhost:4318'
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const proxyTarget = env.VITE_DEV_PROXY_TARGET || 'http://localhost:8080'
  const telemetryProxyTarget = telemetryProxyTargetFromEnv(env)

  return {
    plugins: [react()],
    server: {
      proxy: {
        '/api': {
          target: proxyTarget,
          changeOrigin: true,
        },
        '/docs': {
          target: proxyTarget,
          changeOrigin: true,
        },
        '/healthz': {
          target: proxyTarget,
          changeOrigin: true,
        },
        '/openapi.json': {
          target: proxyTarget,
          changeOrigin: true,
        },
        '/otlp': {
          target: telemetryProxyTarget,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/otlp/, ''),
        },
      },
    },
  }
})
