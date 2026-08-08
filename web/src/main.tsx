import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource/ibm-plex-sans/400.css'
import '@fontsource/ibm-plex-sans/500.css'
import '@fontsource/ibm-plex-sans/600.css'
import '@fontsource/ibm-plex-mono/400.css'
import './ui/foundation/tokens.css'
import './ui/foundation/reset.css'
import './index.css'
import App from './App.tsx'
import { telemetryEnabled } from './lib/config.ts'

async function initializeConfiguredTelemetry() {
  if (!telemetryEnabled) {
    return
  }

  const { initializeTelemetry } = await import('./lib/telemetryRuntime.ts')
  initializeTelemetry()
}

void initializeConfiguredTelemetry()
  .catch((error: unknown) => {
    console.error('Unable to initialize telemetry', error)
  })
  .finally(() => {
    createRoot(document.getElementById('root')!).render(
      <StrictMode>
        <App />
      </StrictMode>,
    )
  })
