import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Check, Copy } from 'lucide-react'
import { useSessionControlPlaneApi } from '../auth/useSessionControlPlaneApi.ts'
import { Badge, Button, Panel } from '../../ui/index.ts'
import styles from './ProxySetup.module.css'

async function writeClipboardText(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    return
  } catch {
    const textarea = document.createElement('textarea')
    textarea.value = text
    textarea.style.position = 'fixed'
    textarea.style.opacity = '0'
    document.body.append(textarea)
    textarea.select()
    const copied = document.execCommand('copy')
    textarea.remove()
    if (!copied) {
      throw new Error('clipboard access is unavailable')
    }
  }
}

export function ProxySetup({ tenantName }: { tenantName?: string }) {
  const api = useSessionControlPlaneApi()
  const [tab, setTab] = useState<'docker' | 'helm' | 'kubernetes'>('docker')
  const [dockerMethod, setDockerMethod] = useState<'compose' | 'run'>('compose')
  const [publishPort, setPublishPort] = useState(false)
  const [proxyPort, setProxyPort] = useState('8080')
  const [useAdditionalCA, setUseAdditionalCA] = useState(false)
  const [copyStatus, setCopyStatus] = useState<'idle' | 'copied' | 'error'>('idle')
  const copyResetTimerRef = useRef<number | null>(null)
  const enrollmentConfiguration = useQuery({
    queryKey: ['proxy-enrollment-configuration'],
    queryFn: () => api.proxyEnrollments.configuration(),
  })
  const enrollmentURL = enrollmentConfiguration.data?.public_api_url ?? ''
  const enrollmentEndpoint = (() => {
    try {
      return new URL(enrollmentURL)
    } catch {
      return null
    }
  })()
  const portNumber = Number(proxyPort)
  const validProxyPort = Number.isInteger(portNumber) && portNumber >= 1 && portNumber <= 65535
  const validEnrollmentURL =
    enrollmentEndpoint?.protocol === 'https:' && enrollmentEndpoint.pathname.replace(/\/$/, '') !== '/api/v1'
  const requiresDockerHostGateway = enrollmentEndpoint?.hostname === 'host.docker.internal'
  const publishedProxyPort = publishPort && validProxyPort ? String(portNumber) : null
  const composeHostGateway = requiresDockerHostGateway
    ? ['    extra_hosts:', '      - "host.docker.internal:host-gateway"', ''].join('\n')
    : ''
  const dockerRunHostGateway = requiresDockerHostGateway ? '  --add-host host.docker.internal:host-gateway \\\n' : ''
  const composeAdditionalCAEnvironment = useAdditionalCA
    ? '      FIREWALL_ENROLLMENT_ADDITIONAL_CA_FILE: /etc/firewall/additional-ca.pem\n'
    : ''
  const composeAdditionalCAVolume = useAdditionalCA
    ? `    volumes:
      - "\${FIREWALL_ENROLLMENT_ADDITIONAL_CA_HOST_FILE:?Set the path to your additional CA bundle}:/etc/firewall/additional-ca.pem:ro"
`
    : ''
  const dockerRunAdditionalCA = useAdditionalCA
    ? `  -v "\${FIREWALL_ENROLLMENT_ADDITIONAL_CA_HOST_FILE:?Set the path to your additional CA bundle}:/etc/firewall/additional-ca.pem:ro" \\
  -e FIREWALL_ENROLLMENT_ADDITIONAL_CA_FILE=/etc/firewall/additional-ca.pem \\
`
    : ''
  const compose = `services:
  valkey:
    image: valkey/valkey:8-alpine

  proxy:
    image: dependency-firewall:latest
    depends_on:
      - valkey
${composeHostGateway}    environment:
      FIREWALL_RUNTIME_MODE: proxy
      FIREWALL_BUNDLE_TLS_MODE: mtls
      FIREWALL_ENROLLMENT_ENABLED: "true"
      FIREWALL_ENROLLMENT_PUBLIC_API_URL: ${enrollmentURL}
${composeAdditionalCAEnvironment}      FIREWALL_VALKEY_ADDR: valkey:6379
${
  publishedProxyPort
    ? `      FIREWALL_SERVER_PORT: "${publishedProxyPort}"
    ports:
      - "${publishedProxyPort}:${publishedProxyPort}"`
    : ''
}${composeAdditionalCAVolume}`
  const dockerRun = `docker network inspect dependency-firewall >/dev/null 2>&1 || \\
  docker network create dependency-firewall

if docker container inspect dependency-firewall-valkey >/dev/null 2>&1; then
  docker start dependency-firewall-valkey >/dev/null
else
  docker run -d --name dependency-firewall-valkey \\
    --network dependency-firewall \\
    valkey/valkey:8-alpine
fi

docker run --rm --name dependency-firewall-proxy \\
  --network dependency-firewall \\
${dockerRunHostGateway}${
    publishedProxyPort
      ? `  -p ${publishedProxyPort}:${publishedProxyPort} \\
  -e FIREWALL_SERVER_PORT=${publishedProxyPort} \\
`
      : ''
  }${dockerRunAdditionalCA}  -e FIREWALL_RUNTIME_MODE=proxy \\
  -e FIREWALL_BUNDLE_TLS_MODE=mtls \\
  -e FIREWALL_ENROLLMENT_ENABLED=true \\
  -e FIREWALL_ENROLLMENT_PUBLIC_API_URL=${enrollmentURL} \\
  -e FIREWALL_VALKEY_ADDR=dependency-firewall-valkey:6379 \\
  dependency-firewall:latest`
  const command = dockerMethod === 'compose' ? compose : dockerRun

  useEffect(() => {
    return () => {
      if (copyResetTimerRef.current !== null) {
        window.clearTimeout(copyResetTimerRef.current)
      }
    }
  }, [])

  function selectDockerMethod(method: 'compose' | 'run') {
    setDockerMethod(method)
    setCopyStatus('idle')
  }

  function setPortPublishing(checked: boolean) {
    setPublishPort(checked)
    setCopyStatus('idle')
  }

  function setPort(value: string) {
    setProxyPort(value)
    setCopyStatus('idle')
  }

  function setAdditionalCA(checked: boolean) {
    setUseAdditionalCA(checked)
    setCopyStatus('idle')
  }

  async function copyCommand() {
    try {
      await writeClipboardText(command)
      setCopyStatus('copied')
    } catch {
      setCopyStatus('error')
    }

    if (copyResetTimerRef.current !== null) {
      window.clearTimeout(copyResetTimerRef.current)
    }
    copyResetTimerRef.current = window.setTimeout(() => {
      setCopyStatus('idle')
      copyResetTimerRef.current = null
    }, 1600)
  }

  return (
    <div className={styles.setup}>
      <div className={styles.heading}>
        <div>
          <h3>Connect your proxy</h3>
          <p>Start a proxy, then approve the one-time code it prints at the activation page.</p>
        </div>
        {tenantName ? <Badge tone="neutral">{tenantName}</Badge> : null}
      </div>
      <div className={styles.tabs} role="tablist" aria-label="Installation method">
        <Button aria-selected={tab === 'docker'} onClick={() => setTab('docker')} role="tab">
          Docker
        </Button>
        <Button disabled onClick={() => setTab('helm')} role="tab">
          Helm — unavailable
        </Button>
        <Button disabled onClick={() => setTab('kubernetes')} role="tab">
          Kubernetes — unavailable
        </Button>
      </div>
      {tab === 'docker' ? (
        <Panel className={styles.command}>
          <div className={styles.dockerMethods} role="tablist" aria-label="Docker command">
            <Button aria-selected={dockerMethod === 'compose'} onClick={() => selectDockerMethod('compose')} role="tab">
              Docker Compose
            </Button>
            <Button aria-selected={dockerMethod === 'run'} onClick={() => selectDockerMethod('run')} role="tab">
              Docker run
            </Button>
          </div>
          <div className={styles.portControls}>
            {enrollmentConfiguration.isPending ? <span>Loading control-plane address…</span> : null}
            {enrollmentConfiguration.isError ? (
              <small className={styles.configurationError}>Proxy setup is unavailable.</small>
            ) : null}
            <label className={styles.portOption}>
              <input
                checked={publishPort}
                onChange={(event) => setPortPublishing(event.target.checked)}
                type="checkbox"
              />
              <span>Publish proxy port</span>
            </label>
            {publishPort ? (
              <div className={styles.portField}>
                <label className={styles.portInput}>
                  <span>Proxy port</span>
                  <input
                    aria-invalid={!validProxyPort}
                    aria-describedby={!validProxyPort ? 'proxy-port-error' : undefined}
                    inputMode="numeric"
                    max={65535}
                    min={1}
                    onChange={(event) => setPort(event.target.value)}
                    step={1}
                    type="number"
                    value={proxyPort}
                  />
                </label>
                {!validProxyPort ? <small id="proxy-port-error">Enter a port from 1 to 65535.</small> : null}
              </div>
            ) : null}
            <label className={styles.portOption}>
              <input
                checked={useAdditionalCA}
                onChange={(event) => setAdditionalCA(event.target.checked)}
                type="checkbox"
              />
              <span>Use an additional CA bundle</span>
            </label>
          </div>
          <pre className={styles.codeBlock}>
            <Button
              aria-label={
                copyStatus === 'copied'
                  ? `${dockerMethod === 'compose' ? 'Docker Compose' : 'Docker run'} commands copied`
                  : `Copy ${dockerMethod === 'compose' ? 'Docker Compose' : 'Docker run'} commands`
              }
              className={styles.copyButton}
              disabled={!validEnrollmentURL || (publishPort && !validProxyPort)}
              onClick={() => void copyCommand()}
              title="Copy commands"
            >
              <span className={copyStatus === 'copied' ? styles.copySuccessIcon : styles.copyIcon}>
                {copyStatus === 'copied' ? (
                  <Check aria-hidden="true" size={16} strokeWidth={2.2} />
                ) : (
                  <Copy aria-hidden="true" size={16} strokeWidth={1.8} />
                )}
              </span>
            </Button>
            <code>{command}</code>
          </pre>
          <span aria-live="polite" className={styles.copyStatus}>
            {copyStatus === 'copied' ? 'Copied.' : copyStatus === 'error' ? 'Unable to copy.' : null}
          </span>
        </Panel>
      ) : null}
    </div>
  )
}
