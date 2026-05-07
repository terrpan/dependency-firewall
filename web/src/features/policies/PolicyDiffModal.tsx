// PolicyDiffModal renders retained-version comparisons for policy definitions.
import { ModalDialog } from '../../components/modal/index.ts'
import type { TypedPolicy, TypedPolicyVersion } from '../../lib/api/index.ts'
import type { PolicyDiffLine } from './policyDiff.ts'

type PreviewFormat = 'json' | 'yaml'

type PolicyDiffModalProps = {
  currentPolicy: TypedPolicy | null
  comparisonVersion: TypedPolicyVersion | null
  diffFormat: PreviewFormat
  diffLines: readonly PolicyDiffLine[]
  hasChanges: boolean
  onClose: () => void
  onFormatChange: (format: PreviewFormat) => void
}

export function PolicyDiffModal({
  currentPolicy,
  comparisonVersion,
  diffFormat,
  diffLines,
  hasChanges,
  onClose,
  onFormatChange,
}: PolicyDiffModalProps) {
  return (
    <ModalDialog
      closeLabel="Close policy diff"
      description={
        currentPolicy && comparisonVersion
          ? `Compare retained version ${comparisonVersion.version} against current version ${currentPolicy.version} in JSON or YAML.`
          : undefined
      }
      eyebrow="Policy diff"
      headerMeta={
        currentPolicy && comparisonVersion ? (
          <>
            <span className="status-pill status-pill-neutral">Current v{currentPolicy.version}</span>
            <span className="status-pill status-pill-neutral">Compare v{comparisonVersion.version}</span>
          </>
        ) : null
      }
      onClose={onClose}
      open={Boolean(currentPolicy && comparisonVersion)}
      size="wide"
      title={comparisonVersion ? `Version ${comparisonVersion.version} vs current` : 'Policy diff'}
    >
      {currentPolicy && comparisonVersion ? (
        <div className="policy-diff-modal">
          <div className="policy-preview-header">
            <div>
              <h4>Definition changes</h4>
              <p className="muted">
                Removed lines come from the retained version. Added lines show what is in the current policy now.
              </p>
            </div>
            <div className="policy-preview-toggle" aria-label="Policy diff format">
              <button
                aria-pressed={diffFormat === 'json'}
                className={`policy-preview-toggle-button${diffFormat === 'json' ? ' active' : ''}`}
                onClick={() => onFormatChange('json')}
                type="button"
              >
                JSON
              </button>
              <button
                aria-pressed={diffFormat === 'yaml'}
                className={`policy-preview-toggle-button${diffFormat === 'yaml' ? ' active' : ''}`}
                onClick={() => onFormatChange('yaml')}
                type="button"
              >
                YAML
              </button>
            </div>
          </div>

          <div className="policy-diff-summary">
            <span className="policy-badge policy-badge-muted">Retained version {comparisonVersion.version}</span>
            <span className="policy-badge policy-badge-info">Current version {currentPolicy.version}</span>
            {!hasChanges ? <span className="status-pill status-pill-neutral">No definition changes</span> : null}
          </div>

          <div className="policy-diff-legend" aria-hidden="true">
            <span className="policy-diff-legend-item policy-diff-legend-item-removed">Removed</span>
            <span className="policy-diff-legend-item policy-diff-legend-item-added">Added</span>
            <span className="policy-diff-legend-item">Unchanged</span>
          </div>

          <div className="policy-diff-table">
            <div className="policy-diff-table-header">
              <span>Delta</span>
              <span>Old</span>
              <span>Now</span>
              <span>{diffFormat.toUpperCase()}</span>
            </div>
            <div className="policy-diff-lines" role="table" aria-label="Policy definition diff">
              {diffLines.map((line, index) => (
                <div
                  key={`${line.type}-${line.oldLineNumber ?? 'new'}-${line.newLineNumber ?? 'old'}-${index}`}
                  className={`policy-diff-row policy-diff-row-${line.type}`}
                  role="row"
                >
                  <span className="policy-diff-marker" aria-hidden="true">
                    {line.type === 'added' ? '+' : line.type === 'removed' ? '-' : ' '}
                  </span>
                  <span className="policy-diff-line-number">{line.oldLineNumber ?? ''}</span>
                  <span className="policy-diff-line-number">{line.newLineNumber ?? ''}</span>
                  <code className="policy-diff-content">{line.content === '' ? ' ' : line.content}</code>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : null}
    </ModalDialog>
  )
}
