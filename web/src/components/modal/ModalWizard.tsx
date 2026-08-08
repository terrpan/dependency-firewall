import type { CSSProperties, ReactNode } from 'react'
import { ModalDialog, type ModalDialogProps } from './ModalDialog.tsx'
import styles from './ModalWizard.module.css'

export type ModalWizardStep = {
  id: string
  label: string
  description?: string
}

export type ModalWizardProps = Omit<ModalDialogProps, 'children'> & {
  steps: readonly ModalWizardStep[]
  currentStep: number
  children: ReactNode
  aside?: ReactNode
  progressLabel?: string
  allowStepSelection?: boolean
  showStepDescriptions?: boolean
  stepGuideVariant?: 'default' | 'compact'
  onStepChange?: (step: number) => void
}

export function ModalWizard({
  steps,
  currentStep,
  children,
  aside,
  progressLabel = 'Wizard steps',
  allowStepSelection = false,
  showStepDescriptions = true,
  stepGuideVariant = 'default',
  onStepChange,
  headerMeta,
  size = 'wide',
  ...dialogProps
}: ModalWizardProps) {
  const maxStepIndex = Math.max(steps.length - 1, 0)
  const activeStep = Math.min(Math.max(currentStep, 0), maxStepIndex)
  const showStepCounter = steps.length > 0
  const stepCount = Math.max(steps.length, 1)
  const stepListClassName = [styles.stepList, stepGuideVariant === 'compact' ? styles.stepListCompact : '']
    .filter(Boolean)
    .join(' ')
  const stepListStyle = {
    '--modal-wizard-step-columns': String(stepCount),
    '--modal-wizard-step-columns-medium': String(Math.min(stepCount, 3)),
    '--modal-wizard-step-columns-small': String(Math.min(stepCount, 2)),
  } as CSSProperties

  return (
    <ModalDialog
      {...dialogProps}
      headerMeta={
        <div className={styles.headerMeta}>
          {headerMeta}
          {showStepCounter ? (
            <span className={styles.stepCounter}>
              Step {activeStep + 1} of {steps.length}
            </span>
          ) : null}
        </div>
      }
      size={size}
    >
      <div className={styles.shell}>
        {steps.length > 0 ? (
          <nav aria-label={progressLabel}>
            <ol className={stepListClassName} style={stepListStyle}>
              {steps.map((step, index) => {
                const toneClassName =
                  index === activeStep
                    ? styles.stepCurrent
                    : index < activeStep
                      ? styles.stepComplete
                      : styles.stepUpcoming
                const stepSurfaceClassName = [
                  allowStepSelection ? styles.stepButton : styles.stepCard,
                  toneClassName,
                  stepGuideVariant === 'compact' ? styles.stepSurfaceCompact : '',
                ]
                  .filter(Boolean)
                  .join(' ')

                const stepContent = (
                  <>
                    <span className={styles.stepNumber}>{index + 1}</span>
                    <div className={styles.stepText}>
                      <p className={styles.stepLabel}>{step.label}</p>
                      {showStepDescriptions && step.description ? (
                        <p className={styles.stepDescription}>{step.description}</p>
                      ) : null}
                    </div>
                  </>
                )

                return (
                  <li
                    className={`${styles.stepItem} ${index === activeStep ? styles.stepItemCurrent : styles.stepItemInactive}`}
                    key={step.id}
                  >
                    {allowStepSelection && onStepChange ? (
                      <button
                        aria-current={index === activeStep ? 'step' : undefined}
                        className={stepSurfaceClassName}
                        onClick={() => onStepChange(index)}
                        type="button"
                      >
                        {stepContent}
                      </button>
                    ) : (
                      <div
                        aria-current={index === activeStep ? 'step' : undefined}
                        className={stepSurfaceClassName}
                      >
                        {stepContent}
                      </div>
                    )}
                  </li>
                )
              })}
            </ol>
          </nav>
        ) : null}

        <div className={`${styles.layout} ${aside ? styles.layoutWithAside : ''}`}>
          <div className={styles.main}>{children}</div>
          {aside ? <aside className={styles.aside}>{aside}</aside> : null}
        </div>
      </div>
    </ModalDialog>
  )
}
