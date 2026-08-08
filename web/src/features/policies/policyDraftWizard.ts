// Policy draft wizard metadata and shared UI types.
import type { ModalWizardStep } from '../../components/modal/index.ts'

export const policyWizardSteps = [
  {
    id: 'choose-upstream',
    label: 'Choose upstream',
    description: 'Select the upstream scope.',
  },
  {
    id: 'choose-type',
    label: 'Choose type',
    description: 'Pick a compatible policy type.',
  },
  {
    id: 'set-basics',
    label: 'Set basics',
    description: 'Set the name and defaults.',
  },
  {
    id: 'set-target',
    label: 'Set target',
    description: 'Scope the rule by npm dependency context.',
  },
  {
    id: 'configure-rule',
    label: 'Configure rule',
    description: 'Add the rule values.',
  },
  {
    id: 'review-create',
    label: 'Review and create',
    description: 'Review the preview and save.',
  },
] satisfies readonly ModalWizardStep[]

export type PreviewFormat = 'json' | 'yaml'

export type PolicyDraftFieldErrorKey =
  | 'type'
  | 'upstreamId'
  | 'name'
  | 'priority'
  | 'schemaVersion'
  | 'numericValue'
  | 'minimumSeverity'
  | 'target'
  | 'listValue'
