export function parseInteger(value: string): number | null {
  const trimmed = value.trim()
  if (!trimmed) {
    return null
  }

  const parsed = Number(trimmed)
  if (!Number.isInteger(parsed)) {
    return null
  }

  return parsed
}

export function parseNumber(value: string): number | null {
  const trimmed = value.trim()
  if (!trimmed) {
    return null
  }

  const parsed = Number(trimmed)
  return Number.isFinite(parsed) ? parsed : null
}

export function parseDelimitedValues(value: string): string[] {
  return value
    .split(/\n|,/g)
    .map((item) => item.trim())
    .filter(Boolean)
}

function normalizeScorecardCheckName(value: string) {
  return value
    .trim()
    .toLowerCase()
    .replace(/[_\s]+/g, '-')
    .replace(/-+/g, '-')
}

export function parseScorecardThresholds(value: string): Record<string, number> {
  const thresholds: Record<string, number> = {}

  for (const rawEntry of value.split(/\n|,/g)) {
    const entry = rawEntry.trim()
    if (!entry) {
      continue
    }

    const separatorIndex = entry.search(/[:=]/)
    if (separatorIndex <= 0) {
      throw new Error('Per-check minimums must use "check=score" or "check: score".')
    }

    const rawName = entry.slice(0, separatorIndex).trim()
    const rawScore = entry.slice(separatorIndex + 1).trim()
    const normalizedName = normalizeScorecardCheckName(rawName)
    if (!normalizedName) {
      throw new Error('Per-check minimums must include a Scorecard check name.')
    }

    const parsedScore = Number(rawScore)
    if (!Number.isFinite(parsedScore) || parsedScore < 0 || parsedScore > 10) {
      throw new Error(`Per-check minimum for "${normalizedName}" must be a number between 0 and 10.`)
    }
    if (normalizedName in thresholds) {
      throw new Error(`Per-check minimum "${normalizedName}" is defined more than once.`)
    }

    thresholds[normalizedName] = parsedScore
  }

  return thresholds
}

export function formatScorecardThresholds(checks: Record<string, number> | undefined) {
  if (!checks || Object.keys(checks).length === 0) {
    return ''
  }

  return Object.entries(checks)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, score]) => `${name}=${score}`)
    .join('\n')
}
