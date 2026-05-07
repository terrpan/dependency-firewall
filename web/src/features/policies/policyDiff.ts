export type PolicyDiffLine = {
  type: 'added' | 'removed' | 'context'
  oldLineNumber: number | null
  newLineNumber: number | null
  content: string
}

function splitPreviewLines(value: string) {
  return value === '' ? [''] : value.split('\n')
}

export function buildPolicyDiffLines(previousContent: string, currentContent: string): PolicyDiffLine[] {
  const previousLines = splitPreviewLines(previousContent)
  const currentLines = splitPreviewLines(currentContent)
  const lcsTable = Array.from({ length: previousLines.length + 1 }, () =>
    Array<number>(currentLines.length + 1).fill(0),
  )

  for (let previousIndex = previousLines.length - 1; previousIndex >= 0; previousIndex -= 1) {
    for (let currentIndex = currentLines.length - 1; currentIndex >= 0; currentIndex -= 1) {
      lcsTable[previousIndex][currentIndex] =
        previousLines[previousIndex] === currentLines[currentIndex]
          ? lcsTable[previousIndex + 1][currentIndex + 1] + 1
          : Math.max(lcsTable[previousIndex + 1][currentIndex], lcsTable[previousIndex][currentIndex + 1])
    }
  }

  const diffLines: PolicyDiffLine[] = []
  let previousIndex = 0
  let currentIndex = 0
  let previousLineNumber = 1
  let currentLineNumber = 1

  while (previousIndex < previousLines.length && currentIndex < currentLines.length) {
    if (previousLines[previousIndex] === currentLines[currentIndex]) {
      diffLines.push({
        type: 'context',
        oldLineNumber: previousLineNumber,
        newLineNumber: currentLineNumber,
        content: previousLines[previousIndex] ?? '',
      })
      previousIndex += 1
      currentIndex += 1
      previousLineNumber += 1
      currentLineNumber += 1
      continue
    }

    if (lcsTable[previousIndex + 1][currentIndex] >= lcsTable[previousIndex][currentIndex + 1]) {
      diffLines.push({
        type: 'removed',
        oldLineNumber: previousLineNumber,
        newLineNumber: null,
        content: previousLines[previousIndex] ?? '',
      })
      previousIndex += 1
      previousLineNumber += 1
      continue
    }

    diffLines.push({
      type: 'added',
      oldLineNumber: null,
      newLineNumber: currentLineNumber,
      content: currentLines[currentIndex] ?? '',
    })
    currentIndex += 1
    currentLineNumber += 1
  }

  while (previousIndex < previousLines.length) {
    diffLines.push({
      type: 'removed',
      oldLineNumber: previousLineNumber,
      newLineNumber: null,
      content: previousLines[previousIndex] ?? '',
    })
    previousIndex += 1
    previousLineNumber += 1
  }

  while (currentIndex < currentLines.length) {
    diffLines.push({
      type: 'added',
      oldLineNumber: null,
      newLineNumber: currentLineNumber,
      content: currentLines[currentIndex] ?? '',
    })
    currentIndex += 1
    currentLineNumber += 1
  }

  return diffLines
}
