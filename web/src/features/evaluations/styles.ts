import styles from './Evaluations.module.css'
import { applicationClass } from '../../ui/foundation/applicationStyles.ts'

export function evaluationClass(...classNames: Array<string | false | null | undefined>) {
  return classNames
    .filter((className): className is string => Boolean(className))
    .flatMap((className) => className.split(/\s+/))
    .map((className) => styles[className] ?? applicationClass(className))
    .join(' ')
}
