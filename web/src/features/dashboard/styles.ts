import styles from './Dashboard.module.css'
import { evaluationClass } from '../evaluations/styles.ts'

export function dashboardClass(...classNames: Array<string | false | null | undefined>) {
  return classNames
    .filter((className): className is string => Boolean(className))
    .flatMap((className) => className.split(/\s+/))
    .map((className) => styles[className] ?? evaluationClass(className))
    .join(' ')
}
