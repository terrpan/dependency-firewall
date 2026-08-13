import styles from './Application.module.css'

export function applicationClass(...classNames: Array<string | false | null | undefined>) {
  return classNames
    .filter((className): className is string => Boolean(className))
    .flatMap((className) => className.split(/\s+/))
    .map((className) => styles[className] ?? className)
    .join(' ')
}
