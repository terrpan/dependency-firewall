import styles from './Upstreams.module.css'

export function upstreamClass(...classNames: Array<string | false | null | undefined>) {
  return classNames
    .filter((className): className is string => Boolean(className))
    .flatMap((className) => className.split(/\s+/))
    .map((className) => styles[className] ?? className)
    .join(' ')
}
