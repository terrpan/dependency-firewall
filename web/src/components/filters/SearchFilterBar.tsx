export type FilterChipTone = 'default' | 'success' | 'danger' | 'warning' | 'info' | 'muted'

export type FilterChipOption<T extends string> = {
  id: T
  label: string
  count?: number
  tone?: FilterChipTone
}

type SearchFilterBarProps<T extends string> = {
  searchInputId: string
  searchLabel: string
  searchValue: string
  searchPlaceholder: string
  searchHelpText?: string
  searchFieldClassName?: string
  onSearchChange: (value: string) => void
  filterGroupLabel: string
  filterOptions: readonly FilterChipOption<T>[]
  activeFilters: readonly T[]
  onToggleFilter: (filter: T) => void
  onClearFilters: () => void
  clearFiltersLabel?: string
}

function toneClassName(tone: FilterChipTone | undefined): string {
  switch (tone) {
    case 'success':
      return styles.success
    case 'danger':
      return styles.danger
    case 'warning':
      return styles.warning
    case 'info':
      return styles.info
    case 'muted':
      return styles.muted
    default:
      return ''
  }
}

export function SearchFilterBar<T extends string>({
  searchInputId,
  searchLabel,
  searchValue,
  searchPlaceholder,
  searchHelpText,
  searchFieldClassName,
  onSearchChange,
  filterGroupLabel,
  filterOptions,
  activeFilters,
  onToggleFilter,
  onClearFilters,
  clearFiltersLabel = 'Clear filters',
}: SearchFilterBarProps<T>) {
  return (
    <div className={styles.toolbar}>
      <label
        className={`${styles.search}${searchFieldClassName ? ` ${searchFieldClassName}` : ''}`}
        htmlFor={searchInputId}
      >
        <span>{searchLabel}</span>
        <Input
          id={searchInputId}
          type="search"
          value={searchValue}
          placeholder={searchPlaceholder}
          onChange={(event) => onSearchChange(event.target.value)}
        />
        {searchHelpText ? <small>{searchHelpText}</small> : null}
      </label>

      <div className={styles.row} role="group" aria-label={filterGroupLabel}>
        {filterOptions.map((filter) => {
          const isActive = activeFilters.includes(filter.id)
          const toneClass = toneClassName(filter.tone)

          return (
            <button
              key={filter.id}
              aria-pressed={isActive}
              className={`${styles.chip}${toneClass ? ` ${toneClass}` : ''}`}
              onClick={() => onToggleFilter(filter.id)}
              type="button"
            >
              {filter.label}
              {typeof filter.count === 'number' ? <span className={styles.count}>{filter.count}</span> : null}
            </button>
          )
        })}

        {activeFilters.length > 0 ? (
          <Button onClick={onClearFilters} type="button">
            {clearFiltersLabel}
          </Button>
        ) : null}
      </div>
    </div>
  )
}
import { Button, Input } from '../../ui/index.ts'
import styles from './SearchFilterBar.module.css'
