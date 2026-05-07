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
      return 'filter-chip-success'
    case 'danger':
      return 'filter-chip-danger'
    case 'warning':
      return 'filter-chip-warning'
    case 'info':
      return 'filter-chip-info'
    case 'muted':
      return 'filter-chip-muted'
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
    <div className="filter-toolbar">
      <label className={`filter-search-field${searchFieldClassName ? ` ${searchFieldClassName}` : ''}`} htmlFor={searchInputId}>
        <span>{searchLabel}</span>
        <input
          id={searchInputId}
          type="search"
          value={searchValue}
          placeholder={searchPlaceholder}
          onChange={(event) => onSearchChange(event.target.value)}
        />
        {searchHelpText ? <small>{searchHelpText}</small> : null}
      </label>

      <div className="filter-chip-row" role="group" aria-label={filterGroupLabel}>
        {filterOptions.map((filter) => {
          const isActive = activeFilters.includes(filter.id)
          const toneClass = toneClassName(filter.tone)

          return (
            <button
              key={filter.id}
              aria-pressed={isActive}
              className={`filter-chip${toneClass ? ` ${toneClass}` : ''}${isActive ? ' filter-chip-active' : ''}`}
              onClick={() => onToggleFilter(filter.id)}
              type="button"
            >
              {filter.label}
              {typeof filter.count === 'number' ? <span className="filter-chip-count">{filter.count}</span> : null}
            </button>
          )
        })}

        {activeFilters.length > 0 ? (
          <button className="secondary-button" onClick={onClearFilters} type="button">
            {clearFiltersLabel}
          </button>
        ) : null}
      </div>
    </div>
  )
}
