export default {
  extends: ['stylelint-config-standard', 'stylelint-config-css-modules'],
  ignoreFiles: [
    'dist/**',
    'node_modules/**',
    'playwright-report/**',
    'test-results/**',
    'src/lib/api/generated/**',
    // Work-in-progress page that references a non-existent API surface.
    'src/pages/OrganizationsPage.module.css',
  ],
  rules: {
    // CSS Modules in this project use camelCase class names by convention.
    'selector-class-pattern': null,
    // Prettier owns formatting; keep Stylelint focused on CSS correctness.
    'declaration-empty-line-before': null,
    'rule-empty-line-before': null,
    'at-rule-empty-line-before': null,
    'custom-property-empty-line-before': null,
    // Stylistic preferences that are not project conventions.
    'media-feature-range-notation': null,
    'color-function-notation': null,
    'color-hex-length': null,
    'color-named': null,
    'length-zero-no-unit': null,
    'shorthand-property-no-redundant-values': null,
    'value-keyword-case': null,
    'import-notation': null,
    // The existing CSS Modules are organized around components and media
    // queries; enforcing strict source order creates churn without improving
    // correctness.
    'no-descending-specificity': null,
    // Duplicate selectors are intentionally used for responsive overrides and
    // logical grouping in this codebase.
    'no-duplicate-selectors': null,
  },
}
