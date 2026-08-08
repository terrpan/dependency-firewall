package domain

import "fmt"

// Validate validates a target block and applies the default unknown behavior.
func (t *PolicyTarget) Validate() error {
	if t == nil {
		return nil
	}
	if t.OnUnknown == "" {
		t.OnUnknown = DependencyUnknownWarn
	}
	switch t.OnUnknown {
	case DependencyUnknownWarn, DependencyUnknownDeny, DependencyUnknownSkip:
	default:
		return fmt.Errorf("%w: target.on_unknown must be one of warn, deny, skip", ErrInvalidPolicy)
	}

	for _, scope := range t.DependencyScopes {
		switch scope {
		case DependencyScopeDirect, DependencyScopeTransitive, DependencyScopeUnknown:
		default:
			return fmt.Errorf("%w: target.dependency_scope contains unsupported value %q", ErrInvalidPolicy, scope)
		}
	}
	for _, depType := range t.DependencyTypes {
		switch depType {
		case DependencyTypeProd, DependencyTypeDev, DependencyTypePeer, DependencyTypeOptional:
		default:
			return fmt.Errorf("%w: target.dependency_types contains unsupported value %q", ErrInvalidPolicy, depType)
		}
	}
	return nil
}

// Normalize applies target defaults and canonical ordering.
func (t *PolicyTarget) Normalize() {
	if t == nil {
		return
	}
	if t.OnUnknown == "" {
		t.OnUnknown = DependencyUnknownWarn
	}
	t.DependencyScopes = uniqueDependencyScopes(t.DependencyScopes)
	t.DependencyTypes = uniqueDependencyTypes(t.DependencyTypes)
}

func uniqueDependencyScopes(values []DependencyScope) []DependencyScope {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[DependencyScope]struct{}, len(values))
	result := make([]DependencyScope, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
