package policy

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// DecodeConfigJSON decodes a raw JSON policy config into its typed config struct.
func DecodeConfigJSON(policyType domain.PolicyType, schemaVersion int, raw []byte) (domain.PolicyConfig, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, invalidPolicyf("config is required")
	}
	if err := rejectDeprecatedEnforceJSON(trimmed); err != nil {
		return nil, err
	}

	normalizedSchemaVersion, err := normalizeSchemaVersion(policyType, schemaVersion)
	if err != nil {
		return nil, err
	}
	if err := validateSchemaVersion(policyType, normalizedSchemaVersion); err != nil {
		return nil, err
	}

	config, err := newConfigForType(policyType, normalizedSchemaVersion)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(config); err != nil {
		return nil, invalidPolicyf("invalid config for policy type %q: %v", policyType, err)
	}
	if decoder.More() {
		return nil, invalidPolicyf("invalid config for policy type %q: unexpected trailing data", policyType)
	}
	if err := config.Validate(); err != nil {
		return nil, invalidPolicyf("%v", err)
	}
	return config, nil
}

// DecodeStoredConfigJSON decodes stored policy config and turns deprecated
// persisted formats into an explicit upgrade-style error.
func DecodeStoredConfigJSON(policyType domain.PolicyType, schemaVersion int, raw []byte) (domain.PolicyConfig, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, invalidPolicyf("config is required")
	}
	if hasDeprecatedEnforceJSON(trimmed) {
		return nil, fmt.Errorf("%w: stored policy config uses deprecated %q field; run the policy data migration", domain.ErrDeprecatedPolicyConfig, "enforce")
	}
	return DecodeConfigJSON(policyType, schemaVersion, trimmed)
}

// DecodeConfigValue decodes a generic value into its typed config struct.
func DecodeConfigValue(policyType domain.PolicyType, schemaVersion int, raw any) (domain.PolicyConfig, error) {
	if raw == nil {
		return nil, invalidPolicyf("config is required")
	}
	if rawMap, ok := raw.(map[string]any); ok {
		if _, hasDeprecatedEnforce := rawMap["enforce"]; hasDeprecatedEnforce {
			return nil, invalidPolicyf("config key %q is not supported; use %q instead", "enforce", "dry_run")
		}
	}

	payload, err := json.Marshal(raw)
	if err != nil {
		return nil, invalidPolicyf("marshalling config for policy type %q: %v", policyType, err)
	}
	return DecodeConfigJSON(policyType, schemaVersion, payload)
}

func rejectDeprecatedEnforceJSON(raw []byte) error {
	if !hasDeprecatedEnforceJSON(raw) {
		return nil
	}
	return invalidPolicyf("config key %q is not supported; use %q instead", "enforce", "dry_run")
}

func hasDeprecatedEnforceJSON(raw []byte) bool {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return false
	}
	_, hasDeprecatedEnforce := fields["enforce"]
	return hasDeprecatedEnforce
}

func invalidPolicyf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{domain.ErrInvalidPolicy}, args...)...)
}
