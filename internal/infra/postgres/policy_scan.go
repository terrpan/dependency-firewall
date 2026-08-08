package postgres

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
	corepolicy "github.com/danielterry/dependency-firewall/internal/core/policy"
)

var errNoPolicyRow = errors.New("policy row not found")

type rowScanner interface {
	Scan(dest ...any) error
}

func scanPolicy(row rowScanner) (*domain.Policy, error) {
	var policy domain.Policy
	var upstreamID sql.NullString
	var configJSON []byte
	var targetJSON []byte
	err := row.Scan(
		&policy.ID,
		&policy.TenantID,
		&upstreamID,
		&policy.Name,
		&policy.Type,
		&policy.Action,
		&policy.SchemaVersion,
		&configJSON,
		&targetJSON,
		&policy.Priority,
		&policy.Enabled,
		&policy.Version,
		&policy.CreatedAt,
		&policy.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errNoPolicyRow
		}
		return nil, fmt.Errorf("scanning policy row: %w", err)
	}
	if upstreamID.Valid {
		policy.UpstreamID = upstreamID.String
	}
	config, err := corepolicy.DecodeStoredConfigJSON(policy.Type, policy.SchemaVersion, configJSON)
	if err != nil {
		return nil, fmt.Errorf("decoding policy config: %w", err)
	}
	policy.Config = config
	target, err := decodePolicyTarget(targetJSON)
	if err != nil {
		return nil, fmt.Errorf("decoding policy target: %w", err)
	}
	policy.Target = target
	return &policy, nil
}

func scanPolicyVersion(row rowScanner) (domain.PolicyVersion, error) {
	var version domain.PolicyVersion
	var upstreamID sql.NullString
	var configJSON []byte
	var targetJSON []byte
	if err := row.Scan(
		&version.PolicyID,
		&version.Version,
		&upstreamID,
		&version.Name,
		&version.Type,
		&version.Action,
		&version.SchemaVersion,
		&configJSON,
		&targetJSON,
		&version.Priority,
		&version.Enabled,
		&version.CreatedAt,
	); err != nil {
		return domain.PolicyVersion{}, fmt.Errorf("scanning policy version row: %w", err)
	}
	if upstreamID.Valid {
		version.UpstreamID = upstreamID.String
	}
	config, err := corepolicy.DecodeStoredConfigJSON(version.Type, version.SchemaVersion, configJSON)
	if err != nil {
		return domain.PolicyVersion{}, fmt.Errorf("decoding policy version config: %w", err)
	}
	version.Config = config
	target, err := decodePolicyTarget(targetJSON)
	if err != nil {
		return domain.PolicyVersion{}, fmt.Errorf("decoding policy version target: %w", err)
	}
	version.Target = target
	return version, nil
}

func nullableString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func nullableJSON(value []byte, valid bool) any {
	if !valid {
		return nil
	}
	return value
}

func decodePolicyTarget(data []byte) (*domain.PolicyTarget, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var target domain.PolicyTarget
	if err := json.Unmarshal(data, &target); err != nil {
		return nil, err
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}
	target.Normalize()
	return &target, nil
}
