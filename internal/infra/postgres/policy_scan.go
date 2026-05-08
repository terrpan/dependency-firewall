package postgres

import (
	"database/sql"
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
	err := row.Scan(
		&policy.ID,
		&policy.TenantID,
		&upstreamID,
		&policy.Name,
		&policy.Type,
		&policy.Action,
		&policy.SchemaVersion,
		&configJSON,
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
	return &policy, nil
}

func scanPolicyVersion(row rowScanner) (domain.PolicyVersion, error) {
	var version domain.PolicyVersion
	var upstreamID sql.NullString
	var configJSON []byte
	if err := row.Scan(
		&version.PolicyID,
		&version.Version,
		&upstreamID,
		&version.Name,
		&version.Type,
		&version.Action,
		&version.SchemaVersion,
		&configJSON,
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
	return version, nil
}

func nullableString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
