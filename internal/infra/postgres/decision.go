package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// DecisionRepository implements port.DecisionRepository using PostgreSQL.
type DecisionRepository struct {
	pool *pgxpool.Pool
}

// NewDecisionRepository creates a new DecisionRepository.
func NewDecisionRepository(pool *pgxpool.Pool) *DecisionRepository {
	return &DecisionRepository{pool: pool}
}

// Record inserts a decision and its associated reasons.
func (r *DecisionRepository) Record(ctx context.Context, decision *domain.Decision) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Ensure the artifact exists and get its ID.
	var artifactID *string
	if decision.Artifact.Name != "" {
		var aid string
		err = tx.QueryRow(ctx,
			`INSERT INTO artifacts (tenant_id, ecosystem, namespace, name, version, digest)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 ON CONFLICT (tenant_id, ecosystem, namespace, name, version, digest) DO UPDATE SET tenant_id = EXCLUDED.tenant_id
			 RETURNING id`,
			decision.TenantID, decision.Artifact.Ecosystem, decision.Artifact.Namespace,
			decision.Artifact.Name, decision.Artifact.Version, decision.Artifact.Digest,
		).Scan(&aid)
		if err != nil {
			return fmt.Errorf("upserting artifact: %w", err)
		}
		artifactID = &aid
	}

	// Insert the decision.
	var policyID *string
	if decision.PolicyID != "" {
		policyID = &decision.PolicyID
	}
	warnings := decision.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	dependencyContextJSON, err := json.Marshal(decision.DependencyContext)
	if err != nil {
		return fmt.Errorf("marshalling dependency context: %w", err)
	}
	err = tx.QueryRow(ctx,
		`INSERT INTO decisions (tenant_id, artifact_id, outcome, policy_id, policy_hash, reason, warnings, dependency_context, cached_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id, evaluated_at`,
		decision.TenantID, artifactID, decision.Outcome, policyID,
		decision.PolicyHash, decision.Reason, warnings, nullableJSON(dependencyContextJSON, decision.DependencyContext != nil), decision.CachedAt,
	).Scan(&decision.ID, &decision.EvaluatedAt)
	if err != nil {
		return fmt.Errorf("inserting decision: %w", err)
	}

	// Insert the evaluation record and its reasons.
	if len(decision.Reasons) > 0 {
		var evaluationID string
		err = tx.QueryRow(ctx,
			`INSERT INTO evaluations (tenant_id, artifact_id, outcome, policy_id, reason, dependency_context)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 RETURNING id`,
			decision.TenantID, artifactID, decision.Outcome, policyID, decision.Reason, nullableJSON(dependencyContextJSON, decision.DependencyContext != nil),
		).Scan(&evaluationID)
		if err != nil {
			return fmt.Errorf("inserting evaluation: %w", err)
		}

		for _, reason := range decision.Reasons {
			var reasonPolicyID *string
			if reason.PolicyID != "" {
				reasonPolicyID = &reason.PolicyID
			}
			_, err = tx.Exec(ctx,
				`INSERT INTO evaluation_reasons (evaluation_id, policy_id, policy_name, category, action, message)
				 VALUES ($1, $2, $3, $4, $5, $6)`,
				evaluationID, reasonPolicyID, reason.PolicyName,
				string(reason.Category), string(reason.Action), reason.Message,
			)
			if err != nil {
				return fmt.Errorf("inserting evaluation reason: %w", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing decision: %w", err)
	}
	return nil
}

// GetByArtifact returns the most recent decision for a tenant's artifact.
func (r *DecisionRepository) GetByArtifact(ctx context.Context, tenantID string, artifact domain.ArtifactIdentity) (*domain.Decision, error) {
	var d domain.Decision
	var policyID *string
	var policyHash *string
	row := r.pool.QueryRow(ctx,
		`SELECT d.id, d.tenant_id, d.outcome, d.policy_id, d.policy_hash, d.reason, d.warnings, d.dependency_context, d.cached_at, d.evaluated_at,
		        a.ecosystem, a.namespace, a.name, a.version, a.digest
		 FROM decisions d
		 JOIN artifacts a ON d.artifact_id = a.id
		 WHERE d.tenant_id = $1
		   AND a.ecosystem = $2 AND a.namespace = $3 AND a.name = $4
		   AND a.version = $5 AND a.digest = $6
		 ORDER BY d.evaluated_at DESC
		 LIMIT 1`,
		tenantID, artifact.Ecosystem, artifact.Namespace,
		artifact.Name, artifact.Version, artifact.Digest,
	)
	var dependencyContextJSON []byte
	err := row.Scan(&d.ID, &d.TenantID, &d.Outcome, &policyID, &policyHash, &d.Reason, &d.Warnings, &dependencyContextJSON,
		&d.CachedAt, &d.EvaluatedAt,
		&d.Artifact.Ecosystem, &d.Artifact.Namespace, &d.Artifact.Name,
		&d.Artifact.Version, &d.Artifact.Digest)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrArtifactNotFound
		}
		return nil, fmt.Errorf("querying decision by artifact: %w", err)
	}
	if policyID != nil {
		d.PolicyID = *policyID
	}
	if policyHash != nil {
		d.PolicyHash = *policyHash
	}
	if err := decodeDecisionDependencyContext(dependencyContextJSON, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// ListByTenant returns decisions for a tenant ordered by evaluated_at descending.
func (r *DecisionRepository) ListByTenant(ctx context.Context, tenantID string, limit, offset int, search string) ([]domain.Decision, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT d.id, d.tenant_id, d.outcome, d.policy_id, d.policy_hash, d.reason, d.warnings, d.dependency_context, d.cached_at, d.evaluated_at,
		        a.ecosystem, a.namespace, a.name, a.version, a.digest
		 FROM decisions d
		 LEFT JOIN artifacts a ON d.artifact_id = a.id
		 WHERE d.tenant_id = $1
		   AND (
		     $2 = ''
		     OR COALESCE(a.namespace, '') ILIKE '%' || $2 || '%'
		     OR COALESCE(a.name, '') ILIKE '%' || $2 || '%'
		     OR COALESCE(a.version, '') ILIKE '%' || $2 || '%'
		     OR COALESCE(a.digest, '') ILIKE '%' || $2 || '%'
		     OR CONCAT_WS('/', NULLIF(a.namespace, ''), COALESCE(a.name, '')) ILIKE '%' || $2 || '%'
		   )
		 ORDER BY d.evaluated_at DESC
		 LIMIT $3 OFFSET $4`,
		tenantID, search, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listing decisions: %w", err)
	}
	defer rows.Close()

	var decisions []domain.Decision
	for rows.Next() {
		var d domain.Decision
		var policyID *string
		var policyHash *string
		var eco, ns, name, ver, dig *string
		var dependencyContextJSON []byte
		if err := rows.Scan(&d.ID, &d.TenantID, &d.Outcome, &policyID, &policyHash, &d.Reason,
			&d.Warnings, &dependencyContextJSON, &d.CachedAt, &d.EvaluatedAt, &eco, &ns, &name, &ver, &dig); err != nil {
			return nil, fmt.Errorf("scanning decision row: %w", err)
		}
		if policyID != nil {
			d.PolicyID = *policyID
		}
		if policyHash != nil {
			d.PolicyHash = *policyHash
		}
		if eco != nil {
			d.Artifact.Ecosystem = domain.EcosystemType(*eco)
		}
		if ns != nil {
			d.Artifact.Namespace = *ns
		}
		if name != nil {
			d.Artifact.Name = *name
		}
		if ver != nil {
			d.Artifact.Version = *ver
		}
		if dig != nil {
			d.Artifact.Digest = *dig
		}
		if err := decodeDecisionDependencyContext(dependencyContextJSON, &d); err != nil {
			return nil, err
		}
		decisions = append(decisions, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating decision rows: %w", err)
	}
	return decisions, nil
}

func decodeDecisionDependencyContext(data []byte, decision *domain.Decision) error {
	if len(data) == 0 {
		return nil
	}
	var dependencyContext domain.DependencyContext
	if err := json.Unmarshal(data, &dependencyContext); err != nil {
		return fmt.Errorf("decoding decision dependency context: %w", err)
	}
	dependencyContext = dependencyContext.Normalize()
	decision.DependencyContext = &dependencyContext
	return nil
}

// HasRecentAllow checks if a recent allow decision exists for the given
// tenant, ecosystem, namespace, and name (any version/digest).
func (r *DecisionRepository) HasRecentAllow(ctx context.Context, tenantID string, ecosystem domain.EcosystemType, namespace, name string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM decisions d
			JOIN artifacts a ON d.artifact_id = a.id
			WHERE d.tenant_id = $1
			  AND a.ecosystem = $2
			  AND a.namespace = $3
			  AND a.name = $4
			  AND d.outcome = 'allow'
			  AND d.evaluated_at > now() - interval '1 hour'
		)`,
		tenantID, string(ecosystem), namespace, name,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("checking recent allow decision: %w", err)
	}
	return exists, nil
}
