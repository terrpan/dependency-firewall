package postgres

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

func mapConstraintError(err error, constraints map[string]error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	if pgErr.Code != "23505" {
		return err
	}

	if mapped, ok := constraints[pgErr.ConstraintName]; ok {
		return mapped
	}

	return err
}

func isConstraint(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.ConstraintName == constraint
}
