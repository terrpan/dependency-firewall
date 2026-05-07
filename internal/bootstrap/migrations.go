// migrations.go runs embedded PostgreSQL migrations during control-plane startup.
package bootstrap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/danielterry/dependency-firewall/internal/config"
	"github.com/danielterry/dependency-firewall/migrations"
)

func migrateDatabase(cfg *config.Config) error {
	source, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("creating migration source: %w", err)
	}

	migrateDSN := strings.Replace(cfg.Database.DSN, "postgres://", "pgx5://", 1)
	migrateDSN = strings.Replace(migrateDSN, "postgresql://", "pgx5://", 1)

	migrator, err := migrate.NewWithSourceInstance("iofs", source, migrateDSN)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}
	if err := migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("running migrations: %w", err)
	}

	srcErr, dbErr := migrator.Close()
	if srcErr != nil {
		return fmt.Errorf("closing migration source: %w", srcErr)
	}
	if dbErr != nil {
		return fmt.Errorf("closing migration db: %w", dbErr)
	}

	return nil
}
