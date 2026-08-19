package migrations

import "embed"

// FS holds the ordered SQL migration files compiled into the binary, so a deployed process can bring a PostgreSQL
// database up to the schema its code expects without shipping the .sql files alongside it.
//
//go:embed *.sql
var FS embed.FS
