package domain

import "time"

// Tenant represents an isolated customer account.
type Tenant struct {
	ID        string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}
