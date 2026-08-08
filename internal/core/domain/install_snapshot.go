package domain

import "time"

// NPMInstallSnapshot is the complete set of package versions one npm install
// resolved, as reported by the npm client through its native audit request.
type NPMInstallSnapshot struct {
	TenantID   string
	Upstream   Upstream
	Packages   []ArtifactIdentity
	ObservedAt time.Time
}
