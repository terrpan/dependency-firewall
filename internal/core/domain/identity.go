package domain

import "strings"

// PrincipalRef uniquely identifies a human principal within an identity issuer.
type PrincipalRef struct {
	Issuer  string
	Subject string
}

// Valid reports whether both exact identity components are present.
func (r PrincipalRef) Valid() bool {
	return strings.TrimSpace(r.Issuer) != "" && strings.TrimSpace(r.Subject) != ""
}

// AuthenticatedPrincipal is a provider-neutral verified human identity.
type AuthenticatedPrincipal struct {
	Ref         PrincipalRef
	DisplayName string
	Email       string
}
