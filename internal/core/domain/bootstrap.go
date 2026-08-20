package domain

// SessionBootstrapRequest models a session bootstrap request.
type SessionBootstrapRequest struct {
	Provider          string
	ExternalAccountID string
	AccountName       string
	ExternalSubject   string
	DisplayName       string
	Email             string
}

// SessionBootstrapResult models a session bootstrap result.
type SessionBootstrapResult struct {
	Tenant    Tenant
	Principal Principal
	Created   bool
}
