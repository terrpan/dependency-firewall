package domain

type SessionBootstrapRequest struct {
	Provider          string
	ExternalAccountID string
	AccountName       string
	ExternalSubject   string
	DisplayName       string
	Email             string
}

type SessionBootstrapResult struct {
	Tenant    Tenant
	Principal Principal
	Created   bool
}
