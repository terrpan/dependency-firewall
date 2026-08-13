package clerk

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	clerksdk "github.com/clerk/clerk-sdk-go/v2"
	"github.com/clerk/clerk-sdk-go/v2/organization"
	"github.com/clerk/clerk-sdk-go/v2/organizationmembership"
	"github.com/clerk/clerk-sdk-go/v2/user"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type organizationGetter interface {
	Get(ctx context.Context, idOrSlug string) (*clerksdk.Organization, error)
}

type userGetter interface {
	Get(ctx context.Context, id string) (*clerksdk.User, error)
}

type membershipLister interface {
	List(ctx context.Context, params *organizationmembership.ListParams) (*clerksdk.OrganizationMembershipList, error)
}

// Directory performs fresh Backend API reads for bootstrap and other
// high-risk account operations.
type Directory struct {
	organizations organizationGetter
	users         userGetter
	memberships   membershipLister
	timeout       time.Duration
}

func NewDirectory(secretKey string, client *http.Client) *Directory {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	config := &clerksdk.ClientConfig{BackendConfig: clerksdk.BackendConfig{
		Key: clerksdk.String(strings.TrimSpace(secretKey)), HTTPClient: client,
	}}
	return &Directory{
		organizations: organization.NewClient(config), users: user.NewClient(config),
		memberships: organizationmembership.NewClient(config), timeout: 10 * time.Second,
	}
}

func (d *Directory) BootstrapRequest(ctx context.Context, identity domain.VerifiedIdentity) (domain.SessionBootstrapRequest, domain.TenantRole, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	account, err := d.organizations.Get(ctx, identity.ExternalAccountID)
	if err != nil {
		return domain.SessionBootstrapRequest{}, "", fmt.Errorf("loading Clerk account: %w", err)
	}
	principal, err := d.users.Get(ctx, identity.Subject)
	if err != nil {
		return domain.SessionBootstrapRequest{}, "", fmt.Errorf("loading Clerk user: %w", err)
	}
	role, err := d.freshTenantRole(ctx, identity)
	if err != nil {
		return domain.SessionBootstrapRequest{}, "", err
	}

	return domain.SessionBootstrapRequest{
		Provider: Provider, ExternalAccountID: account.ID, AccountName: account.Name,
		ExternalSubject: principal.ID, DisplayName: displayName(principal), Email: primaryEmail(principal),
	}, role, nil
}

func (d *Directory) FreshTenantRole(ctx context.Context, identity domain.VerifiedIdentity) (domain.TenantRole, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.freshTenantRole(ctx, identity)
}

func (d *Directory) freshTenantRole(ctx context.Context, identity domain.VerifiedIdentity) (domain.TenantRole, error) {
	limit := int64(2)
	memberships, err := d.memberships.List(ctx, &organizationmembership.ListParams{
		OrganizationID: identity.ExternalAccountID,
		UserIDs:        []string{identity.Subject},
		ListParams:     clerksdk.ListParams{Limit: &limit},
	})
	if err != nil {
		return "", fmt.Errorf("checking Clerk membership: %w", err)
	}
	if len(memberships.OrganizationMemberships) != 1 {
		return "", domain.ErrUnauthorized
	}
	membership := memberships.OrganizationMemberships[0]
	if membership.PublicUserData == nil || membership.PublicUserData.UserID != identity.Subject {
		return "", domain.ErrUnauthorized
	}
	return tenantRole(membership.Role)
}

func displayName(principal *clerksdk.User) string {
	name := strings.TrimSpace(strings.TrimSpace(stringValue(principal.FirstName)) + " " + strings.TrimSpace(stringValue(principal.LastName)))
	if name != "" {
		return name
	}
	if username := strings.TrimSpace(stringValue(principal.Username)); username != "" {
		return username
	}
	return principal.ID
}

func primaryEmail(principal *clerksdk.User) string {
	if principal.PrimaryEmailAddressID == nil {
		return ""
	}
	for _, address := range principal.EmailAddresses {
		if address != nil && address.ID == *principal.PrimaryEmailAddressID {
			return address.EmailAddress
		}
	}
	return ""
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
