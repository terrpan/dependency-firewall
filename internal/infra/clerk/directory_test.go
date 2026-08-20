package clerk

import (
	"context"
	"testing"

	clerksdk "github.com/clerk/clerk-sdk-go/v2"
	"github.com/clerk/clerk-sdk-go/v2/organizationmembership"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type organizationGetterStub struct{ organization *clerksdk.Organization }

func (s organizationGetterStub) Get(context.Context, string) (*clerksdk.Organization, error) {
	return s.organization, nil
}

type userGetterStub struct{ user *clerksdk.User }

func (s userGetterStub) Get(context.Context, string) (*clerksdk.User, error) { return s.user, nil }

type membershipListerStub struct {
	memberships []*clerksdk.OrganizationMembership
}

func (s membershipListerStub) List(
	context.Context,
	*organizationmembership.ListParams,
) (*clerksdk.OrganizationMembershipList, error) {
	return &clerksdk.OrganizationMembershipList{OrganizationMemberships: s.memberships}, nil
}

func TestDirectory_BootstrapRequestUsesFreshMembershipAndProjection(t *testing.T) {
	first, last, username := "Ada", "Lovelace", "ada"
	emailID := "email_primary"
	directory := &Directory{
		organizations: organizationGetterStub{organization: &clerksdk.Organization{ID: "org_123", Name: "Acme"}},
		users: userGetterStub{user: &clerksdk.User{
			ID: "user_123", FirstName: &first, LastName: &last, Username: &username,
			PrimaryEmailAddressID: &emailID,
			EmailAddresses: []*clerksdk.EmailAddress{
				{ID: "other", EmailAddress: "other@example.test"},
				{ID: emailID, EmailAddress: "ada@example.test"},
			},
		}},
		memberships: membershipListerStub{memberships: []*clerksdk.OrganizationMembership{{
			Role: "org:owner", PublicUserData: &clerksdk.OrganizationMembershipPublicUserData{UserID: "user_123"},
		}}},
	}

	request, role, err := directory.BootstrapRequest(context.Background(), domain.VerifiedIdentity{
		Provider: Provider, Subject: "user_123", ExternalAccountID: "org_123", TenantRole: domain.TenantRoleMember,
	})
	require.NoError(t, err)
	assert.Equal(t, domain.TenantRoleOwner, role, "fresh membership role wins over the token projection")
	assert.Equal(t, "Acme", request.AccountName)
	assert.Equal(t, "Ada Lovelace", request.DisplayName)
	assert.Equal(t, "ada@example.test", request.Email)
}

func TestDirectory_BootstrapRequestFailsClosedWithoutExactMembership(t *testing.T) {
	directory := &Directory{
		organizations: organizationGetterStub{organization: &clerksdk.Organization{ID: "org_123", Name: "Acme"}},
		users:         userGetterStub{user: &clerksdk.User{ID: "user_123"}},
		memberships:   membershipListerStub{},
	}

	_, _, err := directory.BootstrapRequest(context.Background(), domain.VerifiedIdentity{
		Provider: Provider, Subject: "user_123", ExternalAccountID: "org_123",
	})
	require.ErrorIs(t, err, domain.ErrUnauthorized)
}

func TestDirectory_VerifyTenantMembershipRejectsOtherProvider(t *testing.T) {
	directory := &Directory{}
	err := directory.VerifyTenantMembership(context.Background(), "other", "org_123", "user_123")
	require.ErrorIs(t, err, domain.ErrUnauthorized)
}
