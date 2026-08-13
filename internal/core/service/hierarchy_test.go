package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

type hierarchyOrganizationRepo struct {
	items map[string]domain.Organization
}

func (r *hierarchyOrganizationRepo) GetByID(_ context.Context, tenantID, id string) (*domain.Organization, error) {
	item, ok := r.items[id]
	if !ok || item.TenantID != tenantID {
		return nil, domain.ErrOrganizationNotFound
	}
	return &item, nil
}
func (r *hierarchyOrganizationRepo) GetDefault(ctx context.Context, tenantID string) (*domain.Organization, error) {
	for _, item := range r.items {
		if item.TenantID == tenantID && item.IsDefault {
			return r.GetByID(ctx, tenantID, item.ID)
		}
	}
	return nil, domain.ErrOrganizationNotFound
}
func (r *hierarchyOrganizationRepo) ListByTenant(_ context.Context, tenantID string) ([]domain.Organization, error) {
	items := make([]domain.Organization, 0)
	for _, item := range r.items {
		if item.TenantID == tenantID {
			items = append(items, item)
		}
	}
	return items, nil
}
func (r *hierarchyOrganizationRepo) Create(_ context.Context, item *domain.Organization) error {
	item.ID = "created-org"
	r.items[item.ID] = *item
	return nil
}
func (r *hierarchyOrganizationRepo) Update(_ context.Context, item *domain.Organization) error {
	r.items[item.ID] = *item
	return nil
}

type hierarchyOrganizationMembers struct {
	items map[string]domain.OrganizationMembership
}

func orgMemberKey(organizationID, principalID string) string {
	return organizationID + ":" + principalID
}
func (r *hierarchyOrganizationMembers) Get(_ context.Context, tenantID, organizationID, principalID string) (*domain.OrganizationMembership, error) {
	item, ok := r.items[orgMemberKey(organizationID, principalID)]
	if !ok || item.TenantID != tenantID {
		return nil, domain.ErrOrganizationMembershipNotFound
	}
	return &item, nil
}
func (r *hierarchyOrganizationMembers) ListByPrincipal(_ context.Context, tenantID, principalID string) ([]domain.OrganizationMembership, error) {
	items := make([]domain.OrganizationMembership, 0)
	for _, item := range r.items {
		if item.TenantID == tenantID && item.PrincipalID == principalID {
			items = append(items, item)
		}
	}
	return items, nil
}
func (r *hierarchyOrganizationMembers) Upsert(_ context.Context, item *domain.OrganizationMembership) error {
	r.items[orgMemberKey(item.OrganizationID, item.PrincipalID)] = *item
	return nil
}
func (r *hierarchyOrganizationMembers) Delete(_ context.Context, tenantID, organizationID, principalID string) error {
	key := orgMemberKey(organizationID, principalID)
	if _, ok := r.items[key]; !ok {
		return domain.ErrOrganizationMembershipNotFound
	}
	delete(r.items, key)
	return nil
}

type hierarchyTeamRepo struct{ items map[string]domain.Team }

func (r *hierarchyTeamRepo) GetByID(_ context.Context, tenantID, organizationID, id string) (*domain.Team, error) {
	item, ok := r.items[id]
	if !ok || item.TenantID != tenantID || item.OrganizationID != organizationID {
		return nil, domain.ErrTeamNotFound
	}
	return &item, nil
}
func (r *hierarchyTeamRepo) ListByOrganization(_ context.Context, tenantID, organizationID string) ([]domain.Team, error) {
	items := make([]domain.Team, 0)
	for _, item := range r.items {
		if item.TenantID == tenantID && item.OrganizationID == organizationID {
			items = append(items, item)
		}
	}
	return items, nil
}
func (r *hierarchyTeamRepo) Create(_ context.Context, item *domain.Team) error {
	item.ID = "created-team"
	r.items[item.ID] = *item
	return nil
}
func (r *hierarchyTeamRepo) Update(_ context.Context, item *domain.Team) error {
	r.items[item.ID] = *item
	return nil
}

type hierarchyTeamMembers struct {
	items map[string]domain.TeamMembership
}

func teamMemberKey(teamID, principalID string) string { return teamID + ":" + principalID }
func (r *hierarchyTeamMembers) IsMember(_ context.Context, tenantID, organizationID, teamID, principalID string) (bool, error) {
	item, ok := r.items[teamMemberKey(teamID, principalID)]
	return ok && item.TenantID == tenantID && item.OrganizationID == organizationID, nil
}
func (r *hierarchyTeamMembers) ListByPrincipal(_ context.Context, tenantID, organizationID, principalID string) ([]domain.TeamMembership, error) {
	items := make([]domain.TeamMembership, 0)
	for _, item := range r.items {
		if item.TenantID == tenantID && item.OrganizationID == organizationID && item.PrincipalID == principalID {
			items = append(items, item)
		}
	}
	return items, nil
}
func (r *hierarchyTeamMembers) Upsert(_ context.Context, item *domain.TeamMembership) error {
	item.CreatedAt = time.Now().UTC()
	r.items[teamMemberKey(item.TeamID, item.PrincipalID)] = *item
	return nil
}
func (r *hierarchyTeamMembers) Delete(_ context.Context, tenantID, organizationID, teamID, principalID string) error {
	key := teamMemberKey(teamID, principalID)
	if _, ok := r.items[key]; !ok {
		return domain.ErrTeamMembershipNotFound
	}
	delete(r.items, key)
	return nil
}

type hierarchyPrincipalRepo struct {
	items      map[string]domain.Principal
	identities map[string]domain.PrincipalIdentity
}

func (r *hierarchyPrincipalRepo) GetByID(_ context.Context, id string) (*domain.Principal, error) {
	item, ok := r.items[id]
	if !ok {
		return nil, domain.ErrPrincipalNotFound
	}
	return &item, nil
}
func (r *hierarchyPrincipalRepo) GetByIdentity(_ context.Context, provider, externalSubject string) (*domain.Principal, error) {
	for principalID, identity := range r.identities {
		if identity.Provider == provider && identity.ExternalSubject == externalSubject {
			return r.GetByID(context.Background(), principalID)
		}
	}
	return nil, domain.ErrPrincipalNotFound
}
func (r *hierarchyPrincipalRepo) GetIdentity(_ context.Context, principalID, provider string) (*domain.PrincipalIdentity, error) {
	item, ok := r.identities[principalID]
	if !ok || item.Provider != provider {
		return nil, domain.ErrPrincipalNotFound
	}
	return &item, nil
}
func (r *hierarchyPrincipalRepo) Create(context.Context, *domain.Principal) error { return nil }
func (r *hierarchyPrincipalRepo) Update(context.Context, *domain.Principal) error { return nil }
func (r *hierarchyPrincipalRepo) LinkIdentity(context.Context, *domain.PrincipalIdentity) error {
	return nil
}

type hierarchyMembershipVerifier struct {
	allowed bool
	calls   int
}

func (v *hierarchyMembershipVerifier) VerifyTenantMembership(context.Context, string, string, string) error {
	v.calls++
	if !v.allowed {
		return domain.ErrUnauthorized
	}
	return nil
}

func hierarchyServiceFixture(role domain.OrganizationRole, verifier TenantMembershipVerifier) (*HierarchyService, domain.AuthenticatedPrincipal, *hierarchyTeamMembers) {
	organizations := &hierarchyOrganizationRepo{items: map[string]domain.Organization{
		"org-a": {ID: "org-a", TenantID: "tenant-a", Name: "A", Status: domain.OrganizationStatusActive},
		"org-b": {ID: "org-b", TenantID: "tenant-b", Name: "B", Status: domain.OrganizationStatusActive},
	}}
	orgMembers := &hierarchyOrganizationMembers{items: map[string]domain.OrganizationMembership{
		orgMemberKey("org-a", "actor"): {TenantID: "tenant-a", OrganizationID: "org-a", PrincipalID: "actor", Role: role},
	}}
	teams := &hierarchyTeamRepo{items: map[string]domain.Team{
		"team-a": {ID: "team-a", TenantID: "tenant-a", OrganizationID: "org-a", Name: "A"},
		"team-b": {ID: "team-b", TenantID: "tenant-a", OrganizationID: "org-a", Name: "B"},
	}}
	teamMembers := &hierarchyTeamMembers{items: map[string]domain.TeamMembership{
		teamMemberKey("team-a", "actor"): {TenantID: "tenant-a", OrganizationID: "org-a", TeamID: "team-a", PrincipalID: "actor"},
	}}
	principals := &hierarchyPrincipalRepo{
		items: map[string]domain.Principal{
			"actor":  {ID: "actor", Status: domain.PrincipalStatusActive},
			"target": {ID: "target", Status: domain.PrincipalStatusActive},
		},
		identities: map[string]domain.PrincipalIdentity{
			"actor":  {PrincipalID: "actor", Provider: "clerk", ExternalSubject: "user-actor"},
			"target": {PrincipalID: "target", Provider: "clerk", ExternalSubject: "user-target"},
		},
	}
	authorization := NewAuthorizationService(organizations, orgMembers, teams, teamMembers)
	service := NewHierarchyService(organizations, orgMembers, teams, teamMembers, principals, authorization, verifier)
	actor := domain.AuthenticatedPrincipal{
		Principal: domain.Principal{ID: "actor", Status: domain.PrincipalStatusActive},
		TenantID:  "tenant-a", TenantRole: domain.TenantRoleMember, Provider: "clerk", ExternalAccountID: "account-a",
	}
	return service, actor, teamMembers
}

func TestHierarchyService_FiltersAssignedOrganizationsAndTeams(t *testing.T) {
	service, actor, _ := hierarchyServiceFixture(domain.OrganizationRoleViewer, &hierarchyMembershipVerifier{allowed: true})

	organizations, err := service.ListOrganizations(context.Background(), actor)
	require.NoError(t, err)
	require.Len(t, organizations, 1)
	assert.Equal(t, "org-a", organizations[0].Organization.ID)

	teams, err := service.ListTeams(context.Background(), actor, "org-a")
	require.NoError(t, err)
	require.Len(t, teams, 1)
	assert.Equal(t, "team-a", teams[0].ID)

	_, err = service.GetTeam(context.Background(), actor, "org-a", "team-b")
	var denial *domain.AuthorizationError
	require.ErrorAs(t, err, &denial)
	assert.Equal(t, domain.AuthorizationDenialTeamMembershipRequired, denial.Reason)
}

func TestHierarchyService_AdminAssignmentRequiresFreshTenantMembership(t *testing.T) {
	verifier := &hierarchyMembershipVerifier{allowed: true}
	service, actor, teamMembers := hierarchyServiceFixture(domain.OrganizationRoleAdmin, verifier)

	membership, err := service.SetTeamMembership(context.Background(), actor, "org-a", "team-b", "target")
	require.NoError(t, err)
	assert.Equal(t, "target", membership.PrincipalID)
	assert.Equal(t, 1, verifier.calls)
	member, err := teamMembers.IsMember(context.Background(), "tenant-a", "org-a", "team-b", "target")
	require.NoError(t, err)
	assert.True(t, member)
}

func TestHierarchyService_AssignmentFailsClosedWithoutProviderVerification(t *testing.T) {
	service, actor, teamMembers := hierarchyServiceFixture(domain.OrganizationRoleAdmin, nil)

	_, err := service.SetTeamMembership(context.Background(), actor, "org-a", "team-b", "target")
	require.ErrorIs(t, err, domain.ErrMembershipCheckUnavailable)
	member, lookupErr := teamMembers.IsMember(context.Background(), "tenant-a", "org-a", "team-b", "target")
	require.NoError(t, lookupErr)
	assert.False(t, member)
}

func TestHierarchyService_HidesCrossTenantOrganization(t *testing.T) {
	service, actor, _ := hierarchyServiceFixture(domain.OrganizationRoleViewer, &hierarchyMembershipVerifier{allowed: true})
	_, err := service.GetOrganization(context.Background(), actor, "org-b")
	var denial *domain.AuthorizationError
	require.ErrorAs(t, err, &denial)
	assert.Equal(t, domain.AuthorizationDenialOrganizationNotFound, denial.Reason)
}
