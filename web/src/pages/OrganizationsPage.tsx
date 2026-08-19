import { useQuery } from '@tanstack/react-query'
import { Archive, Building2, Plus, RotateCcw, UsersRound } from 'lucide-react'
import { useMemo, useState, type FormEvent } from 'react'
import { useSessionControlPlaneApi } from '../features/auth/useSessionControlPlaneApi.ts'
import { useNotifications } from '../features/notifications/useNotifications.ts'
import { AsyncState, Badge, Button, EmptyState, Field, Input, PageHeader, ResourceList } from '../ui/index.ts'
import { applicationClass } from '../ui/foundation/applicationStyles.ts'
import styles from './OrganizationsPage.module.css'

export function OrganizationsPage() {
  const api = useSessionControlPlaneApi()
  const { notifyError, notifySuccess } = useNotifications()
  const [selectedID, setSelectedID] = useState<string | null>(null)
  const [organizationName, setOrganizationName] = useState('')
  const [teamName, setTeamName] = useState('')
  const [isCreatingOrganization, setIsCreatingOrganization] = useState(false)
  const [isCreatingTeam, setIsCreatingTeam] = useState(false)
  const [updatingTeamID, setUpdatingTeamID] = useState<string | null>(null)

  const organizations = useQuery({ queryKey: ['organizations'], queryFn: () => api.organizations.list() })
  const selectedOrganization = useMemo(
    () => organizations.data?.find((organization) => organization.id === selectedID) ?? organizations.data?.[0] ?? null,
    [organizations.data, selectedID],
  )
  const teams = useQuery({
    queryKey: ['teams', selectedOrganization?.id ?? null],
    queryFn: () => api.organizations.teams.list(selectedOrganization!.id),
    enabled: Boolean(selectedOrganization),
  })

  async function createOrganization(event: FormEvent) {
    event.preventDefault()
    const name = organizationName.trim()
    if (!name) return
    setIsCreatingOrganization(true)
    try {
      const organization = await api.organizations.create({ name })
      setOrganizationName('')
      setSelectedID(organization.id)
      await organizations.refetch()
      notifySuccess('Organization created', `${organization.name} is ready for Teams and scoped resources.`)
    } catch (error) {
      notifyError('Unable to create Organization', error instanceof Error ? error.message : 'Try again.')
    } finally {
      setIsCreatingOrganization(false)
    }
  }

  async function createTeam(event: FormEvent) {
    event.preventDefault()
    if (!selectedOrganization) return
    const name = teamName.trim()
    if (!name) return
    setIsCreatingTeam(true)
    try {
      const team = await api.organizations.teams.create(selectedOrganization.id, { name })
      setTeamName('')
      await teams.refetch()
      notifySuccess('Team created', `${team.name} can now own Team-local upstreams and access.`)
    } catch (error) {
      notifyError('Unable to create Team', error instanceof Error ? error.message : 'Try again.')
    } finally {
      setIsCreatingTeam(false)
    }
  }

  async function setArchived(teamID: string, name: string, archived: boolean) {
    if (!selectedOrganization) return
    setUpdatingTeamID(teamID)
    try {
      await api.organizations.teams.update(selectedOrganization.id, teamID, { name, archived })
      await teams.refetch()
      notifySuccess(
        archived ? 'Team archived' : 'Team restored',
        archived ? 'Its Team-local scope is no longer available for new work.' : 'The Team is active again.',
      )
    } catch (error) {
      notifyError('Unable to update Team', error instanceof Error ? error.message : 'Try again.')
    } finally {
      setUpdatingTeamID(null)
    }
  }

  return (
    <section className={applicationClass('page')}>
      <PageHeader
        eyebrow="Organization scope"
        title="Organizations and Teams"
        summary="Local Organizations divide the active account into operational scopes. Teams further limit access inside one Organization."
        actions={<Badge tone="neutral">{organizations.data?.length ?? 0} Organizations</Badge>}
      />

      <div className={styles.layout}>
        <section className={styles.panel} aria-labelledby="organizations-heading">
          <div className={styles.panelHeader}>
            <div>
              <Building2 size={18} aria-hidden="true" />
              <h2 id="organizations-heading">Organizations</h2>
            </div>
            <span>Local operational scopes</span>
          </div>
          <form className={styles.inlineForm} onSubmit={createOrganization}>
            <Field label="New Organization">
              <Input
                value={organizationName}
                onChange={(event) => setOrganizationName(event.target.value)}
                placeholder="Platform Engineering"
                maxLength={120}
              />
            </Field>
            <Button type="submit" variant="primary" disabled={isCreatingOrganization || !organizationName.trim()}>
              <Plus size={16} />
              {isCreatingOrganization ? 'Creating…' : 'Create'}
            </Button>
          </form>
          {organizations.isPending ? <AsyncState status="loading" /> : null}
          {organizations.isError ? (
            <AsyncState
              status="error"
              error={organizations.error instanceof Error ? organizations.error.message : undefined}
              onRetry={() => void organizations.refetch()}
            />
          ) : null}
          {organizations.data?.length === 0 ? (
            <EmptyState title="No local Organizations" message="Create the first operational scope for this account." />
          ) : null}
          {organizations.data?.length ? (
            <ResourceList aria-label="Organizations" className={styles.list}>
              {organizations.data.map((organization) => {
                const selected = organization.id === selectedOrganization?.id
                return (
                  <li className={styles.resource} data-selected={selected || undefined} key={organization.id}>
                    <button
                      className={styles.resourceSelect}
                      onClick={() => setSelectedID(organization.id)}
                      type="button"
                    >
                      <span>
                        <strong>{organization.name}</strong>
                        <small>
                          {organization.role} · {organization.status}
                        </small>
                      </span>
                      {organization.is_default ? <Badge tone="neutral">Default</Badge> : null}
                    </button>
                  </li>
                )
              })}
            </ResourceList>
          ) : null}
        </section>

        <section className={styles.panel} aria-labelledby="teams-heading">
          <div className={styles.panelHeader}>
            <div>
              <UsersRound size={18} aria-hidden="true" />
              <h2 id="teams-heading">Teams</h2>
            </div>
            <span>{selectedOrganization ? selectedOrganization.name : 'Select an Organization'}</span>
          </div>
          {selectedOrganization ? (
            <form className={styles.inlineForm} onSubmit={createTeam}>
              <Field label="New Team">
                <Input
                  value={teamName}
                  onChange={(event) => setTeamName(event.target.value)}
                  placeholder="Runtime Security"
                  maxLength={120}
                />
              </Field>
              <Button type="submit" variant="primary" disabled={isCreatingTeam || !teamName.trim()}>
                <Plus size={16} />
                {isCreatingTeam ? 'Creating…' : 'Create'}
              </Button>
            </form>
          ) : null}
          {!selectedOrganization ? (
            <EmptyState title="Choose an Organization" message="Teams belong to one local Organization." />
          ) : null}
          {teams.isPending && selectedOrganization ? <AsyncState status="loading" /> : null}
          {teams.isError ? (
            <AsyncState
              status="error"
              error={teams.error instanceof Error ? teams.error.message : undefined}
              onRetry={() => void teams.refetch()}
            />
          ) : null}
          {teams.data?.length === 0 ? (
            <EmptyState
              title="No Teams yet"
              message="Create a Team when a group needs Team-local resources or scoped access."
            />
          ) : null}
          {teams.data?.length ? (
            <ResourceList aria-label="Teams" className={styles.list}>
              {teams.data.map((team) => {
                const archived = Boolean(team.archived_at)
                const busy = updatingTeamID === team.id
                return (
                  <li className={styles.resource} key={team.id}>
                    <div className={styles.teamRow}>
                      <span>
                        <strong>{team.name}</strong>
                        <small>{archived ? 'Archived' : 'Active'} · Team-local scope</small>
                      </span>
                      <Button disabled={busy} onClick={() => void setArchived(team.id, team.name, !archived)}>
                        {archived ? <RotateCcw size={16} /> : <Archive size={16} />}
                        {busy ? 'Updating…' : archived ? 'Restore' : 'Archive'}
                      </Button>
                    </div>
                  </li>
                )
              })}
            </ResourceList>
          ) : null}
        </section>
      </div>
    </section>
  )
}
