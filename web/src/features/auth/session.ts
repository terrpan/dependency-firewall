export async function resolveAuthorizationHeader(
  getAccessToken: () => Promise<string | null>,
): Promise<HeadersInit | undefined> {
  const accessToken = (await getAccessToken())?.trim()
  return accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined
}
