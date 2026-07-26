export type IdentityTopologyProbe = {
  email: string;
  serverUrl: string;
  directDatabaseEndpoint: string;
  kubeContext: string;
  removeDirectFixture: () => Promise<void>;
  createThroughServer: () => Promise<Response>;
  directFixtureExists: () => Promise<boolean>;
};

/**
 * Proves that browser setup's direct SQL connection and the server reached by
 * SERVER_URL share the same identity database. It deliberately cleans only
 * after the direct connection has observed the server-created fixture: a split
 * topology must fail loudly instead of pretending the fixture was cleaned.
 */
export async function assertIdentityTopology(
  probe: IdentityTopologyProbe,
): Promise<void> {
  await probe.removeDirectFixture();

  const response = await probe.createThroughServer();
  if (!response.ok) {
    throw new Error(
      `Dashboard E2E identity topology probe could not create ${probe.email} through SERVER_URL=${probe.serverUrl}: ${response.status} ${await response.text()} (DATABASE_URL=${probe.directDatabaseEndpoint}, KUBE_CONTEXT=${probe.kubeContext}). Refusing to run browser tests without a coherent identity plane.`,
    );
  }

  if (!(await probe.directFixtureExists())) {
    throw new Error(
      `Dashboard E2E identity topology mismatch: SERVER_URL=${probe.serverUrl} created ${probe.email}, but DATABASE_URL=${probe.directDatabaseEndpoint} cannot observe it (KUBE_CONTEXT=${probe.kubeContext}). Refusing to run browser tests against split identity planes.`,
    );
  }

  await probe.removeDirectFixture();
}
