export type IdentityTopologyProbe = {
  email: string;
  serverUrl: string;
  directDatabaseEndpoint: string;
  kubeContext: string;
  removeDirectFixture: () => Promise<void>;
  seedDirectFixture: () => Promise<void>;
  signInThroughServer: () => Promise<Response>;
  directSessionExists: () => Promise<boolean>;
};

/**
 * Proves that browser setup's direct SQL connection and the server reached by
 * SERVER_URL share the same identity database: the server must authenticate a
 * directly seeded synthetic identity, and direct SQL must observe the session
 * created by that sign-in. Merely finding the seeded user would not prove this.
 */
export async function assertIdentityTopology(
  probe: IdentityTopologyProbe,
): Promise<void> {
  await probe.removeDirectFixture();

  try {
    await probe.seedDirectFixture();
    const response = await probe.signInThroughServer();
    if (!response.ok) {
      throw new Error(
        `Dashboard E2E identity topology probe could not sign in ${probe.email} through SERVER_URL=${probe.serverUrl}: ${response.status} ${await response.text()} (DATABASE_URL=${probe.directDatabaseEndpoint}, KUBE_CONTEXT=${probe.kubeContext}). Refusing to run browser tests without a coherent identity plane.`,
      );
    }

    if (!(await probe.directSessionExists())) {
      throw new Error(
        `Dashboard E2E identity topology mismatch: SERVER_URL=${probe.serverUrl} accepted ${probe.email}, but DATABASE_URL=${probe.directDatabaseEndpoint} cannot observe its new session (KUBE_CONTEXT=${probe.kubeContext}). Refusing to run browser tests against split identity planes.`,
      );
    }
  } finally {
    // Clean only our direct fixture even on failure; no remote cleanup claim.
    await probe.removeDirectFixture();
  }
}
