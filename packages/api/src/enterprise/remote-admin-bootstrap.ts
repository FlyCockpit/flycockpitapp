import type { RemoteAdminCustody } from "@flycockpit/cockpit-protocol";

/** Public-only registration result. Attestation, userHandle, raw credential id never persist here. */
export type VerifiedPublicCredential = {
  credentialIdHash: Uint8Array;
  p256X: Uint8Array;
  p256Y: Uint8Array;
  coseAlg: -7;
  declaredCustody: RemoteAdminCustody;
};

export type BootstrapChallenge = {
  id: string;
  kind: "OWNER_BOOTSTRAP" | "SECURITY_ADMIN_BOOTSTRAP";
  orgId: string | null;
  nominatorId: string;
  nomineeId: string;
  requestDigest: Uint8Array;
  challengeHash: Uint8Array;
  issuedAt: number;
  expiresAt: number;
  consumedAt: number | null;
  committedDigest: Uint8Array | null;
  committedResult: unknown | null;
};

export type BootstrapSnapshot = {
  challenge: BootstrapChallenge;
  nominator: { id: string; active: boolean; role: "OWNER" | "SECURITY_ADMIN" | "MEMBER" };
  nominee: { id: string; active: boolean; role: "OWNER" | "SECURITY_ADMIN" | "MEMBER" };
  ownerBootstrapSealed: boolean;
  securityAdminBootstrapSealed: boolean;
  activeSecurityAdmins: number;
};

export type BootstrapTransaction<Result> = {
  serializable<T>(callback: () => Promise<T>): Promise<T>;
  lockChallenge(id: string): Promise<BootstrapSnapshot>;
  insertCredentialAndMembership(input: {
    challengeId: string;
    orgId: string | null;
    principalId: string;
    role: "OWNER" | "SECURITY_ADMIN";
    credential: VerifiedPublicCredential;
    registryGeneration: bigint;
  }): Promise<Result>;
  sealAndAudit(input: {
    challengeId: string;
    kind: BootstrapChallenge["kind"];
    result: Result;
    committedDigest: Uint8Array;
    registryGeneration: bigint;
  }): Promise<void>;
};

const equal = (left: Uint8Array | null, right: Uint8Array) =>
  left !== null &&
  left.length === right.length &&
  left.every((value, index) => value === right[index]);

/**
 * Transaction barrier for both one-time bootstraps. The caller verifies the UV
 * registration and canonical review digest before entering this function.
 */
export async function commitRemoteAdminBootstrap<Result>(input: {
  tx: BootstrapTransaction<Result>;
  challengeId: string;
  now: number;
  acceptedDigest: Uint8Array;
  credential: VerifiedPublicCredential;
}): Promise<Result> {
  return input.tx.serializable(async () => {
    const snapshot = await input.tx.lockChallenge(input.challengeId);
    const { challenge } = snapshot;
    if (challenge.consumedAt !== null) {
      if (
        equal(challenge.committedDigest, input.acceptedDigest) &&
        challenge.committedResult !== null
      )
        return challenge.committedResult as Result;
      throw new Error("remote_admin_bootstrap_changed_retry");
    }
    const expectedTtl = challenge.kind === "OWNER_BOOTSTRAP" ? 5 * 60 * 1000 : 15 * 60 * 1000;
    if (input.now > challenge.expiresAt || challenge.expiresAt - challenge.issuedAt !== expectedTtl)
      throw new Error("remote_admin_bootstrap_expired");
    if (!equal(challenge.requestDigest, input.acceptedDigest))
      throw new Error("remote_admin_bootstrap_digest_changed");
    if (!snapshot.nominator.active || !snapshot.nominee.active)
      throw new Error("remote_admin_bootstrap_principal_invalid");

    let role: "OWNER" | "SECURITY_ADMIN";
    let generation: bigint;
    if (challenge.kind === "OWNER_BOOTSTRAP") {
      if (
        snapshot.ownerBootstrapSealed ||
        challenge.orgId !== null ||
        snapshot.nominee.role !== "MEMBER"
      )
        throw new Error("remote_admin_owner_bootstrap_closed");
      role = "OWNER";
      generation = 1n;
    } else {
      if (
        snapshot.nominator.id === snapshot.nominee.id ||
        snapshot.securityAdminBootstrapSealed ||
        snapshot.activeSecurityAdmins !== 0 ||
        !snapshot.ownerBootstrapSealed ||
        snapshot.nominator.role !== "OWNER" ||
        snapshot.nominee.role !== "MEMBER" ||
        challenge.orgId === null
      )
        throw new Error("remote_admin_security_bootstrap_closed");
      role = "SECURITY_ADMIN";
      generation = 2n;
    }
    const result = await input.tx.insertCredentialAndMembership({
      challengeId: challenge.id,
      orgId: challenge.orgId,
      principalId: snapshot.nominee.id,
      role,
      credential: input.credential,
      registryGeneration: generation,
    });
    await input.tx.sealAndAudit({
      challengeId: challenge.id,
      kind: challenge.kind,
      result,
      committedDigest: input.acceptedDigest,
      registryGeneration: generation,
    });
    return result;
  });
}
