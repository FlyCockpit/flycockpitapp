import { createHash } from "node:crypto";
import {
  type AuthorityConfig,
  AuthorityPublicSnapshot,
  type AuthorityRingFile,
  authorityRingDigest,
  createRemoteAuthorityStatusJws,
  FileAuthoritySigner,
  type MembershipSnapshot,
  type ObservationLease,
  type PublicAuthorityRing,
  parseAuthorityConfig,
  publicAuthorityJwks,
  publicAuthorityRing,
  REMOTE_AUTHORITY,
  type RemoteAuthorityStatusV1,
  RingAuthorityVerifier,
  type RolloutDecision,
  reduceAuthorityRollout,
  type SigningJournalEntry,
  verifyRemoteAuthorityStatusJws,
} from "./remote-authority";
import { readAuthorityRingFile } from "./remote-authority-file";

export interface AuthorityLifecycleRecord {
  revision: string;
  ringDigest: string;
  authorityEpoch: string;
  currentKid: string;
  revokedKids: string[];
  highestStatusGeneration: string;
}
export interface FinalizedAuthorityStatus {
  compactJws: string;
  status: RemoteAuthorityStatusV1;
}
export interface AuthorityRuntimeStore {
  loadLifecycle(deploymentId: string): Promise<AuthorityLifecycleRecord | null>;
  loadMembership(deploymentId: string): Promise<MembershipSnapshot>;
  loadPublicRings(
    deploymentId: string,
    digests: readonly string[],
  ): Promise<ReadonlyMap<string, PublicAuthorityRing>>;
  observePublicRing(deploymentId: string, digest: string, ring: PublicAuthorityRing): Promise<void>;
  loadHighestFinalizedStatus(scope: {
    deploymentId: string;
    ringDigest: string;
    authorityEpoch: string;
  }): Promise<FinalizedAuthorityStatus | null>;
  reserveAndFinalizeStatus(args: {
    deploymentId: string;
    expectedGeneration: string;
    status: RemoteAuthorityStatusV1;
    compactJws: string;
    bodyDigest: string;
  }): Promise<boolean>;
  reserveMint(args: {
    deploymentId: string;
    mintId: string;
    kid: string;
    signingGeneration: string;
    claimsHash: string;
  }): Promise<SigningJournalEntry>;
  ensureOpenSigningFence(args: {
    deploymentId: string;
    kid: string;
    signingGeneration: string;
  }): Promise<boolean>;
  finalizeMint(args: {
    mintId: string;
    signingGeneration: string;
    claimsHash: string;
    signatureP1363: string;
    compactJws: string;
  }): Promise<SigningJournalEntry>;
}
export interface AuthorityObservationStore {
  redisTime(): Promise<string>;
  publishLease(lease: ObservationLease, ttlSeconds: 30): Promise<void>;
  listLeases(deploymentId: string, membershipGeneration: string): Promise<ObservationLease[]>;
}
export interface AuthorityRuntimeOptions {
  keyFile: string;
  issuer: string;
  deploymentId: string;
  digests: string;
  replicaId: string;
  leaseGeneration: string;
  store: AuthorityRuntimeStore;
  observations: AuthorityObservationStore;
  snapshot: AuthorityPublicSnapshot;
}
export class RemoteAuthorityRuntime {
  readonly config: AuthorityConfig;
  #ring?: AuthorityRingFile;
  #signer?: FileAuthoritySigner;
  #lastRedisTime?: string;
  #decision: RolloutDecision = {
    ready: false,
    mayMint: false,
    signingKid: null,
    phase: "unavailable",
    reason: "not_started",
  };
  #status?: FinalizedAuthorityStatus;
  #recoveryMinimumGeneration?: string;
  #lastSuccessfulTickAt = 0;
  constructor(private readonly options: AuthorityRuntimeOptions) {
    this.config = parseAuthorityConfig({
      issuer: options.issuer,
      deploymentId: options.deploymentId,
      digests: options.digests,
    });
  }
  get decision() {
    return this.#decision;
  }
  async tick() {
    let now: string;
    try {
      now = await this.options.observations.redisTime();
    } catch {
      return this.#fail("redis_unavailable");
    }
    const previousRedisTime = this.#lastRedisTime;
    if (previousRedisTime && BigInt(now) < BigInt(previousRedisTime))
      return this.#fail("redis_time_regression");
    this.#lastRedisTime = now;
    let ring: AuthorityRingFile;
    try {
      ring = await readAuthorityRingFile(this.options.keyFile, this.#ring?.revision);
    } catch (error) {
      if (this.#ring && error instanceof Error && error.message.includes("nonmonotonic"))
        ring = this.#ring;
      else return this.#fail("provider_unavailable");
    }
    const digest = authorityRingDigest(ring, this.config);
    if (!this.config.allowedDigests.includes(digest)) return this.#fail("unconfigured_digest");
    const lifecycle = await this.options.store
      .loadLifecycle(this.config.deploymentId)
      .catch(() => null);
    if (
      !lifecycle ||
      lifecycle.ringDigest !== digest ||
      lifecycle.revision !== ring.revision ||
      lifecycle.authorityEpoch !== ring.authorityEpoch ||
      lifecycle.currentKid !== ring.currentKid
    )
      return this.#fail("lifecycle_mismatch");
    const membership = await this.options.store
      .loadMembership(this.config.deploymentId)
      .catch(() => null);
    if (!membership) return this.#fail("membership_unavailable");
    const localMember = membership.members.find(
      (member) => member.replicaId === this.options.replicaId,
    );
    if (!localMember) return this.#fail("replica_not_member");
    const signingKey = ring.keys.find((key) => key.kid === ring.currentKid),
      time = BigInt(now);
    if (
      !signingKey ||
      BigInt(signingKey.activatedAt) > time ||
      (signingKey.retireAt !== null && BigInt(signingKey.retireAt) <= time)
    )
      return this.#fail("signing_key_not_active");
    const publicRing = publicAuthorityRing(ring, this.config),
      issuerDigest = createHash("sha256").update(this.config.issuer).digest("hex"),
      lease: ObservationLease = {
        issuerDigest,
        deploymentId: this.config.deploymentId,
        membershipGeneration: membership.membershipGeneration,
        replicaId: this.options.replicaId,
        replicaGeneration: localMember.replicaGeneration,
        leaseGeneration: this.options.leaseGeneration,
        revision: ring.revision,
        digest,
        currentKid: ring.currentKid,
        publicKids: publicRing.keys.filter((k) => k.state !== "revoked").map((k) => k.kid),
        authorityEpoch: ring.authorityEpoch,
        observedRedisTime: now,
        expiresAt: (BigInt(now) + REMOTE_AUTHORITY.leaseTtl).toString(),
      };
    try {
      await this.options.store.observePublicRing(this.config.deploymentId, digest, publicRing);
      await this.options.observations.publishLease(lease, 30);
      const [leases, rings] = await Promise.all([
        this.options.observations.listLeases(
          this.config.deploymentId,
          membership.membershipGeneration,
        ),
        this.options.store.loadPublicRings(this.config.deploymentId, this.config.allowedDigests),
      ]);
      this.#decision = reduceAuthorityRollout({
        now,
        previousRedisTime,
        issuerDigest,
        deploymentId: this.config.deploymentId,
        snapshot: membership,
        leases,
        plan: this.config.allowedDigests as [string] | [string, string, string],
        rings,
        localDigest: digest,
      });
    } catch {
      return this.#fail("observation_unavailable");
    }
    if (!this.#decision.ready) return this.#decision;
    let status = await this.options.store
      .loadHighestFinalizedStatus({
        deploymentId: this.config.deploymentId,
        ringDigest: digest,
        authorityEpoch: ring.authorityEpoch,
      })
      .catch(() => null);
    if (status) {
      try {
        const verified = await verifyRemoteAuthorityStatusJws(
          status.compactJws,
          new RingAuthorityVerifier(ring, now),
          {
            issuer: this.config.issuer,
            deploymentId: this.config.deploymentId,
            ringDigest: digest,
            authorityEpoch: ring.authorityEpoch,
            minimumGeneration: "0",
            now,
          },
        );
        if (
          verified.header.kid !== ring.currentKid ||
          verified.payload.statusGeneration !== status.status.statusGeneration
        )
          status = null;
        else status = { compactJws: status.compactJws, status: verified.payload };
      } catch {
        status = null;
      }
    }
    const mustRecover =
      this.#recoveryMinimumGeneration !== undefined &&
      (!status ||
        BigInt(status.status.statusGeneration) <= BigInt(this.#recoveryMinimumGeneration));
    if (!status || mustRecover || BigInt(status.status.validUntil) <= BigInt(now) + 40n) {
      try {
        const signer = new FileAuthoritySigner(
          ring.keys.find((k) => k.kid === this.#decision.signingKid)!,
        );
        const generation = (BigInt(lifecycle.highestStatusGeneration) + 1n).toString(),
          body: RemoteAuthorityStatusV1 = {
            schemaVersion: 1,
            iss: this.config.issuer,
            aud: "flycockpit-remote-authority-status-v1",
            deploymentId: this.config.deploymentId,
            revision: ring.revision,
            ringDigest: digest,
            authorityEpoch: ring.authorityEpoch,
            statusGeneration: generation,
            revokedKids: [...new Set(lifecycle.revokedKids)].sort((a, b) =>
              Buffer.compare(Buffer.from(a), Buffer.from(b)),
            ),
            iat: now,
            validUntil: (BigInt(now) + 60n).toString(),
          },
          compactJws = await createRemoteAuthorityStatusJws(body, signer),
          committed = await this.options.store.reserveAndFinalizeStatus({
            deploymentId: this.config.deploymentId,
            expectedGeneration: lifecycle.highestStatusGeneration,
            status: body,
            compactJws,
            bodyDigest: createHash("sha256").update(compactJws).digest("hex"),
          });
        if (!committed) return this.#fail("status_generation_conflict");
        status = { status: body, compactJws };
      } catch {
        return this.#fail("status_refresh_failed");
      }
    }
    if (BigInt(status.status.validUntil) <= BigInt(now)) return this.#fail("status_expired");
    this.#ring = ring;
    this.#signer = new FileAuthoritySigner(
      ring.keys.find((k) => k.kid === this.#decision.signingKid)!,
    );
    this.#status = status;
    if (
      !(await this.options.store
        .ensureOpenSigningFence({
          deploymentId: this.config.deploymentId,
          kid: this.#signer.kid,
          signingGeneration: ring.authorityEpoch,
        })
        .catch(() => false))
    )
      return this.#fail("signing_fence_unavailable");
    this.#recoveryMinimumGeneration = undefined;
    this.#lastSuccessfulTickAt = Date.now();
    this.options.snapshot.publish(
      publicAuthorityJwks(ring, now),
      status.compactJws,
      status.status.validUntil,
      now,
    );
    return this.#decision;
  }
  async mint(mintId: string, claims: Uint8Array, compact: (signature: Uint8Array) => string) {
    if (!this.#decision.mayMint || !this.#signer || !this.#status)
      throw new Error("remote authority not ready");
    const wallNow = BigInt(Math.floor(Date.now() / 1000));
    if (
      Date.now() - this.#lastSuccessfulTickAt > 10_000 ||
      wallNow >= BigInt(this.#status.status.validUntil)
    ) {
      this.#fail("mint_freshness_expired");
      throw new Error("remote authority freshness expired");
    }
    const claimsHash = createHash("sha256").update(claims).digest("hex"),
      generation = this.#ring!.authorityEpoch;
    const reserved = await this.options.store.reserveMint({
      deploymentId: this.config.deploymentId,
      mintId,
      kid: this.#signer.kid,
      signingGeneration: generation,
      claimsHash,
    });
    if (reserved.state === "finalized" && reserved.compactJws) return reserved.compactJws;
    if (
      reserved.deploymentId !== this.config.deploymentId ||
      reserved.kid !== this.#signer.kid ||
      reserved.signingGeneration !== generation ||
      reserved.claimsHash !== claimsHash
    )
      throw new Error("mint request conflict");
    const signature = await this.#signer.signP1363(claims, mintId),
      jws = compact(signature),
      finalized = await this.options.store.finalizeMint({
        mintId,
        signingGeneration: generation,
        claimsHash,
        signatureP1363: Buffer.from(signature).toString("base64url"),
        compactJws: jws,
      });
    if (finalized.state !== "finalized" || finalized.compactJws !== jws)
      throw new Error("late or conflicting signing result");
    return jws;
  }
  #fail(reason: string) {
    if (this.#decision.ready && this.#status)
      this.#recoveryMinimumGeneration = this.#status.status.statusGeneration;
    this.#decision = {
      ready: false,
      mayMint: false,
      signingKid: null,
      phase: "unavailable",
      reason,
    };
    this.#signer = undefined;
    return this.#decision;
  }
}
