import { createHash } from "node:crypto";
import { canonicalizeRfc8785 } from "@flycockpit/cockpit-protocol";
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
  bootstrapAuthority(args: {
    deploymentId: string;
    replicaId: string;
    ring: PublicAuthorityRing;
    digest: string;
  }): Promise<void>;
  loadLifecycle(deploymentId: string): Promise<AuthorityLifecycleRecord | null>;
  loadMembership(deploymentId: string): Promise<MembershipSnapshot>;
  promoteJoiningReplica(deploymentId: string, replicaId: string): Promise<boolean>;
  drainReplica(deploymentId: string, replicaId: string): Promise<boolean>;
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
  acquireStatusLease(args: {
    deploymentId: string;
    replicaId: string;
    leaseGeneration: string;
  }): Promise<boolean>;
  prepareLifecycleTransition(args: {
    transitionId: string;
    deploymentId: string;
    from: AuthorityLifecycleRecord;
    to: PublicAuthorityRing;
    toDigest: string;
    statusGeneration: string;
    statusBodyDigest: string;
    signerKid: string;
  }): Promise<boolean | string>;
  markTransitionStatusSigned(transitionId: string, compactJws: string): Promise<boolean>;
  commitLifecycleTransition(args: {
    transitionId: string;
    deploymentId: string;
    status: RemoteAuthorityStatusV1;
    compactJws: string;
    signerKid: string;
    revokedKids: string[];
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
  closeAndFreezeSigningFence(deploymentId: string, kid: string): Promise<boolean>;
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
  nextLeaseGeneration(deploymentId: string, replicaId: string): Promise<string>;
  publishLease(lease: ObservationLease, ttlSeconds: 30): Promise<void>;
  listLeases(deploymentId: string, membershipGeneration: string): Promise<ObservationLease[]>;
}
export interface AuthorityRuntimeOptions {
  keyFile: string;
  issuer: string;
  deploymentId: string;
  digests: string;
  replicaId: string;
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
  #leaseGeneration?: string;
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
  async drain() {
    this.#fail("replica_draining");
    return this.options.store.drainReplica(this.config.deploymentId, this.options.replicaId);
  }
  async tick() {
    try {
      return await this.#tick();
    } catch {
      return this.#fail("runtime_dependency_failure");
    }
  }
  async #tick() {
    let now: string;
    let convergenceLeases: ObservationLease[] = [];
    try {
      now = await this.options.observations.redisTime();
      this.#leaseGeneration ??= await this.options.observations.nextLeaseGeneration(
        this.config.deploymentId,
        this.options.replicaId,
      );
    } catch {
      return this.#fail("redis_unavailable");
    }
    const previousRedisTime = this.#lastRedisTime;
    if (previousRedisTime && BigInt(now) < BigInt(previousRedisTime))
      return this.#fail("redis_time_regression");
    this.#lastRedisTime = now;
    let ring: AuthorityRingFile;
    try {
      ring = await readAuthorityRingFile(this.options.keyFile, this.#ring?.revision, this.#ring);
    } catch {
      return this.#fail("provider_unavailable");
    }
    const digest = authorityRingDigest(ring, this.config);
    if (!this.config.allowedDigests.includes(digest)) return this.#fail("unconfigured_digest");
    const publicRing = publicAuthorityRing(ring, this.config);
    try {
      await this.options.store.bootstrapAuthority({
        deploymentId: this.config.deploymentId,
        replicaId: this.options.replicaId,
        ring: publicRing,
        digest,
      });
    } catch {
      return this.#fail("authority_bootstrap_failed");
    }
    let lifecycle = await this.options.store
      .loadLifecycle(this.config.deploymentId)
      .catch(() => null);
    if (!lifecycle) return this.#fail("lifecycle_missing");
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
    const issuerDigest = createHash("sha256").update(this.config.issuer).digest("hex"),
      lease: ObservationLease = {
        issuerDigest,
        deploymentId: this.config.deploymentId,
        membershipGeneration: membership.membershipGeneration,
        replicaId: this.options.replicaId,
        replicaGeneration: localMember.replicaGeneration,
        leaseGeneration: this.#leaseGeneration,
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
      if (localMember.state === "joining") {
        await this.options.store.promoteJoiningReplica(
          this.config.deploymentId,
          this.options.replicaId,
        );
        return this.#fail("membership_snapshot_changed");
      }
      const [leases, rings] = await Promise.all([
        this.options.observations.listLeases(
          this.config.deploymentId,
          membership.membershipGeneration,
        ),
        this.options.store.loadPublicRings(this.config.deploymentId, this.config.allowedDigests),
      ]);
      convergenceLeases = leases;
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
    if (localMember.state !== "required") return this.#fail("replica_not_required");
    if (!this.#decision.ready) return this.#fail(this.#decision.reason);
    if (lifecycle.ringDigest !== digest) {
      if (
        BigInt(ring.revision) !== BigInt(lifecycle.revision) + 1n ||
        BigInt(ring.authorityEpoch) !== BigInt(lifecycle.authorityEpoch) + 1n
      ) {
        if (BigInt(ring.revision) > BigInt(lifecycle.revision))
          return this.#fail("lifecycle_transition_required");
      } else {
        const generation = (BigInt(lifecycle.highestStatusGeneration) + 1n).toString(),
          revokedKids = publicRing.keys
            .filter((key) => key.state === "revoked")
            .map((key) => key.kid),
          candidateBody: RemoteAuthorityStatusV1 = {
            schemaVersion: 1,
            iss: this.config.issuer,
            aud: "flycockpit-remote-authority-status-v1",
            deploymentId: this.config.deploymentId,
            revision: ring.revision,
            ringDigest: digest,
            authorityEpoch: ring.authorityEpoch,
            statusGeneration: generation,
            revokedKids,
            iat: now,
            validUntil: (BigInt(now) + REMOTE_AUTHORITY.statusLifetime).toString(),
          },
          signer = new FileAuthoritySigner(ring.keys.find((key) => key.kid === ring.currentKid)!),
          transitionId = createHash("sha256")
            .update(`${this.config.deploymentId}\0${lifecycle.ringDigest}\0${digest}`)
            .digest("hex"),
          bodyDigest = createHash("sha256")
            .update(canonicalizeRfc8785(candidateBody))
            .digest("hex"),
          prepared = await this.options.store.prepareLifecycleTransition({
            transitionId,
            deploymentId: this.config.deploymentId,
            from: lifecycle,
            to: publicRing,
            toDigest: digest,
            statusGeneration: generation,
            statusBodyDigest: bodyDigest,
            signerKid: signer.kid,
          });
        if (!prepared) return this.#fail("lifecycle_transition_conflict");
        let body = candidateBody,
          compactJws: string;
        if (typeof prepared === "string") {
          compactJws = prepared;
          const payload = compactJws.split(".")[1];
          if (!payload) return this.#fail("stored_transition_status_invalid");
          body = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
          await verifyRemoteAuthorityStatusJws(compactJws, new RingAuthorityVerifier(ring, now), {
            issuer: this.config.issuer,
            deploymentId: this.config.deploymentId,
            ringDigest: digest,
            authorityEpoch: ring.authorityEpoch,
            minimumGeneration: generation,
            now,
            authorizedSignerKid: ring.currentKid,
          });
        } else compactJws = await createRemoteAuthorityStatusJws(body, signer);
        if (
          (typeof prepared !== "string" &&
            !(await this.options.store.markTransitionStatusSigned(transitionId, compactJws))) ||
          !(await this.options.store.commitLifecycleTransition({
            transitionId,
            deploymentId: this.config.deploymentId,
            status: body,
            compactJws,
            signerKid: signer.kid,
            revokedKids,
          }))
        )
          return this.#fail("lifecycle_transition_commit_failed");
        lifecycle = {
          revision: ring.revision,
          ringDigest: digest,
          authorityEpoch: ring.authorityEpoch,
          currentKid: ring.currentKid,
          revokedKids,
          highestStatusGeneration: generation,
        };
      }
    }
    if (
      this.config.allowedDigests.length === 3 &&
      digest === this.config.allowedDigests[2] &&
      convergenceLeases.every((lease) => lease.digest === digest)
    ) {
      const d1 = (
        await this.options.store.loadPublicRings(this.config.deploymentId, [
          this.config.allowedDigests[1]!,
        ])
      ).get(this.config.allowedDigests[1]!);
      if (
        !d1 ||
        !(await this.options.store.closeAndFreezeSigningFence(
          this.config.deploymentId,
          d1.currentKid,
        ))
      )
        return this.#fail("prior_signing_fence_not_frozen");
    }
    const servingPublicRing =
      lifecycle.ringDigest === digest
        ? publicRing
        : (
            await this.options.store
              .loadPublicRings(this.config.deploymentId, [lifecycle.ringDigest])
              .catch(() => new Map<string, PublicAuthorityRing>())
          ).get(lifecycle.ringDigest);
    if (!servingPublicRing) return this.#fail("committed_public_ring_missing");
    let status = await this.options.store
      .loadHighestFinalizedStatus({
        deploymentId: this.config.deploymentId,
        ringDigest: lifecycle.ringDigest,
        authorityEpoch: lifecycle.authorityEpoch,
      })
      .catch(() => null);
    if (status) {
      try {
        const verified = await verifyRemoteAuthorityStatusJws(
          status.compactJws,
          new RingAuthorityVerifier(servingPublicRing, now),
          {
            issuer: this.config.issuer,
            deploymentId: this.config.deploymentId,
            ringDigest: lifecycle.ringDigest,
            authorityEpoch: lifecycle.authorityEpoch,
            minimumGeneration: "0",
            now,
            authorizedSignerKid: lifecycle.currentKid,
          },
        );
        if (verified.payload.statusGeneration !== status.status.statusGeneration) status = null;
        else status = { compactJws: status.compactJws, status: verified.payload };
      } catch {
        status = null;
      }
    }
    const mustRecover =
      this.#recoveryMinimumGeneration !== undefined &&
      (!status ||
        BigInt(status.status.statusGeneration) <= BigInt(this.#recoveryMinimumGeneration));
    const localMayIssueStatus = this.#decision.signingKid === lifecycle.currentKid;
    if (
      (!status || mustRecover || BigInt(status.status.validUntil) <= BigInt(now) + 40n) &&
      localMayIssueStatus
    ) {
      try {
        const elected = await this.options.store.acquireStatusLease({
          deploymentId: this.config.deploymentId,
          replicaId: this.options.replicaId,
          leaseGeneration: this.#leaseGeneration,
        });
        if (!elected) {
          const winner = await this.options.store.loadHighestFinalizedStatus({
            deploymentId: this.config.deploymentId,
            ringDigest: lifecycle.ringDigest,
            authorityEpoch: lifecycle.authorityEpoch,
          });
          if (winner && BigInt(winner.status.validUntil) > BigInt(now)) status = winner;
          else return this.#fail("status_election_wait");
        } else {
          const signer = new FileAuthoritySigner(
            ring.keys.find((k) => k.kid === this.#decision.signingKid)!,
          );
          const generation = (BigInt(lifecycle.highestStatusGeneration) + 1n).toString(),
            body: RemoteAuthorityStatusV1 = {
              schemaVersion: 1,
              iss: this.config.issuer,
              aud: "flycockpit-remote-authority-status-v1",
              deploymentId: this.config.deploymentId,
              revision: lifecycle.revision,
              ringDigest: lifecycle.ringDigest,
              authorityEpoch: lifecycle.authorityEpoch,
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
          if (!committed) {
            status = await this.options.store.loadHighestFinalizedStatus({
              deploymentId: this.config.deploymentId,
              ringDigest: lifecycle.ringDigest,
              authorityEpoch: lifecycle.authorityEpoch,
            });
            if (!status) return this.#fail("status_generation_conflict");
          } else status = { status: body, compactJws };
        }
      } catch {
        return this.#fail("status_refresh_failed");
      }
    }
    if (!status) return this.#fail("current_status_unavailable");
    if (
      this.#recoveryMinimumGeneration !== undefined &&
      BigInt(status.status.statusGeneration) <= BigInt(this.#recoveryMinimumGeneration)
    )
      return this.#fail("fresh_recovery_status_required");
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
      publicAuthorityJwks(servingPublicRing, now),
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
    if (
      reserved.deploymentId !== this.config.deploymentId ||
      reserved.kid !== this.#signer.kid ||
      reserved.signingGeneration !== generation ||
      reserved.claimsHash !== claimsHash
    )
      throw new Error("mint request conflict");
    if (reserved.state === "finalized" && reserved.compactJws) return reserved.compactJws;
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
    if (this.#status) this.#recoveryMinimumGeneration = this.#status.status.statusGeneration;
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
