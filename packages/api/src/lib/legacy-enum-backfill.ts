import prisma from "@flycockpit/db";

type CountResult = { count: number };
type UpdateMany<Model> = (args: {
  where: Partial<Record<keyof Model, unknown>>;
  data: Partial<Record<keyof Model, unknown>>;
}) => Promise<CountResult>;
type Count<Model> = (args: { where: Partial<Record<keyof Model, unknown>> }) => Promise<number>;

type AssetBackfill = {
  metadataState: unknown;
  isMetadataVerified: unknown;
};
type VideoBackfill = {
  ladderPolicy: unknown;
  ladderIncludes4k: unknown;
};

export type LegacyEnumBackfillClient = {
  asset: {
    count: Count<AssetBackfill>;
    updateMany: UpdateMany<AssetBackfill>;
  };
  video: {
    count: Count<VideoBackfill>;
    updateMany: UpdateMany<VideoBackfill>;
  };
};

export type LegacyEnumBackfillCounts = {
  assetsServerVerified: number;
  assetsClientHint: number;
  videosInclude4k: number;
  videosStandard: number;
};

export type LegacyEnumBackfillStatus = {
  assetsRemaining: number;
  videosRemaining: number;
  totalRemaining: number;
};

const defaultClient = prisma as unknown as LegacyEnumBackfillClient;

export async function getLegacyEnumBackfillStatus(
  client: LegacyEnumBackfillClient = defaultClient,
): Promise<LegacyEnumBackfillStatus> {
  const [assetsRemaining, videosRemaining] = await Promise.all([
    client.asset.count({ where: { metadataState: null } }),
    client.video.count({ where: { ladderPolicy: null } }),
  ]);

  return {
    assetsRemaining,
    videosRemaining,
    totalRemaining: assetsRemaining + videosRemaining,
  };
}

export async function backfillLegacyEnumColumns(
  client: LegacyEnumBackfillClient = defaultClient,
): Promise<{ changed: LegacyEnumBackfillCounts; remaining: LegacyEnumBackfillStatus }> {
  const assetsServerVerified = await client.asset.updateMany({
    where: { metadataState: null, isMetadataVerified: true },
    data: { metadataState: "SERVER_VERIFIED" },
  });
  const assetsClientHint = await client.asset.updateMany({
    where: { metadataState: null, isMetadataVerified: false },
    data: { metadataState: "CLIENT_HINT" },
  });
  console.info("[maintenance] legacy enum backfill assets", {
    serverVerified: assetsServerVerified.count,
    clientHint: assetsClientHint.count,
  });

  const videosInclude4k = await client.video.updateMany({
    where: { ladderPolicy: null, ladderIncludes4k: true },
    data: { ladderPolicy: "INCLUDE_4K" },
  });
  const videosStandard = await client.video.updateMany({
    where: { ladderPolicy: null, ladderIncludes4k: false },
    data: { ladderPolicy: "STANDARD" },
  });
  console.info("[maintenance] legacy enum backfill videos", {
    include4k: videosInclude4k.count,
    standard: videosStandard.count,
  });

  return {
    changed: {
      assetsServerVerified: assetsServerVerified.count,
      assetsClientHint: assetsClientHint.count,
      videosInclude4k: videosInclude4k.count,
      videosStandard: videosStandard.count,
    },
    remaining: await getLegacyEnumBackfillStatus(client),
  };
}
