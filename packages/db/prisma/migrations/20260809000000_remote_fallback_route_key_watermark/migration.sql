CREATE TABLE "remote_fallback_route_key_watermarks" (
    "deploymentId" TEXT NOT NULL,
    "highestRevision" DECIMAL(20,0) NOT NULL,
    "currentGeneration" DECIMAL(20,0) NOT NULL,
    "fileDigest" TEXT NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "remote_fallback_route_key_watermarks_pkey" PRIMARY KEY ("deploymentId")
);
