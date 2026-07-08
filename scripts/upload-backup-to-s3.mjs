#!/usr/bin/env node
import { createReadStream } from "node:fs";
import { basename } from "node:path";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";

const file = process.argv[2];
if (!file) {
  console.error("FATAL: backup upload requires a file path argument.");
  process.exit(1);
}

const bucket = process.env.BACKUP_S3_BUCKET;
if (!bucket) {
  console.error("FATAL: BACKUP_S3_BUCKET is not set.");
  process.exit(1);
}

const accessKeyId = process.env.BACKUP_S3_ACCESS_KEY_ID ?? process.env.S3_ACCESS_KEY_ID;
const secretAccessKey = process.env.BACKUP_S3_SECRET_ACCESS_KEY ?? process.env.S3_SECRET_ACCESS_KEY;

if (!accessKeyId || !secretAccessKey) {
  console.error(
    "FATAL: Set BACKUP_S3_ACCESS_KEY_ID/BACKUP_S3_SECRET_ACCESS_KEY or S3_ACCESS_KEY_ID/S3_SECRET_ACCESS_KEY.",
  );
  process.exit(1);
}

const prefix = (process.env.BACKUP_S3_PREFIX ?? "database").replace(/^\/+|\/+$/g, "");
const key = `${prefix}/${basename(file)}`;

const client = new S3Client({
  region: process.env.BACKUP_S3_REGION ?? process.env.S3_REGION ?? "auto",
  endpoint: process.env.BACKUP_S3_ENDPOINT ?? process.env.S3_ENDPOINT,
  forcePathStyle:
    (process.env.BACKUP_S3_FORCE_PATH_STYLE ?? process.env.S3_FORCE_PATH_STYLE) === "true",
  credentials: { accessKeyId, secretAccessKey },
});

await client.send(
  new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    Body: createReadStream(file),
    ContentType: "application/sql",
  }),
);

console.log(`Uploaded backup to s3://${bucket}/${key}`);
