import path from "node:path";

import dotenv from "dotenv";
import { defineConfig } from "prisma/config";

// Resolve relative to this config file so Prisma commands work from any CWD.
// dotenv won't override an existing DATABASE_URL, so external values still win.
dotenv.config({
  path: path.resolve(import.meta.dirname, "../../.env"),
});

export default defineConfig({
  schema: path.join("prisma", "schema"),
  migrations: {
    path: path.join("prisma", "migrations"),
  },
  datasource: {
    url: process.env.DATABASE_URL,
  },
});
