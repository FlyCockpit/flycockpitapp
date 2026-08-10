import { describe, expect, it } from "vitest";
import fixture from "../fixtures/dependency-health-v1.json";
import {
  DEPENDENCY_HEALTH_SCHEMA_VERSION,
  type DependencyHealthSnapshotV1,
  DependencyHealthSnapshotV1Schema,
} from "./dependency-health";

const typedFixture: DependencyHealthSnapshotV1 = DependencyHealthSnapshotV1Schema.parse(fixture);

describe("dependency health schema", () => {
  it("keeps the fixture on version 1", () => {
    expect(typedFixture.schema_version).toBe(DEPENDENCY_HEALTH_SCHEMA_VERSION);
    expect(typedFixture.rows[0]?.id).toBe("git");
  });
});
