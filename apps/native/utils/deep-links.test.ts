import { describe, expect, it } from "vitest";
import { routeFromCockpitUrl } from "./deep-links";

describe("native notification deep links", () => {
  it("maps cockpit URLs that mirror web instance and session paths", () => {
    expect(routeFromCockpitUrl("cockpit:///instances/i1")).toEqual({
      pathname: "/instances/[instanceId]",
      params: { instanceId: "i1" },
    });
    expect(routeFromCockpitUrl("cockpit:///instances/i1/projects/p1/sessions/s1")).toEqual({
      pathname: "/instances/[instanceId]/projects/[projectId]",
      params: { instanceId: "i1", projectId: "p1", session: "s1" },
    });
  });

  it("keeps a cold-start target serializable for auth-gate replay", () => {
    const target = routeFromCockpitUrl(
      "cockpit:///instances/i1/projects/path%2Fwith%20space/sessions/s1/interrupts/int1",
    );
    expect(JSON.parse(JSON.stringify(target))).toEqual({
      pathname: "/instances/[instanceId]/projects/[projectId]",
      params: {
        instanceId: "i1",
        projectId: "path%2Fwith%20space",
        session: "s1",
        interrupt: "int1",
      },
    });
  });

  it("rejects unrelated or malformed URLs", () => {
    expect(routeFromCockpitUrl("https://app.flycockpit.test/instances/i1")).toBeNull();
    expect(routeFromCockpitUrl("cockpit:///projects/p1")).toBeNull();
  });
});
