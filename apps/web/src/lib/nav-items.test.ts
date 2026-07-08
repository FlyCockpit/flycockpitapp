import { describe, expect, it } from "vitest";

import { getNavDirection, getNavItems, stripLangPrefix, toLangRoute } from "./nav-items";

describe("nav-items", () => {
  it("returns public desktop items for signed-out visitors", () => {
    const items = getNavItems({
      placement: "desktop",
      isAuthenticated: false,
    }).map((item) => item.path);

    expect(items).toEqual(["/", "/about", "/cookie-policy"]);
  });

  it("keeps public desktop items and adds app items for signed-in users", () => {
    const items = getNavItems({
      placement: "desktop",
      isAuthenticated: true,
      role: "user",
    }).map((item) => item.path);

    expect(items).toEqual([
      "/",
      "/about",
      "/cookie-policy",
      "/dashboard",
      "/instances",
      "/settings",
    ]);
    expect(items).not.toContain("/admin");
  });

  it("adds admin destinations only when the shared admin role helper matches", () => {
    const nonAdminItems = getNavItems({
      placement: "desktop",
      isAuthenticated: true,
      role: "manager",
    }).map((item) => item.path);
    const adminItems = getNavItems({
      placement: "desktop",
      isAuthenticated: true,
      role: "user, admin",
    }).map((item) => item.path);

    expect(nonAdminItems).not.toContain("/admin");
    expect(adminItems).toContain("/admin");
  });

  it("keeps mobile navigation compact and role-aware", () => {
    const signedOutItems = getNavItems({
      placement: "mobile",
      isAuthenticated: false,
    }).map((item) => item.path);
    const adminItems = getNavItems({
      placement: "mobile",
      isAuthenticated: true,
      role: "admin",
    }).map((item) => item.path);

    expect(signedOutItems).toEqual(["/"]);
    expect(adminItems).toEqual(["/", "/dashboard", "/instances", "/settings", "/admin"]);
  });

  it("derives user-menu destinations from the shared nav model", () => {
    const userItems = getNavItems({
      placement: "userMenu",
      isAuthenticated: true,
      role: "user",
    }).map((item) => item.path);
    const adminItems = getNavItems({
      placement: "userMenu",
      isAuthenticated: true,
      role: "admin",
    }).map((item) => item.path);

    expect(userItems).toEqual(["/settings"]);
    expect(adminItems).toEqual(["/settings", "/admin"]);
  });

  it("builds typed locale-prefixed routes", () => {
    expect(toLangRoute("/")).toBe("/$lang");
    expect(toLangRoute("/dashboard")).toBe("/$lang/dashboard");
  });

  it("returns forward for later items in the composed app nav list", () => {
    expect(getNavDirection("/", "/dashboard")).toBe("forward");
    expect(getNavDirection("/dashboard", "/instances")).toBe("forward");
    expect(getNavDirection("/instances", "/settings")).toBe("forward");
  });

  it("returns back for earlier items in the composed app nav list", () => {
    expect(getNavDirection("/settings", "/instances")).toBe("back");
    expect(getNavDirection("/instances", "/dashboard")).toBe("back");
    expect(getNavDirection("/dashboard", "/about")).toBe("back");
  });

  it("returns none for same-path navigation", () => {
    expect(getNavDirection("/settings", "/settings")).toBe("none");
  });

  it("returns forward for off-nav child routes", () => {
    expect(getNavDirection("/settings", "/settings/privacy")).toBe("forward");
  });

  it("returns back from child routes to their parent", () => {
    expect(getNavDirection("/settings/privacy", "/settings")).toBe("back");
  });

  it("returns back when moving left across settings sub-nav siblings", () => {
    expect(getNavDirection("/settings/privacy", "/settings/security")).toBe("back");
  });

  it("returns forward when moving right across settings sub-nav siblings", () => {
    expect(getNavDirection("/settings/security", "/settings/privacy")).toBe("forward");
  });

  it("defaults unrelated routes to forward", () => {
    expect(getNavDirection("/dashboard", "/login")).toBe("forward");
  });

  it("strips the locale prefix from top-level routes", () => {
    expect(stripLangPrefix("/en-US/dashboard")).toBe("/dashboard");
  });

  it("returns root when only the locale segment is present", () => {
    expect(stripLangPrefix("/en-US")).toBe("/");
    expect(stripLangPrefix("/en-US/")).toBe("/");
  });

  it("preserves nested segments after stripping the locale prefix", () => {
    expect(stripLangPrefix("/en-US/settings/privacy")).toBe("/settings/privacy");
  });
});
