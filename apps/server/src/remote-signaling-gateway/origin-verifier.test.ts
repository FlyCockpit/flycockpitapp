import { describe, expect, it } from "vitest";
import {
  OriginVerificationError,
  subprotocolExpectedOriginClass,
  verifyOriginClass,
} from "./origin-verifier";

const CONFIGURED = "https://app.example.test";

describe("remote_gateway_origin_verifier: browser_same_origin", () => {
  it("accepts exact configured origin", () => {
    const result = verifyOriginClass(CONFIGURED, CONFIGURED, "browser_same_origin");
    expect(result.class).toBe("browser_same_origin");
  });

  it("rejects absent Origin for browser class", () => {
    expect(() => verifyOriginClass(undefined, CONFIGURED, "browser_same_origin")).toThrow(
      OriginVerificationError,
    );
  });

  it("rejects null Origin", () => {
    expect(() => verifyOriginClass("null", CONFIGURED, "browser_same_origin")).toThrow(
      OriginVerificationError,
    );
  });

  it("rejects alternate scheme", () => {
    expect(() =>
      verifyOriginClass("http://app.example.test", CONFIGURED, "browser_same_origin"),
    ).toThrow(OriginVerificationError);
  });

  it("rejects alternate port", () => {
    expect(() =>
      verifyOriginClass("https://app.example.test:8080", CONFIGURED, "browser_same_origin"),
    ).toThrow(OriginVerificationError);
  });

  it("rejects subdomain", () => {
    expect(() =>
      verifyOriginClass("https://evil.app.example.test", CONFIGURED, "browser_same_origin"),
    ).toThrow(OriginVerificationError);
  });

  it("rejects multiple Origin headers", () => {
    expect(() =>
      verifyOriginClass([CONFIGURED, "https://evil.test"], CONFIGURED, "browser_same_origin"),
    ).toThrow(OriginVerificationError);
  });
});

describe("remote_gateway_origin_verifier: native/daemon no origin", () => {
  it("accepts absent Origin for native class", () => {
    const result = verifyOriginClass(undefined, CONFIGURED, "native_no_origin");
    expect(result.class).toBe("native_no_origin");
  });

  it("accepts absent Origin for daemon class", () => {
    const result = verifyOriginClass(undefined, CONFIGURED, "daemon_no_origin");
    expect(result.class).toBe("daemon_no_origin");
  });

  it("rejects present Origin for native class", () => {
    expect(() => verifyOriginClass(CONFIGURED, CONFIGURED, "native_no_origin")).toThrow(
      OriginVerificationError,
    );
  });

  it("rejects present Origin for daemon class", () => {
    expect(() => verifyOriginClass(CONFIGURED, CONFIGURED, "daemon_no_origin")).toThrow(
      OriginVerificationError,
    );
  });
});

describe("remote_gateway_origin_verifier: subprotocol mapping", () => {
  it("maps control subprotocol to daemon_no_origin", () => {
    expect(subprotocolExpectedOriginClass("flycockpit.remote-control.v1")).toBe("daemon_no_origin");
  });

  it("maps signal subprotocol to browser by default", () => {
    expect(subprotocolExpectedOriginClass("flycockpit.remote-signal.v1")).toBe(
      "browser_same_origin",
    );
  });

  it("maps signal subprotocol with native ticket class", () => {
    expect(subprotocolExpectedOriginClass("flycockpit.remote-signal.v1", "native_no_origin")).toBe(
      "native_no_origin",
    );
  });

  it("maps data subprotocol to browser by default", () => {
    expect(subprotocolExpectedOriginClass("flycockpit.remote-data.v1")).toBe("browser_same_origin");
  });
});
