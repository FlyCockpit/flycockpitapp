import { describe, expect, it } from "vitest";
import {
  remoteAdminAssertionOptions,
  remoteAdminRegistrationOptions,
} from "./remote-admin-passkey";

describe("remote_admin_passkey_web_accessibility", () => {
  it("builds the closed five-minute UV ES256 discoverable registration contract", () => {
    const options = remoteAdminRegistrationOptions({
      challenge: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
      rpId: "admin.example.com",
      userId: new Uint8Array(16).fill(2),
    });
    expect(new Uint8Array(options.challenge)).toHaveLength(32);
    expect(options.timeout).toBe(300_000);
    expect(options.authenticatorSelection).toMatchObject({
      residentKey: "preferred",
      userVerification: "required",
    });
    expect(options.pubKeyCredParams).toEqual([{ type: "public-key", alg: -7 }]);
    expect(options.attestation).toBe("none");
  });

  it("requires UV for discoverable assertions", () => {
    const options = remoteAdminAssertionOptions({
      challenge: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
      rpId: "admin.example.com",
    });
    expect(options.userVerification).toBe("required");
    expect(options.allowCredentials).toBeUndefined();
  });
});
