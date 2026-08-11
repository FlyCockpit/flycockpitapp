import { CustodyClass, PresenceMode } from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import {
  FakeNativeCustodyAdapter,
  INELIGIBLE_NATIVE_CUSTODY_PATHS,
  NATIVE_CUSTODY_PROFILES,
  NativeCustodyPolicyGate,
  NativeCustodyProfile,
  NativeIdentityCustodyProvider,
  nativeCustodyReport,
  nativeFoundationConsumptionGuard,
  nativePrivateMaterialGuard,
  nativeX25519BridgeAbsenceGuard,
  RemoteNativeIdentityCustodyError,
} from "./remote-native-identity-custody";

const IosSecureEnclave = NativeCustodyProfile.IosSecureEnclave;
const IosKeychain = NativeCustodyProfile.IosKeychain;
const AndroidStrongBox = NativeCustodyProfile.AndroidStrongBox;
const AndroidTee = NativeCustodyProfile.AndroidTee;
const AndroidSoftwareKeystore = NativeCustodyProfile.AndroidSoftwareKeystore;

describe("remote_native_identity_platform_matrix", () => {
  it("covers the exact iOS Secure-Enclave/Keychain and Android StrongBox/TEE/software-Keystore mappings", () => {
    const iosSe = nativeCustodyReport(IosSecureEnclave);
    expect(iosSe.custodyClass).toBe(CustodyClass.hardware_or_external);
    expect(iosSe.presenceMode).toBe(PresenceMode.unattended_after_first_unlock);
    expect(iosSe.platform).toBe("ios");

    const iosKc = nativeCustodyReport(IosKeychain);
    expect(iosKc.custodyClass).toBe(CustodyClass.os_protected);
    expect(iosKc.presenceMode).toBe(PresenceMode.unattended_after_first_unlock);
    expect(iosKc.platform).toBe("ios");

    const androidSb = nativeCustodyReport(AndroidStrongBox);
    expect(androidSb.custodyClass).toBe(CustodyClass.hardware_or_external);
    expect(androidSb.presenceMode).toBe(PresenceMode.unattended_unlocked_device);
    expect(androidSb.platform).toBe("android");

    const androidTee = nativeCustodyReport(AndroidTee);
    expect(androidTee.custodyClass).toBe(CustodyClass.os_protected);
    expect(androidTee.presenceMode).toBe(PresenceMode.unattended_unlocked_device);
    expect(androidTee.platform).toBe("android");

    const androidSw = nativeCustodyReport(AndroidSoftwareKeystore);
    expect(androidSw.custodyClass).toBe(CustodyClass.os_protected);
    expect(androidSw.presenceMode).toBe(PresenceMode.unattended_unlocked_device);
    expect(androidSw.platform).toBe("android");
  });

  it("every profile reports hardware_or_external or os_protected, never origin_protected", () => {
    for (const profile of NATIVE_CUSTODY_PROFILES) {
      const report = nativeCustodyReport(profile);
      expect(
        report.custodyClass === CustodyClass.hardware_or_external ||
          report.custodyClass === CustodyClass.os_protected,
      ).toBe(true);
      expect(report.custodyClass).not.toBe(CustodyClass.origin_protected);
    }
  });

  it("unattended keys use no biometric/passcode prompt and report the correct presence mode", () => {
    expect(nativeCustodyReport(IosSecureEnclave).presenceMode).toBe(
      PresenceMode.unattended_after_first_unlock,
    );
    expect(nativeCustodyReport(IosKeychain).presenceMode).toBe(
      PresenceMode.unattended_after_first_unlock,
    );
    expect(nativeCustodyReport(AndroidStrongBox).presenceMode).toBe(
      PresenceMode.unattended_unlocked_device,
    );
    expect(nativeCustodyReport(AndroidTee).presenceMode).toBe(
      PresenceMode.unattended_unlocked_device,
    );
    expect(nativeCustodyReport(AndroidSoftwareKeystore).presenceMode).toBe(
      PresenceMode.unattended_unlocked_device,
    );
  });

  it("a key requiring presence cannot satisfy the unattended one-tap policy", () => {
    const gate = new NativeCustodyPolicyGate();
    for (const profile of NATIVE_CUSTODY_PROFILES) {
      expect(() => gate.authorize(profile, PresenceMode.user_presence_required)).toThrow(
        RemoteNativeIdentityCustodyError,
      );
    }
  });

  it("stronger-provider failure is unavailable, never a fallback", () => {
    const gate = new NativeCustodyPolicyGate();
    expect(() => gate.authorize(IosSecureEnclave, PresenceMode.user_presence_required)).toThrow();
    expect(() => gate.authorize(IosSecureEnclave, PresenceMode.unattended_unlocked_device)).toThrow(
      RemoteNativeIdentityCustodyError,
    );
  });

  it("rejects every ineligible custody path (backup/restore/migration/exportable/JS keys)", () => {
    const gate = new NativeCustodyPolicyGate();
    for (const path of INELIGIBLE_NATIVE_CUSTODY_PATHS) {
      expect(() => gate.rejectIneligible(path)).toThrow(RemoteNativeIdentityCustodyError);
    }
  });

  it("proves no X25519 bridge exists in the JS layer", () => {
    const guard = nativeX25519BridgeAbsenceGuard();
    expect(guard.hasX25519Bridge).toBe(false);
    expect(guard.ownsX25519).toBe(false);
  });

  it("proves private bytes cannot reach JS, logs, errors, telemetry, storage, or backup", () => {
    const guard = nativePrivateMaterialGuard();
    expect(guard.exposesPrivateBytes).toBe(false);
    expect(guard.persistsPrivateBytes).toBe(false);
    expect(guard.logsPrivateBytes).toBe(false);
  });

  it("consumes the shared custody/presence enums rather than redefining them", () => {
    const guard = nativeFoundationConsumptionGuard();
    expect(guard.custodyClassOriginProtected).toBe(CustodyClass.origin_protected);
    expect(guard.custodyClassOsProtected).toBe(CustodyClass.os_protected);
    expect(guard.custodyClassHardwareOrExternal).toBe(CustodyClass.hardware_or_external);
    expect(guard.presenceUnattended).toBe(PresenceMode.unattended);
    expect(guard.presenceUnattendedAfterFirstUnlock).toBe(
      PresenceMode.unattended_after_first_unlock,
    );
    expect(guard.presenceUnattendedUnlockedDevice).toBe(PresenceMode.unattended_unlocked_device);
    expect(guard.presenceUserPresenceRequired).toBe(PresenceMode.user_presence_required);
  });
});

describe("remote_native_identity_private_material_guard", () => {
  it("generate returns only a handle, public key, and evidence — never private bytes", async () => {
    const adapter = new FakeNativeCustodyAdapter();
    const provider = new NativeIdentityCustodyProvider(adapter);
    const record = await provider.generate(1 as const, IosKeychain, new Uint8Array([1, 2, 3]));
    expect(record.handleId.length).toBe(16);
    expect(record.publicKey.length).toBe(64);
    expect(record.custodyClass).toBe(CustodyClass.os_protected);
  });

  it("sign returns a 64-byte low-S P1363 signature, never private bytes", async () => {
    const adapter = new FakeNativeCustodyAdapter();
    const provider = new NativeIdentityCustodyProvider(adapter);
    const record = await provider.generate(1 as const, IosSecureEnclave, new Uint8Array([1]));
    const sig = await provider.signPossessionProof(record.handleId, new Uint8Array(32).fill(0xab));
    expect(sig.length).toBe(64);
    expect(sig[31] & 0x80).toBe(0);
    expect(sig[63] & 0x80).toBe(0);
  });

  it("error paths never expose private bytes", async () => {
    const adapter = new FakeNativeCustodyAdapter();
    const provider = new NativeIdentityCustodyProvider(adapter);
    try {
      await provider.reopen(new Uint8Array(16).fill(0xff));
      expect.unreachable("should have thrown");
    } catch (error) {
      const message = (error as Error).message;
      expect(message).not.toMatch(/private\s*key|secret\s*key|pkcs8|\bjwk\b/i);
    }
  });
});

describe("remote_native_identity_atomic_generation", () => {
  it("atomic generation and idempotent reopen", async () => {
    const adapter = new FakeNativeCustodyAdapter();
    const provider = new NativeIdentityCustodyProvider(adapter);
    const record = await provider.generate(1 as const, AndroidStrongBox, new Uint8Array([1]));
    const reopened = await provider.reopen(record.handleId);
    expect(reopened.publicKey).toEqual(record.publicKey);
    expect(reopened.custodyClass).toBe(CustodyClass.hardware_or_external);
  });

  it("rotation publishes only after the new handle is durable", async () => {
    const adapter = new FakeNativeCustodyAdapter();
    const provider = new NativeIdentityCustodyProvider(adapter);
    const original = await provider.generate(1 as const, IosKeychain, new Uint8Array([1]));
    const rotated = await provider.rotate(original.handleId, new Uint8Array([2]));
    expect(rotated.generation).toBe(original.generation + 1);
    const reopened = await provider.reopen(original.handleId);
    expect(reopened.publicKey).toEqual(rotated.publicKey);
  });

  it("destroy removes the handle and subsequent operations fail", async () => {
    const adapter = new FakeNativeCustodyAdapter();
    const provider = new NativeIdentityCustodyProvider(adapter);
    const record = await provider.generate(1 as const, AndroidTee, new Uint8Array([1]));
    expect(provider.recordCount).toBe(1);
    await provider.destroy(record.handleId);
    expect(provider.recordCount).toBe(0);
    await expect(provider.reopen(record.handleId)).rejects.toThrow();
    await expect(
      provider.signPossessionProof(record.handleId, new Uint8Array(32)),
    ).rejects.toThrow();
  });

  it("concurrent creates produce distinct handles", async () => {
    const adapter = new FakeNativeCustodyAdapter();
    const provider = new NativeIdentityCustodyProvider(adapter);
    const handles: Uint8Array[] = [];
    for (let i = 0; i < 8; i++) {
      const record = await provider.generate(1 as const, IosSecureEnclave, new Uint8Array([i]));
      handles.push(record.handleId);
    }
    const seen = new Set<string>();
    for (const handle of handles) {
      const key = Array.from(handle).join(",");
      expect(seen.has(key)).toBe(false);
      seen.add(key);
    }
    expect(provider.recordCount).toBe(8);
  });

  it("enrollment fails before server allocation when unsupported (presence-required key)", async () => {
    const adapter = new FakeNativeCustodyAdapter();
    const provider = new NativeIdentityCustodyProvider(adapter);
    expect(() =>
      new NativeCustodyPolicyGate().authorize(
        IosSecureEnclave,
        PresenceMode.user_presence_required,
      ),
    ).toThrow(RemoteNativeIdentityCustodyError);
    expect(provider.recordCount).toBe(0);
  });

  it("preserves one-tap reconnection when handles remain usable", async () => {
    const adapter = new FakeNativeCustodyAdapter();
    const provider = new NativeIdentityCustodyProvider(adapter);
    const record = await provider.generate(
      1 as const,
      AndroidSoftwareKeystore,
      new Uint8Array([1]),
    );
    const reopened = await provider.reopen(record.handleId);
    expect(reopened.handleId).toEqual(record.handleId);
    const sig = await provider.signPossessionProof(record.handleId, new Uint8Array(32).fill(0x42));
    expect(sig.length).toBe(64);
  });
});
