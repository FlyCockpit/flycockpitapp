# Native platform TODO — remote identity custody

The TypeScript layer of this module (provider contract, atomic generation
reservation, fail-closed reopen, presence preservation, low-S normalization, and
the WebCrypto conformance fake) is implemented and covered by vitest. The
platform-native bodies below are **deliberately unimplemented and fail closed** —
they throw an explicit "unimplemented on this platform" error rather than return
a plausible-but-wrong result or rely on volatile state. They can only be built
and verified on their respective CI legs, never on the Linux gate box.

Nothing here "pretends to work": a real app calling any native entry point today
gets a typed error, not a silent wrong answer.

## iOS — `ios/RemoteIdentityCustodyModule.swift`

- `generateP256`, `signP256`, `publicKey`, `rotateP256`, `destroyGeneration`:
  each calls `requireNativeBackingWired()` first, which **throws**. The reference
  Keychain / Secure Enclave implementation is retained below the guard to
  document the intended mechanism (and to satisfy the source-scan for the
  required API tokens), but is unreachable at runtime until the backing lands.
- `profileForTag`: **throws** instead of returning the old hardcoded
  `("ios-secure-enclave", false)`. TODO: recover the key's real profile/presence
  from its `SecAccessControl` / accessibility attributes.
- Durable store: TODO wire a real high-water + tag→generation store in a
  non-synchronizable, `ThisDeviceOnly` Keychain generic-password item.
- **Build/verify on:** the iOS CI leg (EAS / Xcode). Never on Linux.

## Android — `android/.../RemoteIdentityCustodyModule.kt`

- Same five methods gated by `requireNativeBackingWired()` (throws); reference
  Android Keystore / StrongBox implementation retained below the guard.
- `profileForAlias`: **throws** instead of returning the old hardcoded
  `"android-strongbox"`. TODO: recover the real profile from `KeyInfo` /
  the durable alias→profile mapping.
- Durable store: TODO wire a real high-water + alias→generation store in
  app-private `SharedPreferences`.
- **Build/verify on:** the Android CI leg (EAS / Gradle). Never on Linux.

## TypeScript store

- `NativeCustodyStore` (the interface) and `InMemoryNativeCustodyStore` (a
  **test-only** in-memory implementation) exist and are exercised by vitest.
  **There is no production, platform-backed `NativeCustodyStore` yet** — the
  production store must be backed by the module-owned native durable storage
  above (iOS Keychain metadata item / Android SharedPreferences).

## Rust daemon adapters (same "unverifiable on Linux" boundary)

- `crates/cockpit-core/src/remote_daemon_identity_custody/macos.rs`:
  reopen-across-restart (`SecItemCopyMatching`) and durable delete
  (`SecItemDelete`) are TODO. The in-memory map is a process-lifetime cache;
  after a restart `reopen` returns `NotFound` (fails closed). Builds only on the
  macOS CI matrix leg.
- `windows.rs`: real NCrypt persisted keys, but compiled/run only on the Windows
  CI matrix leg — never executed on Linux.
- `pkcs11.rs`: real `cryptoki`, but compiled/run only by the SoftHSM CI job
  (feature `daemon-custody-pkcs11`, `#[ignore]`d tests) — never on the default
  Linux gate.
