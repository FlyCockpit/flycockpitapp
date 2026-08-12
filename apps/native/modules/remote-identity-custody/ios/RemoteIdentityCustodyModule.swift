import ExpoModulesCore
import Foundation
import Security

// RemoteIdentityCustody — iOS durable P-256 custody.
//
// A durable handle is a non-exportable P-256 private key held in the Secure
// Enclave (enclave profile) or as a Keychain SecKey (software-backed profile).
// The `handleId` returned to JS is the key's random application tag
// (`kSecAttrApplicationTag`). JS never receives private key bytes.
//
// Generation metadata (the app-layer monotonic high-water mark that maps a tag
// to its generation) is persisted separately as a non-synchronizable,
// `ThisDeviceOnly` Keychain generic-password item — see the app-layer
// `NativeCustodyStore`. The private key itself is created with
// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and is never marked
// synchronizable, so it can neither leave the device nor sync to iCloud.
//
// Diffie-Hellman key agreement lives entirely outside this module (the Noise
// binding owns it); this module is P-256 signing only.
public class RemoteIdentityCustodyModule: Module {
  private let keyType = kSecAttrKeyTypeECSECPrimeRandom
  private let p256Order = P256Scalar.order
  private let p256HalfOrder = P256Scalar.halfOrder

  // MARK: - Native platform backing (UNIMPLEMENTED — fails closed)

  // TODO(native-platform): the durable native custody backing is NOT wired yet.
  // Until it is, every entry point fails closed rather than returning a
  // plausible-but-wrong result or relying on volatile state. What remains:
  //   1. a real durable store for the tag->generation high-water mark
  //      (non-synchronizable ThisDeviceOnly Keychain generic-password item), and
  //   2. recovery of a key's real profile/presence from its SecAccessControl /
  //      accessibility attributes (see profileForTag below).
  // The reference implementation of each method is retained below to document
  // the intended Keychain / Secure Enclave mechanism. This MUST be built and
  // verified on the iOS CI leg — it cannot be compiled on the Linux gate box.
  // See NATIVE-PLATFORM-TODO.md.
  private func requireNativeBackingWired() throws {
    throw CustodyException(
      "unimplemented on this platform: durable native custody backing is not wired — failing closed (see NATIVE-PLATFORM-TODO.md)"
    )
  }

  public func definition() -> ModuleDefinition {
    Name("RemoteIdentityCustody")

    AsyncFunction("generateP256") { (handleId: Data, profile: String, requireUserPresence: Bool) -> [String: Any] in
      try self.generate(handleId: handleId, profile: profile, requireUserPresence: requireUserPresence)
    }

    AsyncFunction("signP256") { (handleId: Data, signingMessage: Data) -> Data in
      try self.sign(handleId: handleId, message: signingMessage)
    }

    AsyncFunction("publicKey") { (handleId: Data) -> [String: Any] in
      try self.publicKeyReport(handleId: handleId)
    }

    AsyncFunction("rotateP256") { (handleId: Data, newHandleId: Data) -> [String: Any] in
      try self.rotate(handleId: handleId, newHandleId: newHandleId)
    }

    AsyncFunction("destroyGeneration") { (handleId: Data) -> Void in
      try self.destroy(handleId: handleId)
    }
  }

  // MARK: - Generation

  private func generate(handleId: Data, profile: String, requireUserPresence: Bool) throws -> [String: Any] {
    try requireNativeBackingWired() // TODO(native-platform): fails closed until wired.
    // The caller-assigned handle IS the keystore application tag, so a durable
    // write-ahead marker can name the key before it exists.
    let tag = handleId
    let inEnclave = profile == "ios-secure-enclave"

    var keyAttributes: [String: Any] = [
      kSecAttrKeyType as String: keyType,
      kSecAttrKeySizeInBits as String: 256,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag,
      ],
    ]

    // The durable key is device-bound and non-exportable: ThisDeviceOnly
    // accessibility, never synchronizable. Presence profiles additionally
    // require a live user via `.userPresence`.
    let flags: SecAccessControlCreateFlags =
      requireUserPresence ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
    guard
      let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        nil
      )
    else {
      throw CustodyException("failed to create access control")
    }
    var privateAttrs = keyAttributes[kSecPrivateKeyAttrs as String] as! [String: Any]
    privateAttrs[kSecAttrAccessControl as String] = access
    keyAttributes[kSecPrivateKeyAttrs as String] = privateAttrs

    if inEnclave {
      // Secure Enclave residency: keys are generated inside the SEP and cannot
      // be extracted. `kSecAttrTokenIDSecureEnclave` pins residency.
      keyAttributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
    }

    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(keyAttributes as CFDictionary, &error) else {
      throw CustodyException("SecKeyCreateRandomKey failed: \(Self.describe(error))")
    }

    let (x, y) = try Self.publicCoordinates(of: privateKey)
    let attestation = try Self.attest(privateKey: privateKey, profile: profile, requireUserPresence: requireUserPresence)
    let evidence = Self.providerEvidence(tag: tag, attestation: attestation)

    return [
      "handleId": tag,
      "publicKey": ["x": x, "y": y],
      "attestation": attestation,
      "providerEvidence": evidence,
    ]
  }

  // MARK: - Rotation

  private func rotate(handleId: Data, newHandleId: Data) throws -> [String: Any] {
    try requireNativeBackingWired() // TODO(native-platform): fails closed until wired.
    // The old key must exist; the new key is created under the caller-assigned
    // `newHandleId` tag and the old key is retained until destroyed after publish.
    _ = try loadPrivateKey(tag: handleId)
    let existing = try Self.profileForTag(handleId)
    return try generate(
      handleId: newHandleId,
      profile: existing.profile,
      requireUserPresence: existing.requireUserPresence
    )
  }

  // MARK: - Signing

  private func sign(handleId: Data, message: Data) throws -> Data {
    try requireNativeBackingWired() // TODO(native-platform): fails closed until wired.
    let privateKey = try loadPrivateKey(tag: handleId)
    var error: Unmanaged<CFError>?
    // Message-based signing: the platform hashes with SHA-256 internally.
    guard
      let derSignature = SecKeyCreateSignature(
        privateKey,
        .ecdsaSignatureMessageX962SHA256,
        message as CFData,
        &error
      ) as Data?
    else {
      throw CustodyException("SecKeyCreateSignature failed: \(Self.describe(error))")
    }
    // Convert DER (SEQUENCE { INTEGER r, INTEGER s }) to fixed 64-byte P1363 and
    // normalize to low-S. Zero / out-of-range components are corruption, not
    // normalized away.
    return try P256Scalar.derToLowSP1363(derSignature)
  }

  // MARK: - Public key

  private func publicKeyReport(handleId: Data) throws -> [String: Any] {
    try requireNativeBackingWired() // TODO(native-platform): fails closed until wired.
    let privateKey = try loadPrivateKey(tag: handleId)
    let (x, y) = try Self.publicCoordinates(of: privateKey)
    let existing = try Self.profileForTag(handleId)
    let attestation = try Self.attest(
      privateKey: privateKey,
      profile: existing.profile,
      requireUserPresence: existing.requireUserPresence
    )
    return ["x": x, "y": y, "attestation": attestation]
  }

  // MARK: - Destroy

  private func destroy(handleId: Data) throws {
    try requireNativeBackingWired() // TODO(native-platform): fails closed until wired.
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: handleId,
      kSecAttrKeyType as String: keyType,
    ]
    let status = SecItemDelete(query as CFDictionary)
    if status != errSecSuccess && status != errSecItemNotFound {
      throw CustodyException("SecItemDelete failed: \(status)")
    }
    if status == errSecItemNotFound {
      throw CustodyException("handle not found")
    }
  }

  // MARK: - Keychain lookup

  private func loadPrivateKey(tag: Data) throws -> SecKey {
    // Returns a REFERENCE to the key (kSecReturnRef), never its raw bytes. A
    // data-returning keychain query is never issued, so private key material
    // cannot leave the keystore.
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
      kSecAttrKeyType as String: keyType,
      kSecReturnRef as String: true,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let key = item else {
      throw CustodyException("handle not found")
    }
    // swiftlint:disable:next force_cast
    return (key as! SecKey)
  }

  // MARK: - Attestation & evidence

  private static func attest(
    privateKey: SecKey,
    profile: String,
    requireUserPresence: Bool
  ) throws -> [String: Any] {
    let attrs = SecKeyCopyAttributes(privateKey) as? [String: Any] ?? [:]
    let tokenId = attrs[kSecAttrTokenID as String] as? String
    let inEnclave = tokenId == (kSecAttrTokenIDSecureEnclave as String)

    let securityLevel: String
    let custodyClass: Int
    switch profile {
    case "ios-secure-enclave":
      securityLevel = "secure_enclave"
      // hardware_or_external only when residency is actually the enclave.
      custodyClass = inEnclave ? 3 : 2
    default:
      securityLevel = "keychain"
      custodyClass = 2 // os_protected
    }

    // presence: user_presence_required(4) when gated, else
    // unattended_after_first_unlock(2) for ThisDeviceOnly WhenUnlocked keys.
    let presenceMode = requireUserPresence ? 4 : 2

    return [
      "custodyClass": custodyClass,
      "presenceMode": presenceMode,
      "securityLevel": securityLevel,
      "profile": profile,
    ]
  }

  private static func providerEvidence(tag: Data, attestation: [String: Any]) -> Data {
    var evidence = Data()
    evidence.append(contentsOf: "flycockpit.ios-custody.v1".utf8)
    evidence.append(0)
    evidence.append(contentsOf: (attestation["securityLevel"] as? String ?? "").utf8)
    evidence.append(0)
    evidence.append(tag)
    return evidence
  }

  private static func publicCoordinates(of privateKey: SecKey) throws -> (Data, Data) {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw CustodyException("failed to derive public key")
    }
    var error: Unmanaged<CFError>?
    // External representation of the PUBLIC key only: 0x04 || X(32) || Y(32).
    // The private key is Secure-Enclave / non-exportable; the OS refuses to
    // externalize it.
    guard let rep = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      throw CustodyException("failed to export public key: \(describe(error))")
    }
    guard rep.count == 65, rep.first == 0x04 else {
      throw CustodyException("unexpected public key encoding")
    }
    return (rep.subdata(in: 1..<33), rep.subdata(in: 33..<65))
  }

  private static func profileForTag(_ tag: Data) throws -> (profile: String, requireUserPresence: Bool) {
    // TODO(native-platform): recover the key's REAL profile/presence from its
    // SecAccessControl / accessibility attributes (and the tag->profile mapping
    // in the durable store). Returning a hardcoded value here would silently
    // downgrade a user-presence-gated key to unattended, so we fail closed
    // instead of guessing.
    throw CustodyException(
      "unimplemented on this platform: native profile/presence recovery is not wired — failing closed"
    )
  }

  private static func describe(_ error: Unmanaged<CFError>?) -> String {
    guard let error = error?.takeRetainedValue() else { return "unknown error" }
    return CFErrorCopyDescription(error) as String? ?? "unknown error"
  }
}

private struct CustodyException: Error {
  let message: String
  init(_ message: String) { self.message = message }
}

// P-256 scalar helpers: DER→P1363 and low-S normalization.
private enum P256Scalar {
  // n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
  static let order: [UInt8] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
  ]
  // floor(n / 2)
  static let halfOrder: [UInt8] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
  ]

  static func derToLowSP1363(_ der: Data) throws -> Data {
    let bytes = [UInt8](der)
    var i = 0
    func read() throws -> UInt8 {
      guard i < bytes.count else { throw CustodyException("corrupted signature") }
      defer { i += 1 }
      return bytes[i]
    }
    guard try read() == 0x30 else { throw CustodyException("corrupted signature") }
    _ = try read() // total length
    func readInt() throws -> [UInt8] {
      guard try read() == 0x02 else { throw CustodyException("corrupted signature") }
      let len = Int(try read())
      guard len > 0, i + len <= bytes.count else { throw CustodyException("corrupted signature") }
      var v = Array(bytes[i..<(i + len)])
      i += len
      while v.count > 1 && v.first == 0x00 { v.removeFirst() }
      while v.count < 32 { v.insert(0x00, at: 0) }
      guard v.count == 32 else { throw CustodyException("corrupted signature") }
      return v
    }
    let r = try readInt()
    var s = try readInt()

    if isZero(r) || isZero(s) || compare(r, order) >= 0 || compare(s, order) >= 0 {
      throw CustodyException("corrupted signature")
    }
    if compare(s, halfOrder) > 0 {
      s = subtract(order, s) // s := n - s
    }
    return Data(r + s)
  }

  private static func isZero(_ v: [UInt8]) -> Bool { v.allSatisfy { $0 == 0 } }

  private static func compare(_ a: [UInt8], _ b: [UInt8]) -> Int {
    for idx in 0..<32 {
      if a[idx] != b[idx] { return a[idx] < b[idx] ? -1 : 1 }
    }
    return 0
  }

  private static func subtract(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
    var out = [UInt8](repeating: 0, count: 32)
    var borrow = 0
    for idx in stride(from: 31, through: 0, by: -1) {
      let diff = Int(a[idx]) - Int(b[idx]) - borrow
      if diff < 0 {
        out[idx] = UInt8(diff + 256)
        borrow = 1
      } else {
        out[idx] = UInt8(diff)
        borrow = 0
      }
    }
    return out
  }
}
