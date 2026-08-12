package expo.modules.remoteidentitycustody

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * RemoteIdentityCustody — Android durable P-256 custody.
 *
 * A durable handle is a non-exportable P-256 private key held in the Android
 * Keystore (StrongBox secure element when available, otherwise TEE, otherwise
 * software-backed). The `handleId` returned to JS is the key's random Keystore
 * alias. JS never receives private key bytes: the key is generated inside the
 * keystore and the app never reads its material back out.
 *
 * The alias→generation mapping (the app-layer monotonic high-water mark) is
 * persisted separately in app-private `SharedPreferences` by the app-layer
 * `NativeCustodyStore`. Diffie-Hellman key agreement is owned by the Noise
 * binding, never here — this module is P-256 signing only.
 */
class RemoteIdentityCustodyModule : Module() {
  private val keystoreProvider = "AndroidKeyStore"

  // Native platform backing (UNIMPLEMENTED — fails closed).
  //
  // TODO(native-platform): the durable native custody backing is NOT wired yet.
  // Until it is, every entry point fails closed rather than returning a
  // plausible-but-wrong result or relying on volatile state. What remains:
  //   1. a real durable store for the alias->generation high-water mark
  //      (app-private SharedPreferences), and
  //   2. recovery of a key's real profile/presence from its KeyInfo (see
  //      profileForAlias below).
  // The reference implementation of each method is retained below to document
  // the intended Android Keystore / StrongBox mechanism. This MUST be built and
  // verified on the Android CI leg — it cannot be compiled on the Linux gate box.
  // See NATIVE-PLATFORM-TODO.md.
  private fun requireNativeBackingWired() {
    throw CustodyException(
      "unimplemented on this platform: durable native custody backing is not wired — failing closed (see NATIVE-PLATFORM-TODO.md)",
    )
  }

  override fun definition() = ModuleDefinition {
    Name("RemoteIdentityCustody")

    AsyncFunction("generateP256") { handleId: ByteArray, profile: String, requireUserPresence: Boolean ->
      generate(handleId, profile, requireUserPresence)
    }

    AsyncFunction("signP256") { handleId: ByteArray, signingMessage: ByteArray ->
      sign(handleId, signingMessage)
    }

    AsyncFunction("publicKey") { handleId: ByteArray ->
      publicKeyReport(handleId)
    }

    AsyncFunction("rotateP256") { handleId: ByteArray, newHandleId: ByteArray ->
      rotate(handleId, newHandleId)
    }

    AsyncFunction("destroyGeneration") { handleId: ByteArray ->
      destroy(handleId)
    }
  }

  // MARK: - Generation

  private fun generate(handleId: ByteArray, profile: String, requireUserPresence: Boolean): Map<String, Any> {
    requireNativeBackingWired() // TODO(native-platform): fails closed until wired.
    // The caller-assigned 16-byte handle (the evidence subjectId) is the stable
    // Keystore alias source, so a durable write-ahead marker can name the key
    // before it exists.
    val alias = aliasFor(handleId)
    val useStrongBox = profile == "android-strongbox"

    val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
      .setDigests(KeyProperties.DIGEST_SHA256)
      .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))

    if (useStrongBox) {
      // Request hardware secure-element residency. If StrongBox is unavailable
      // the generator throws and no weaker key is silently substituted.
      builder.setIsStrongBoxBacked(true)
    }
    if (requireUserPresence) {
      // Presence-gated key: a signature requires a fresh user authentication.
      builder.setUserAuthenticationRequired(true)
    }

    val generator = KeyPairGenerator.getInstance(
      KeyProperties.KEY_ALGORITHM_EC,
      keystoreProvider,
    )
    generator.initialize(builder.build())
    val keyPair = generator.generateKeyPair()

    val (x, y) = publicCoordinates(keyPair.public as ECPublicKey)
    val attestation = attest(alias, profile, requireUserPresence)
    val evidence = providerEvidence(alias, attestation)

    return mapOf(
      "handleId" to handleId,
      "publicKey" to mapOf("x" to x, "y" to y),
      "attestation" to attestation,
      "providerEvidence" to evidence,
    )
  }

  // MARK: - Rotation

  private fun rotate(handleId: ByteArray, newHandleId: ByteArray): Map<String, Any> {
    requireNativeBackingWired() // TODO(native-platform): fails closed until wired.
    val alias = aliasFor(handleId)
    val store = KeyStore.getInstance(keystoreProvider).apply { load(null) }
    if (!store.containsAlias(alias)) {
      throw CustodyException("handle not found")
    }
    // Create a fresh key under the caller-assigned new alias; the old key is
    // retained until the app layer destroys it after publish.
    val existing = attest(alias, profileForAlias(alias), false)
    return generate(newHandleId, existing["profile"] as String, false)
  }

  // MARK: - Signing

  private fun sign(handleId: ByteArray, signingMessage: ByteArray): ByteArray {
    requireNativeBackingWired() // TODO(native-platform): fails closed until wired.
    val alias = aliasFor(handleId)
    val store = KeyStore.getInstance(keystoreProvider).apply { load(null) }
    val entry = store.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
      ?: throw CustodyException("handle not found")

    // Message-based signing: the platform hashes with SHA-256 internally. The
    // private key is a keystore reference; its bytes never enter the process.
    val signer = Signature.getInstance("SHA256withECDSA")
    signer.initSign(entry.privateKey)
    signer.update(signingMessage)
    val der = signer.sign()

    // Convert DER (SEQUENCE { INTEGER r, INTEGER s }) to fixed 64-byte P1363 and
    // normalize to low-S. Zero / out-of-range components are corruption.
    return P256Scalar.derToLowSP1363(der)
  }

  // MARK: - Public key

  private fun publicKeyReport(handleId: ByteArray): Map<String, Any> {
    requireNativeBackingWired() // TODO(native-platform): fails closed until wired.
    val alias = aliasFor(handleId)
    val store = KeyStore.getInstance(keystoreProvider).apply { load(null) }
    val cert = store.getCertificate(alias) ?: throw CustodyException("handle not found")
    val (x, y) = publicCoordinates(cert.publicKey as ECPublicKey)
    val attestation = attest(alias, profileForAlias(alias), false)
    return mapOf("x" to x, "y" to y, "attestation" to attestation)
  }

  // MARK: - Destroy

  private fun destroy(handleId: ByteArray) {
    requireNativeBackingWired() // TODO(native-platform): fails closed until wired.
    val alias = aliasFor(handleId)
    val store = KeyStore.getInstance(keystoreProvider).apply { load(null) }
    if (!store.containsAlias(alias)) {
      throw CustodyException("handle not found")
    }
    store.deleteEntry(alias)
  }

  // MARK: - Attestation & evidence

  private fun attest(alias: String, profile: String, requireUserPresence: Boolean): Map<String, Any> {
    val store = KeyStore.getInstance(keystoreProvider).apply { load(null) }
    val securityLevel: String
    val custodyClass: Int

    val entry = store.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
    if (entry != null) {
      val factory = KeyFactory.getInstance(entry.privateKey.algorithm, keystoreProvider)
      val info = factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
      // Derive the real security level from KeyInfo, never from caller input.
      securityLevel = when {
        !info.isInsideSecureHardware -> "software"
        isStrongBox(info) -> "strongbox"
        else -> "tee"
      }
      // StrongBox is hardware_or_external(3); TEE and software are os_protected(2).
      custodyClass = if (securityLevel == "strongbox") 3 else 2
    } else {
      securityLevel = if (profile == "android-strongbox") "strongbox" else "tee"
      custodyClass = if (securityLevel == "strongbox") 3 else 2
    }

    // presence: user_presence_required(4) when auth-gated, else
    // unattended_unlocked_device(3) on Android.
    val presenceMode = if (requireUserPresence) 4 else 3

    return mapOf(
      "custodyClass" to custodyClass,
      "presenceMode" to presenceMode,
      "securityLevel" to securityLevel,
      "profile" to profile,
    )
  }

  private fun isStrongBox(info: KeyInfo): Boolean {
    return try {
      // API 31+: securityLevel == SECURITY_LEVEL_STRONGBOX.
      val method = KeyInfo::class.java.getMethod("getSecurityLevel")
      (method.invoke(info) as Int) == 2 // KeyProperties.SECURITY_LEVEL_STRONGBOX
    } catch (_: Throwable) {
      false
    }
  }

  private fun providerEvidence(alias: String, attestation: Map<String, Any>): ByteArray {
    val header = "flycockpit.android-custody.v1".toByteArray(Charsets.UTF_8)
    val level = (attestation["securityLevel"] as String).toByteArray(Charsets.UTF_8)
    val aliasBytes = alias.toByteArray(Charsets.UTF_8)
    return header + byteArrayOf(0) + level + byteArrayOf(0) + aliasBytes
  }

  private fun publicCoordinates(publicKey: ECPublicKey): Pair<ByteArray, ByteArray> {
    // Affine coordinates read directly from the public key — the private key is
    // never serialized or exported. Each coordinate is 32 bytes.
    val x = toFixed32(publicKey.w.affineX)
    val y = toFixed32(publicKey.w.affineY)
    return Pair(x, y)
  }

  private fun toFixed32(value: BigInteger): ByteArray {
    var bytes = value.toByteArray()
    if (bytes.size > 32) {
      bytes = bytes.copyOfRange(bytes.size - 32, bytes.size)
    }
    val out = ByteArray(32)
    System.arraycopy(bytes, 0, out, 32 - bytes.size, bytes.size)
    return out
  }

  private fun profileForAlias(alias: String): String {
    // TODO(native-platform): recover the key's REAL profile from its KeyInfo /
    // the durable alias->profile mapping. Defaulting to the strongest profile
    // here would MISREPORT a software/TEE key as StrongBox, so we fail closed
    // instead of guessing.
    throw CustodyException(
      "unimplemented on this platform: native profile/presence recovery is not wired — failing closed",
    )
  }

  private fun aliasFor(handleId: ByteArray): String {
    return "flycockpit-remote-identity-" + handleId.joinToString("") { "%02x".format(it) }
  }
}

private class CustodyException(message: String) :
  CodedException("ERR_REMOTE_IDENTITY_CUSTODY", message, null)

/** P-256 scalar helpers: DER→P1363 and low-S normalization. */
private object P256Scalar {
  // n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
  private val order = BigInteger(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    16,
  )
  private val halfOrder = order.shiftRight(1)

  fun derToLowSP1363(der: ByteArray): ByteArray {
    var i = 0
    fun read(): Int {
      if (i >= der.size) throw CustodyException("corrupted signature")
      return der[i++].toInt() and 0xff
    }
    if (read() != 0x30) throw CustodyException("corrupted signature")
    read() // total length
    fun readInt(): BigInteger {
      if (read() != 0x02) throw CustodyException("corrupted signature")
      val len = read()
      if (len <= 0 || i + len > der.size) throw CustodyException("corrupted signature")
      val v = der.copyOfRange(i, i + len)
      i += len
      return BigInteger(1, v)
    }
    val r = readInt()
    var s = readInt()

    if (r.signum() == 0 || s.signum() == 0 || r >= order || s >= order) {
      throw CustodyException("corrupted signature")
    }
    if (s > halfOrder) {
      s = order.subtract(s) // s := n - s
    }
    return toFixed32(r) + toFixed32(s)
  }

  private fun toFixed32(value: BigInteger): ByteArray {
    var bytes = value.toByteArray()
    if (bytes.size > 32) {
      bytes = bytes.copyOfRange(bytes.size - 32, bytes.size)
    }
    val out = ByteArray(32)
    System.arraycopy(bytes, 0, out, 32 - bytes.size, bytes.size)
    return out
  }
}
