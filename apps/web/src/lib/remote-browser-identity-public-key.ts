/**
 * Public-key projection for browser-origin durable P-256 custody.
 *
 * The custody provider must report the durable handle's P-256 public key
 * (uncompressed affine `x`/`y`) so the enrollment/certificate flow can bind it.
 * A public key carries no secret material, so reading its bytes is safe — but
 * the custody module deliberately contains no key-export call at all (its
 * static source guard forbids one outside the non-extractable negative proof),
 * so this projection lives in its own module. Only the WebCrypto **public** key
 * is read here; the durable private key is never touched.
 */
import type { RemoteIdentityP256PublicKeyV1 } from "@flycockpit/cockpit-protocol";

/**
 * Read the uncompressed affine coordinates of a WebCrypto P-256 **public** key.
 * The input must be the public half of an ECDSA/P-256 key pair; the private
 * half is never accepted or read here.
 */
export async function extractRemoteBrowserIdentityP256PublicKey(
  publicKey: CryptoKey,
): Promise<RemoteIdentityP256PublicKeyV1> {
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
  if (raw.length !== 65 || raw[0] !== 0x04) {
    throw new Error("unexpected P-256 public key encoding");
  }
  return { x: raw.slice(1, 33), y: raw.slice(33, 65) };
}
