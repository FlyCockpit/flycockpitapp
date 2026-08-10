export function decodeRemoteAdminBase64Url(value: string) {
  const padded = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

export function remoteAdminRegistrationOptions(input: {
  challenge: string;
  rpId: string;
  userId: Uint8Array;
}): PublicKeyCredentialCreationOptions {
  const userId = new Uint8Array(input.userId.length);
  userId.set(input.userId);
  return {
    challenge: decodeRemoteAdminBase64Url(input.challenge),
    rp: { id: input.rpId, name: "FlyCockpit" },
    user: {
      id: userId,
      name: "remote-security-admin",
      displayName: "Remote security administrator",
    },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    timeout: 300_000,
    authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
    attestation: "none",
  };
}

export function remoteAdminAssertionOptions(input: {
  challenge: string;
  rpId: string;
  credentialId?: ArrayBuffer;
}): PublicKeyCredentialRequestOptions {
  return {
    challenge: decodeRemoteAdminBase64Url(input.challenge),
    rpId: input.rpId,
    allowCredentials: input.credentialId
      ? [{ type: "public-key", id: input.credentialId }]
      : undefined,
    timeout: 300_000,
    userVerification: "required",
  };
}
