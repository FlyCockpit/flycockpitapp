# Remote Transport Fixtures

Byte-exact cross-language vectors for the logical lane substrate
(`remote-transport-logical-lanes`).

Rust is the source of truth. Every file here is produced by the real codecs in
`crates/cockpit-proto/src/remote_transport/` and written by
`crates/cockpit-proto/tests/remote_transport_fixtures.rs`. The TypeScript mirror
`packages/cockpit-protocol/src/remote-transport-lanes.test.ts` consumes the same
files, so no byte literal is duplicated between the two languages and neither
side can drift without both suites failing.

Do not hand edit these files.

Regenerate from the repository root with:

```sh
COCKPIT_UPDATE_GOLDEN=1 cargo test -p cockpit-proto --test remote_transport_fixtures
```

| File | Contents |
| --- | --- |
| `constants.json` | Frame/fragment/bulk/queue constants, the Noise derivation chain, and the lane schedule |
| `channels.json` | The fixed three-channel contract (ids 0/2/4, labels, settings) |
| `classification.json` | Every request/response/event variant's lane, class, and inline-payload disposition, plus the >512 KiB inventory |
| `frames.json` | `RemoteTransportFrameV1` vectors (72-byte header, network byte order) |
| `fragments.json` | `RemoteCarrierFragmentV1` vectors, including the maximal nine-fragment split |
| `bulk.json` | `begin`/`chunk`/`complete`/`abort` bulk payload vectors |

Large vectors record their header, digest, and length rather than a full
`encodedHex` body, and describe their payload generatively (`{fill, length}`) so
both languages rebuild the identical bytes without a megabyte of hex in the
file.
