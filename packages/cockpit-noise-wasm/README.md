# `@flycockpit/cockpit-noise-wasm`

Browser binding output for the Rust-owned `cockpit-noise` state machine. CI
generates this package with pinned `wasm-pack`/`wasm-bindgen` versions and
compares two clean builds byte-for-byte. Consumers must treat handles and byte
arrays as opaque and must not add a TypeScript cryptographic implementation.

Generated release files are attached from the verified build; they are not
hand-edited or accepted when the reproducibility comparison differs.
