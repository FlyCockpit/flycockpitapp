# `@flycockpit/cockpit-noise-native`

React Native New-Architecture specification for the opaque `cockpit-noise`
UniFFI libraries. Swift/Kotlin adapters may marshal handles and byte buffers
only. Authorization is completed through the generated
`BindingAuthorizationGate` callback; adapters must never accept a boolean
authorization shortcut or implement cryptography.

CI builds `crates/cockpit-noise` with `native-bindings` using UniFFI 0.29.4.
Generated Swift/Kotlin sources and platform libraries are release artifacts
whose hashes are recorded alongside the release; they are never hand-edited.
