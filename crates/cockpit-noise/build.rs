fn main() {
    #[cfg(feature = "native-bindings")]
    uniffi_build::generate_scaffolding("src/cockpit_noise.udl")
        .expect("generate cockpit-noise UniFFI scaffolding");
}
