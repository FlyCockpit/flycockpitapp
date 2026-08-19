#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the independent structural verifier in isolation over arbitrary bytes.
// It is the last, sanitizer-independent line of defense, so it must be robust
// to inputs that never came from the canonicalizer. The property under test is
// total safety: no input may panic, abort, hang, or exhaust memory.
//
// Hard caps are supplied at run time by libFuzzer flags (see ../README.md):
//   -max_len=1048576  -rss_limit_mb=2048  -timeout=10
fuzz_target!(|data: &[u8]| {
    cockpit_core::generated_svg::fuzz_verify_canonical_svg(data);
});
