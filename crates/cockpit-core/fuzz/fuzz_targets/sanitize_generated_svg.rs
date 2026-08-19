#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the full closed-policy sanitizer pipeline (accept -> canonicalize ->
// svg-hush -> independent verifier) over arbitrary bytes. The property under
// test is total safety: no input may panic, abort, hang, or exhaust memory.
//
// Hard caps are supplied at run time by libFuzzer flags (see ../README.md):
//   -max_len=1048576   bounds the input size handed to the target
//   -rss_limit_mb=2048  aborts if resident memory exceeds the cap
//   -timeout=10         aborts any single input that runs longer than 10s
// The sanitizer additionally enforces its own internal raw-byte, depth,
// element, attribute, path and text ceilings; fuzzing must never disable them,
// so this harness calls the ordinary production entry point unchanged.
fuzz_target!(|data: &[u8]| {
    let _ = cockpit_core::generated_svg::sanitize_generated_svg(data);
});
