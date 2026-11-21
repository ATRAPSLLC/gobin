//! Arbitrary bytes through detection, parsing and every accessor.
//!
//! Random bytes rarely get past the container headers, so this target mostly
//! covers the ELF, Mach-O, PE and wasm front ends (goblin included) and the
//! fallback scans. `mutate` reaches the Go structures behind them.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| gobin_fuzz::parse_and_exercise(data));
