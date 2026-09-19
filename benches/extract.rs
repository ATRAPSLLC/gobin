//! Extraction benchmarks across the fixture corpus.
//!
//! Two axes matter for gobin's callers, and `divan`'s allocation profiler
//! reports both in one table:
//!
//! - **Wall time** per extraction surface, which is what a triage pipeline
//!   pays per sample.
//! - **Allocations and bytes**, which is what a pipeline running thousands of
//!   samples in parallel actually feels.
//!
//! Fixtures are chosen to span the layouts that cost differently rather than
//! to cover every version: an ELF with named sections (the cheap path), a PE
//! with none (which forces the moduledata scan), a stripped Mach-O, and a wasm
//! module (whose address space is a reconstructed linear-memory image).
//!
//! Run with `cargo bench`, or a subset with
//! `cargo bench -- types` / `cargo bench -- parse`.

// Workspace-level `[lints.clippy]` applies to benchmark binaries too, but a
// benchmark harness legitimately panics on a missing fixture (there is nothing
// to measure) and has no rustdoc surface.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::type_complexity,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use std::sync::OnceLock;

use divan::{AllocProfiler, Bencher, black_box};
use gobin::{
    GoBinary,
    formats::BinaryContext,
    structures::{buildinfo, pclntab},
};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

fn main() {
    divan::main();
}

/// Short names the benches sweep. Kept short so divan's table stays readable;
/// [`path_of`] maps each to its fixture.
const FIXTURES: &[&str] = &[
    "elf126",
    "elf127",
    "pe127",
    "macho127s",
    "wasm127",
    "types127",
];

/// Fixture path for a short name.
fn path_of(name: &str) -> &'static str {
    match name {
        "elf126" => "tests/samples/basic_go126_linux_amd64",
        "elf127" => "tests/samples/basic_go127_linux_amd64",
        "pe127" => "tests/samples/basic_go127_windows_amd64.exe",
        "macho127s" => "tests/samples/basic_go127_darwin_arm64_stripped",
        "wasm127" => "tests/samples/basic_go127_wasip1_wasm",
        "types127" => "tests/samples/types_go127_linux_amd64",
        other => panic!("unknown fixture {other}"),
    }
}

/// Read a fixture once per process and hand out a shared borrow.
///
/// Benchmarks measure gobin, not the filesystem, so the read must not land
/// inside the timed region - and it must not be re-counted by the allocation
/// profiler on every iteration either.
fn fixture(path: &str) -> &'static [u8] {
    static CACHE: OnceLock<std::sync::Mutex<Vec<(String, &'static [u8])>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    let mut guard = cache.lock().expect("fixture cache poisoned");
    if let Some((_, data)) = guard.iter().find(|(p, _)| p == path) {
        return data;
    }
    let data: &'static [u8] = Box::leak(
        std::fs::read(path)
            .unwrap_or_else(|e| panic!("read {path}: {e}"))
            .into_boxed_slice(),
    );
    guard.push((path.to_string(), data));
    data
}

/// Detection + format parse + pclntab + buildinfo + moduledata: what every
/// caller pays before asking for anything.
#[divan::bench(args = FIXTURES)]
fn parse(bencher: Bencher, name: &str) {
    let data = fixture(path_of(name));
    bencher.bench(|| black_box(GoBinary::parse(black_box(data))).is_some());
}

/// Function enumeration with names and source files resolved - the most
/// commonly consumed surface.
#[divan::bench(args = FIXTURES)]
fn functions(bencher: Bencher, name: &str) {
    let data = fixture(path_of(name));
    let bin = GoBinary::parse(data).expect("fixture parses");
    bencher.bench(|| black_box(bin.functions().count()));
}

/// Reflection-visible type descriptors.
#[divan::bench(args = FIXTURES)]
fn types(bencher: Bencher, name: &str) {
    let data = fixture(path_of(name));
    let bin = GoBinary::parse(data).expect("fixture parses");
    bencher.bench(|| black_box(bin.types().count()));
}

/// Transitive closure over every reachable descriptor.
#[divan::bench(args = FIXTURES)]
fn all_types(bencher: Bencher, name: &str) {
    let data = fixture(path_of(name));
    let bin = GoBinary::parse(data).expect("fixture parses");
    bencher.bench(|| black_box(bin.all_types().len()));
}

/// Go string-literal recovery - a full pointer-aligned sweep of the image.
#[divan::bench(args = FIXTURES)]
fn strings(bencher: Bencher, name: &str) {
    let data = fixture(path_of(name));
    let bin = GoBinary::parse(data).expect("fixture parses");
    bencher.bench(|| black_box(bin.strings().count()));
}

/// Interface/concrete-type pairs.
#[divan::bench(args = FIXTURES)]
fn itabs(bencher: Bencher, name: &str) {
    let data = fixture(path_of(name));
    let bin = GoBinary::parse(data).expect("fixture parses");
    bencher.bench(|| black_box(bin.itab_pairs().count()));
}

/// Inline-tree decoding over every function - the heaviest pclntab surface.
#[divan::bench(args = FIXTURES)]
fn inline_trees(bencher: Bencher, name: &str) {
    let data = fixture(path_of(name));
    let bin = GoBinary::parse(data).expect("fixture parses");
    bencher.bench(|| {
        let Some(pcl) = bin.pclntab() else { return 0 };
        let mut n = 0usize;
        for (_, off) in pcl.func_entries() {
            if let Some(fd) = pcl.parse_func(off) {
                n += bin.inline_tree(&fd).count();
            }
        }
        black_box(n)
    });
}

/// Format parse: goblin plus, for wasm, the linear-memory reconstruction.
/// Everything else is measured on top of this.
#[divan::bench(args = FIXTURES)]
fn stage_context(bencher: Bencher, name: &str) {
    let data = fixture(path_of(name));
    bencher.bench(|| {
        black_box(BinaryContext::new(black_box(data)))
            .sections()
            .has_gopclntab
    });
}

/// Build-info blob location and decode. PE and wasm have no `.go.buildinfo`
/// section, so this is the stage that has to search for its own input.
#[divan::bench(args = FIXTURES)]
fn stage_buildinfo(bencher: Bencher, name: &str) {
    let data = fixture(path_of(name));
    let ctx = BinaryContext::new(data);
    bencher.bench(|| black_box(buildinfo::extract(black_box(&ctx))).is_some());
}

/// pclntab location and header parse. PE has no `.gopclntab` section and falls
/// back to a magic scan.
#[divan::bench(args = FIXTURES)]
fn stage_pclntab(bencher: Bencher, name: &str) {
    let data = fixture(path_of(name));
    let ctx = BinaryContext::new(data);
    bencher.bench(|| black_box(pclntab::parse(black_box(&ctx))).is_some());
}

/// Package initialization order, decoded from `moduledata.inittasks`.
#[divan::bench(args = FIXTURES)]
fn init_order(bencher: Bencher, name: &str) {
    let data = fixture(path_of(name));
    let bin = GoBinary::parse(data).expect("fixture parses");
    bencher.bench(|| black_box(bin.init_order().len()));
}

/// `//go:embed` payload recovery - a symbol-independent structural search.
#[divan::bench(args = FIXTURES)]
fn embeds(bencher: Bencher, name: &str) {
    let data = fixture(path_of(name));
    let bin = GoBinary::parse(data).expect("fixture parses");
    bencher.bench(|| black_box(bin.embedded_assets().len()));
}

/// A full metadata sweep - the shape of an actual triage run.
#[divan::bench(args = FIXTURES)]
fn full_sweep(bencher: Bencher, name: &str) {
    let data = fixture(path_of(name));
    bencher.bench(|| {
        let Some(bin) = GoBinary::parse(black_box(data)) else {
            return 0usize;
        };
        let mut n = bin.functions().count();
        n += bin.types().count();
        n += bin.itab_pairs().count();
        n += bin.strings().count();
        n += bin.init_order().len();
        n += bin.embedded_assets().len();
        black_box(n)
    });
}
