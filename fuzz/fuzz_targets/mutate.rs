//! Real Go binaries with a few targeted byte patches, through every accessor.
//!
//! The input does not carry a binary. It picks one of the fixtures under
//! `tests/samples` (loaded once), one or more regions of it that hold Go
//! structures (pclntab, moduledata, type descriptors, build info, coverage
//! blobs, ...), and patches to apply there. The container stays valid, so
//! the damage reaches the Go decoders instead of stopping at the file header.
//! Patches are undone after each run.
//!
//! `GOBIN_FUZZ_SAMPLES` overrides the fixture directory; `GOBIN_FUZZ_DUMP`
//! names a file to write the patched binary to (for triage).

#![no_main]

use std::ops::Range;
use std::sync::{Mutex, OnceLock};

use arbitrary::{Arbitrary, Result, Unstructured};
use gobin::GoBinary;
use libfuzzer_sys::fuzz_target;

/// A mix of Go versions, formats and build modes.
const FIXTURES: &[&str] = &[
    "basic_go12_linux_amd64",
    "basic_go14_linux_amd64",
    "basic_go17_linux_amd64",
    "basic_go110_linux_amd64",
    "basic_go113_linux_amd64",
    "basic_go116_windows_amd64.exe",
    "generics_go118_linux_amd64",
    "basic_go120_linux_amd64_cover",
    "basic_go121_linux_386",
    "basic_go124_darwin_arm64",
    "basic_go126_wasip1_wasm",
    "basic_go127_linux_amd64_pie",
    "basic_go127_windows_amd64_stripped.exe",
    "basic_go128_linux_amd64",
    "basic_go128_js_wasm",
    "deps_go128_linux_amd64_cover_stripped",
    "embed_go127_linux_amd64",
    "types_go128_linux_amd64",
    "plugin_go126_darwin_arm64.so",
    "basic_go128_darwin_universal",
];

struct Fixture {
    data: Vec<u8>,
    /// File ranges worth patching; the whole file is always first.
    regions: Vec<Range<usize>>,
}

fn fixtures() -> &'static [Mutex<Fixture>] {
    static FIXTURES_LOADED: OnceLock<Vec<Mutex<Fixture>>> = OnceLock::new();
    FIXTURES_LOADED.get_or_init(|| {
        let dir = std::env::var("GOBIN_FUZZ_SAMPLES")
            .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/samples").into());
        FIXTURES
            .iter()
            .map(|name| {
                let path = format!("{dir}/{name}");
                let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
                let regions = regions(&data);
                Mutex::new(Fixture { data, regions })
            })
            .collect()
    })
}

/// The file ranges of `data` that hold Go structures, found through the
/// crate's own view of the unpatched binary.
fn regions(data: &[u8]) -> Vec<Range<usize>> {
    let mut out = vec![0..data.len()];
    let mut push = |start: usize, len: usize| {
        let end = start.saturating_add(len).min(data.len());
        if start < end {
            out.push(start..end);
        }
    };
    let find = |needle: &[u8]| data.windows(needle.len()).position(|w| w == needle);
    if let Some(at) = find(b"\xff Go buildinf:") {
        push(at, 0x1000);
    }
    if let Some(at) = find(b"\xff Go build ID: \"") {
        push(at, 0x100);
    }
    // A fat Mach-O: its header and each slice's start.
    if let Some(slices) = gobin::formats::macho_slices(data) {
        push(0, 0x200);
        for slice in slices {
            push(slice.range.start, 0x2000);
        }
        return out;
    }
    let Ok(bin) = GoBinary::try_parse(data) else {
        return out;
    };
    let ctx = bin.context();
    let sections = ctx.sections();
    for range in [
        sections.gopclntab,
        sections.go_buildinfo,
        sections.go_module,
        sections.typelink,
        sections.itablink,
        sections.go_type,
        sections.go_func,
    ]
    .into_iter()
    .flatten()
    {
        push(range.offset, range.size);
    }
    let file = |va: u64| ctx.va_to_file(va);
    if let Some(md) = bin.moduledata() {
        // The moduledata record itself: where its first word, the pcHeader
        // address, is stored.
        let width = match bin.pclntab().map(|p| p.meta().ptr_size) {
            Some(4) => 4,
            _ => 8,
        };
        let header = md.pc_header.to_le_bytes();
        if let Some(at) = header.get(..width).and_then(|needle| find(needle)) {
            push(at, 0x300);
        }
        for slice in [
            md.ftab,
            md.pclntable,
            md.funcnametab,
            md.filetab,
            md.cutab,
            md.pctab,
        ] {
            if let Some(at) = file(slice.ptr) {
                push(at, slice.len.min(1 << 20) as usize);
            }
        }
        if let Some(at) = file(md.pc_header) {
            push(at, 0x100);
        }
        if let (Some(start), Some(end)) = (file(md.types), file(md.etypes)) {
            push(start, end.saturating_sub(start));
            // The first descriptors, where most structure starts.
            push(start, 0x4000);
        }
        for slice in [md.typelinks, md.itablinks].into_iter().flatten() {
            if let Some(at) = file(slice.ptr) {
                push(at, slice.len.saturating_mul(8).min(1 << 20) as usize);
            }
        }
        if let Some(at) = md.gofunc.and_then(file) {
            push(at, 0x10000);
        }
        for range in [md.noptrdata, md.data] {
            if let Some(at) = file(range.start) {
                push(at, range.size().min(1 << 20) as usize);
            }
        }
    }
    for package in bin.symbols().iter() {
        if package.name.contains(".goCover_") && package.name.ends_with("_M") {
            if let Some(at) = file(package.va) {
                push(at, package.size.max(64) as usize);
            }
        }
    }
    out
}

/// A value to store, chosen to hit bounds and counts.
#[derive(Arbitrary, Debug)]
enum Value {
    Zero,
    One,
    AllOnes,
    SignedMax,
    /// The region's length: an offset or count just past the end.
    RegionLen,
    /// Add a small delta to what is there: an off-by-a-little offset.
    Nudge(i8),
    Raw(u64),
}

#[derive(Arbitrary, Debug)]
enum Op {
    /// Overwrite with up to 16 bytes.
    Bytes(Vec<u8>),
    /// Store a little-endian integer of `1 << (width % 4)` bytes.
    Int { width: u8, value: Value },
    /// Copy up to 64 bytes from elsewhere in the same region.
    Copy { from: u32, len: u8 },
}

#[derive(Debug)]
struct Patch {
    region: u8,
    offset: u32,
    op: Op,
}

impl<'a> Arbitrary<'a> for Patch {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        Ok(Patch {
            region: u.arbitrary()?,
            offset: u.arbitrary()?,
            op: match u.int_in_range(0..=2u8)? {
                0 => {
                    let len = u.int_in_range(1..=16usize)?;
                    Op::Bytes(u.bytes(len)?.to_vec())
                }
                1 => Op::Int {
                    width: u.arbitrary()?,
                    value: u.arbitrary()?,
                },
                _ => Op::Copy {
                    from: u.arbitrary()?,
                    len: u.arbitrary()?,
                },
            },
        })
    }
}

#[derive(Debug)]
struct Input {
    fixture: u8,
    patches: Vec<Patch>,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let fixture = u.arbitrary()?;
        let count = u.int_in_range(1..=8usize)?;
        let mut patches = Vec::with_capacity(count);
        for _ in 0..count {
            patches.push(u.arbitrary()?);
        }
        Ok(Input { fixture, patches })
    }
}

/// Apply `patch` to `data`, recording the bytes it replaced in `undo`.
fn apply(
    data: &mut [u8],
    regions: &[Range<usize>],
    patch: &Patch,
    undo: &mut Vec<(usize, Vec<u8>)>,
) {
    let Some(region) = regions.get(usize::from(patch.region) % regions.len()) else {
        return;
    };
    let len = region.len();
    if len == 0 {
        return;
    }
    let at = region.start + (patch.offset as usize) % len;
    let bytes: Vec<u8> = match &patch.op {
        Op::Bytes(bytes) => bytes.clone(),
        Op::Int { width, value } => {
            let width = 1usize << (width % 4);
            let mut current = [0u8; 8];
            let available = data.len().saturating_sub(at).min(width);
            current[..available].copy_from_slice(&data[at..at + available]);
            let current = u64::from_le_bytes(current);
            let v = match value {
                Value::Zero => 0,
                Value::One => 1,
                Value::AllOnes => u64::MAX,
                Value::SignedMax => (1u64 << (width * 8 - 1)) - 1,
                Value::RegionLen => len as u64,
                Value::Nudge(d) => current.wrapping_add(*d as i64 as u64),
                Value::Raw(v) => *v,
            };
            v.to_le_bytes()[..width].to_vec()
        }
        Op::Copy { from, len: n } => {
            let from = region.start + (*from as usize) % len;
            let end = (from + usize::from(*n)).min(region.end);
            data[from..end].to_vec()
        }
    };
    let end = (at + bytes.len()).min(data.len());
    undo.push((at, data[at..end].to_vec()));
    data[at..end].copy_from_slice(&bytes[..end - at]);
}

fuzz_target!(
    // Loading and mapping the fixtures takes seconds; keep it off the clock
    // of the first input.
    init: {
        fixtures();
    },
    |input: Input| {
    let all = fixtures();
    let Some(slot) = all.get(usize::from(input.fixture) % all.len()) else {
        return;
    };
    let mut fixture = slot.lock().unwrap_or_else(|e| e.into_inner());
    let Fixture { data, regions } = &mut *fixture;
    let mut undo = Vec::new();
    for patch in &input.patches {
        apply(data, regions, patch, &mut undo);
    }
    // Triage: `GOBIN_FUZZ_DUMP=<file>` prints the patches and writes the
    // patched binary out, to study it outside the fuzzer.
    if let Some(path) = std::env::var_os("GOBIN_FUZZ_DUMP") {
        eprintln!("fixture {} patches {:?}", FIXTURES[usize::from(input.fixture) % FIXTURES.len()], input.patches);
        eprintln!("patched (offset, old bytes): {undo:x?}");
        let _ = std::fs::write(path, &data);
    }
    gobin_fuzz::parse_and_exercise(data);
    for (at, old) in undo.into_iter().rev() {
        data[at..at + old.len()].copy_from_slice(&old);
    }
    }
);
