//! `inittasks` decoder - recovers package initialization order.
//!
//! The linker builds `moduledata.inittasks` (`[]*initTask`, Go 1.24+): the
//! ordered list of package-init work the runtime runs at startup. Each entry
//! points at an `initTask`:
//!
//! ```text
//! type initTask struct {
//!     state uint32 // 0 = uninitialized, 1 = in progress, 2 = done
//!     nfns  uint32
//!     // followed by nfns function pointers (uintptr each), one per init fn
//! }
//! ```
//!
//! Source: `src/runtime/proc.go` (`initTask`), `src/cmd/link/internal/ld`.
//!
//! Each function pointer is the entry VA of an init function (`pkg.init`,
//! `pkg.init.0`, …). Resolving those VAs back to names (done by the caller via
//! the pclntab function table) yields a readable startup order - useful for
//! understanding droppers' persistence / staging behaviour.

use crate::{
    formats::BinaryContext,
    structures::{moduledata::Moduledata, util::read_uintptr},
};

/// Hard caps so adversarial `len`/`nfns` fields cannot blow up memory.
const MAX_TASKS: usize = 100_000;
const MAX_FNS_PER_TASK: usize = 100_000;

/// Decode the init tasks into per-task lists of init-function entry VAs.
///
/// Returns one inner `Vec<u64>` per `initTask`, in linker order. Entries that
/// fail to dereference are skipped; a wholly missing/unreadable table yields
/// an empty outer `Vec`. Never panics on malformed input.
pub fn decode(ctx: &BinaryContext<'_>, md: &Moduledata, ps: u8) -> Vec<Vec<u64>> {
    let p = ps as usize;
    let (Some(slice), true) = (md.inittasks.as_ref(), p == 4 || p == 8) else {
        return Vec::new();
    };
    let ntasks = (slice.len as usize).min(MAX_TASKS);
    if ntasks == 0 {
        return Vec::new();
    }
    let array = match ctx.slice_at_va(slice.ptr) {
        Some(a) => a,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    for i in 0..ntasks {
        let ptr_off = match i.checked_mul(p) {
            Some(o) => o,
            None => break,
        };
        let task_va = match read_uintptr(array, ptr_off, ps) {
            Some(v) if v != 0 => v,
            _ => continue,
        };
        if let Some(fns) = decode_one(ctx, task_va, ps) {
            out.push(fns);
        }
    }
    out
}

/// Decode a single `initTask` at `task_va` into its init-function entry VAs.
fn decode_one(ctx: &BinaryContext<'_>, task_va: u64, ps: u8) -> Option<Vec<u64>> {
    let p = ps as usize;
    let buf = ctx.slice_at_va(task_va)?;
    // state (u32) @ 0, nfns (u32) @ 4, then nfns pointers @ 8.
    let nfns_bytes: [u8; 4] = buf.get(4..8)?.try_into().ok()?;
    let nfns = (u32::from_le_bytes(nfns_bytes) as usize).min(MAX_FNS_PER_TASK);
    let mut fns = Vec::with_capacity(nfns.min(64));
    for j in 0..nfns {
        let off = j.checked_mul(p).and_then(|o| o.checked_add(8))?;
        match read_uintptr(buf, off, ps) {
            Some(pc) if pc != 0 => fns.push(pc),
            _ => break,
        }
    }
    Some(fns)
}
