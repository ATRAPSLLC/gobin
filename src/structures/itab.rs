//! `itablink` decoder - recovers `(interface, concrete type)` pairs.
//!
//! When the Go linker proves that a concrete type implements an interface, it
//! emits an `itab` record carrying both type-descriptor pointers plus a hash
//! used at runtime for type-switch dispatch. The set of all generated itabs
//! is enumerated in the `itablinks` slice (or, on ELF, the `.itablink`
//! section), which is an array of `*itab` pointers.
//!
//! ## `itab` Layout (Go 1.16+)
//!
//! ```text
//! Offset  Size       Field    Description
//! 0       ptrSize    inter    *interfacetype  (VA of interface type descriptor)
//! ptrSize ptrSize    _type    *_type          (VA of concrete type descriptor)
//! 2*ptr   4          hash     u32             (copy of _type.hash, for type assertion)
//! 2*ptr+4 4          _pad     [4]byte         (reserved)
//! 2*ptr+8 var        fun[N]   uintptr[]       (method func VAs; N inferred from interfacetype)
//! ```
//!
//! Source: `src/runtime/runtime2.go:982-991`
//!
//! ## Why It Matters
//!
//! Itab pairs let an analyst answer questions like "what implements
//! `io.Reader` in this binary?" - extremely useful when chasing exfiltration
//! paths in malware analysis.

use crate::{
    formats::BinaryContext,
    structures::{
        abitype::AbiType, interfacetype::InterfaceTypeExtra, moduledata::Moduledata,
        util::read_uintptr,
    },
};

/// One `(interface, concrete type)` pair recorded by the linker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItabPair {
    /// Virtual address of the interface type descriptor.
    pub iface_type_va: u64,
    /// Virtual address of the concrete type descriptor.
    pub concrete_type_va: u64,
    /// Type hash (copy of `_type.hash` for runtime type assertions).
    pub hash: u32,
    /// Virtual address of the itab itself.
    pub itab_va: u64,
}

/// Streaming iterator over [`ItabPair`]s in a binary.
///
/// Each [`Iterator::next`] reads one pointer from the underlying itab-array
/// (either the `.itablink` section or `moduledata.itablinks`), dereferences
/// it through VA→file translation, and parses the [`ItabPair`]. Skips entries
/// that fail to dereference / parse - adversarial input cannot panic the walk.
pub struct ItabIter<'a> {
    ctx: &'a BinaryContext<'a>,
    ps: usize,
    source: ItabSource<'a>,
}

/// Where the itab records come from. Go ≤1.26 stores an array of `*itab`
/// pointers (the `.itablink` section or `moduledata.itablinks`); Go 1.27+
/// (V5) dropped that and stores the itab structs *inline* and
/// variable-sized at `[types+itaboffset .. +itabsize]`.
enum ItabSource<'a> {
    /// No itab source available.
    Empty,
    /// Array of pointer-sized `*itab` VAs to dereference.
    Pointers { array: &'a [u8], pos: usize },
    /// Inline variable-sized itab structs (Go 1.27+ / V5). `va` is the
    /// current cursor, `end_va` the exclusive bound; each record advances
    /// by `itab.Size()` (`runtime/iface.go::addModuleItabs`).
    Inline { va: u64, end_va: u64 },
}

impl<'a> ItabIter<'a> {
    fn empty(ctx: &'a BinaryContext<'a>) -> Self {
        Self {
            ctx,
            ps: 0,
            source: ItabSource::Empty,
        }
    }
}

impl Iterator for ItabIter<'_> {
    type Item = ItabPair;

    fn next(&mut self) -> Option<ItabPair> {
        let ps = self.ps;
        if ps == 0 {
            return None;
        }
        let ps_u8 = u8::try_from(ps).ok()?;
        match &mut self.source {
            ItabSource::Empty => None,
            ItabSource::Pointers { array, pos } => loop {
                let end = pos.checked_add(ps)?;
                if end > array.len() {
                    return None;
                }
                let v = match ps {
                    4 => array
                        .get(*pos..end)
                        .and_then(|s| s.try_into().ok())
                        .map(|b: [u8; 4]| u32::from_le_bytes(b) as u64),
                    8 => array
                        .get(*pos..end)
                        .and_then(|s| s.try_into().ok())
                        .map(u64::from_le_bytes),
                    _ => return None,
                };
                *pos = end;
                let itab_va = match v {
                    Some(v) if v != 0 => v,
                    _ => continue,
                };
                if let Some(pair) = parse_itab(self.ctx, itab_va, ps, ps_u8) {
                    return Some(pair);
                }
                // parse failed; skip and try next entry
            },
            ItabSource::Inline { va, end_va } => {
                if *va >= *end_va {
                    return None;
                }
                let cur = *va;
                let pair = parse_itab(self.ctx, cur, ps, ps_u8)?;
                // Advance by the record's true size. `itab.Size()` is
                // sizeof(itab) (== 4*ptrSize) when `fun[0] == 0`, else
                // 4*ptrSize + (nmethods-1)*ptrSize. Stop the walk if we
                // cannot compute a strictly-positive stride - better to
                // truncate than to misalign and emit garbage.
                let stride = itab_stride(self.ctx, cur, ps, ps_u8)?;
                let next = cur.checked_add(stride as u64)?;
                if next <= cur {
                    return None;
                }
                *va = next;
                Some(pair)
            }
        }
    }
}

/// Construct a streaming iterator over the binary's itab pairs.
///
/// Source-of-truth selection:
/// 1. `.itablink` / `__itablink` section (ELF / Mach-O, Go ≤1.26).
/// 2. `moduledata.itablinks` slice (PE / older Go ≤1.26).
/// 3. Inline itab walk at `types+itaboffset` (Go 1.27+ / V5).
/// 4. Empty iterator otherwise.
pub fn extract_iter<'a>(
    ctx: &'a BinaryContext<'a>,
    ptr_size: u8,
    moduledata: Option<&Moduledata>,
) -> ItabIter<'a> {
    let ps = ptr_size as usize;
    if ps == 0 {
        return ItabIter::empty(ctx);
    }
    let sections = ctx.sections();

    if let Some(ref range) = sections.itablink
        && let Some(bytes) = ctx.section_data(range)
    {
        return ItabIter {
            ctx,
            ps,
            source: ItabSource::Pointers {
                array: bytes,
                pos: 0,
            },
        };
    }

    if let Some(slice) = moduledata.and_then(|md| md.itablinks.as_ref())
        && let Some(rest) = ctx.slice_at_va(slice.ptr)
        && let Some(byte_len) = (slice.len as usize).checked_mul(ps)
        && let Some(s) = rest.get(..byte_len)
    {
        return ItabIter {
            ctx,
            ps,
            source: ItabSource::Pointers { array: s, pos: 0 },
        };
    }

    // Go 1.27+ (V5): inline itab structs at types+itaboffset.
    if let Some(md) = moduledata
        && let (Some(itaboffset), Some(itabsize)) = (md.itaboffset, md.itabsize)
        && itabsize > 0
        && let Some(start) = md.types.checked_add(itaboffset)
        && let Some(end_va) = start.checked_add(itabsize)
    {
        return ItabIter {
            ctx,
            ps,
            source: ItabSource::Inline { va: start, end_va },
        };
    }

    ItabIter::empty(ctx)
}

/// Size in bytes of the inline itab record at `itab_va` (Go 1.27+).
///
/// Mirrors `internal/abi.ITab.Size()`: the fixed header is `4*ptrSize`
/// (Inter, Type, Hash+pad, Fun[1]); when `Fun[0] != 0` the record carries
/// one `uintptr` per interface method, so the total is
/// `4*ptrSize + (nmethods-1)*ptrSize`.
fn itab_stride(ctx: &BinaryContext<'_>, itab_va: u64, ps: usize, ps_u8: u8) -> Option<usize> {
    let base = ps.checked_mul(4)?;
    let buf = ctx.slice_at_va(itab_va)?;
    // Fun[0] sits at offset 3*ptrSize (after Inter, Type, Hash+pad).
    let fun0_off = ps.checked_mul(3)?;
    let fun0 = read_uintptr(buf, fun0_off, ps_u8)?;
    if fun0 == 0 {
        return Some(base);
    }
    let inter_va = read_uintptr(buf, 0, ps_u8)?;
    // No method count means no stride. Guessing one (the old code assumed a
    // single method) silently misaligns the rest of the walk and turns every
    // following record into fabricated itab pairs; the caller stops instead.
    let nmethods = interface_method_count(ctx, inter_va, ps_u8)?;
    let extra = nmethods.checked_sub(1)?.checked_mul(ps)?;
    base.checked_add(extra)
}

/// Resolve the `Fun[]` method-pointer array of an itab - the concrete-type
/// implementations bound to each interface method, in interface-method order.
///
/// `Fun` sits at `itab_va + 3*ptrSize` and has one `uintptr` per interface
/// method (count taken from the interface type descriptor). A `0` entry means
/// the linker did not bind that method (the type does not fully implement the
/// interface). Returns an empty vec if the count cannot be resolved.
pub fn itab_methods(ctx: &BinaryContext<'_>, pair: &ItabPair, ptr_size: u8) -> Vec<u64> {
    let ps = ptr_size as usize;
    if ps == 0 {
        return Vec::new();
    }
    let n = match interface_method_count(ctx, pair.iface_type_va, ptr_size) {
        Some(n) if n > 0 && n < 100_000 => n,
        _ => return Vec::new(),
    };
    let fun_off = match pair
        .itab_va
        .checked_add(ps.checked_mul(3).unwrap_or(0) as u64)
    {
        Some(v) => v,
        None => return Vec::new(),
    };
    let buf = match ctx.slice_at_va(fun_off) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let off = match i.checked_mul(ps) {
            Some(o) => o,
            None => break,
        };
        match read_uintptr(buf, off, ptr_size) {
            Some(v) => out.push(v),
            None => break,
        }
    }
    out
}

/// Number of methods declared by the interface type descriptor at `inter_va`.
fn interface_method_count(ctx: &BinaryContext<'_>, inter_va: u64, ps_u8: u8) -> Option<usize> {
    let buf = ctx.slice_at_va(inter_va)?;
    let extra_off = AbiType::size(ps_u8);
    let extra = InterfaceTypeExtra::parse(buf.get(extra_off..)?, ps_u8)?;
    usize::try_from(extra.methods.len).ok()
}

/// Parse a single `itab` at `itab_va`.
fn parse_itab(ctx: &BinaryContext<'_>, itab_va: u64, ps: usize, ps_u8: u8) -> Option<ItabPair> {
    let buf = ctx.slice_at_va(itab_va)?;
    let hash_off = ps.checked_mul(2)?;
    let needed = hash_off.checked_add(4)?;
    if buf.len() < needed {
        return None;
    }
    let iface_type_va = read_uintptr(buf, 0, ps_u8)?;
    let concrete_type_va = read_uintptr(buf, ps, ps_u8)?;
    let hash_end = hash_off.checked_add(4)?;
    let hash_bytes: [u8; 4] = buf.get(hash_off..hash_end)?.try_into().ok()?;
    let hash = u32::from_le_bytes(hash_bytes);
    Some(ItabPair {
        iface_type_va,
        concrete_type_va,
        hash,
        itab_va,
    })
}
