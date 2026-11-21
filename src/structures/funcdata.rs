//! Per-function data: the `FUNCDATA` blocks and `PCDATA` tables a Go `_func`
//! record points at.
//!
//! Each function record ends with `npcdata` table offsets and `nfuncdata`
//! block references. The runtime reads them by index (`funcdata(f, i)`,
//! `pcdatavalue(f, i, pc)`), and the indices are constants of the Go version:
//! they were renumbered in Go 1.13 and 1.16 as kinds joined and left
//! (`runtime/funcdata.h`). [`FuncDataKind::index`] and [`PcDataKind::index`]
//! hold those tables, Go 1.2 to tip.
//!
//! A block reference is a pointer through Go 1.17 and, from Go 1.18, a `u32`
//! offset from `moduledata.gofunc` (`^0` for none); see
//! [`crate::GoBinary::funcdata`]. The decoders here read the blocks
//! themselves, each in the format its Go version wrote:
//!
//! | Kind | Go | Decoder |
//! |------|----|---------|
//! | `ArgsPointerMaps`, `LocalsPointerMaps` | all | [`PointerMaps::parse`] ([`PointerMapFormat`]) |
//! | `StackObjects` | 1.12+ | [`parse_stack_objects`] |
//! | `OpenCodedDeferInfo` | 1.14+ | [`OpenDefers::parse`] |
//! | `ArgInfo` | 1.17+ | [`ArgLayout::parse`] |
//! | `WrapInfo` | 1.18+ | [`parse_wrap_info`] |
//! | `InlTree` | 1.9+ | [`crate::structures::inline`] |
//!
//! Sources: `src/runtime/funcdata.h`, `src/internal/abi/symtab.go`,
//! `src/runtime/{symtab,stack,panic,traceback,tracestack}.go`, per release.

use crate::util::{read_i32, read_u32, read_uintptr, read_uvarint};

/// A kind of per-function data block (`FUNCDATA_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FuncDataKind {
    /// GC pointer maps of the arguments, one per safe point (all versions;
    /// `FUNCDATA_GCArgs` in Go 1.2).
    ArgsPointerMaps,
    /// GC pointer maps of the locals, one per safe point (all versions).
    LocalsPointerMaps,
    /// GC pointer maps of the registers (Go 1.11-1.15).
    RegPointerMaps,
    /// The frame's stack objects: addressable locals the GC traces (Go 1.12+).
    StackObjects,
    /// The inlining tree (Go 1.9+).
    InlTree,
    /// Where open-coded defers keep their state (Go 1.14+).
    OpenCodedDeferInfo,
    /// The argument layout tracebacks print (Go 1.17+).
    ArgInfo,
    /// Liveness of register-passed arguments for tracebacks (Go 1.18+).
    ArgLiveInfo,
    /// For a wrapper, the function it wraps (Go 1.18+).
    WrapInfo,
}

impl FuncDataKind {
    /// The `FUNCDATA` index of this kind in Go 1.`go_minor`, or `None` when
    /// that version has no such kind.
    pub fn index(self, go_minor: u32) -> Option<u8> {
        let m = go_minor;
        match self {
            Self::ArgsPointerMaps => Some(0),
            Self::LocalsPointerMaps => Some(1),
            Self::RegPointerMaps => match m {
                11 | 12 => Some(3),
                13..=15 => Some(2),
                _ => None,
            },
            Self::StackObjects => match m {
                12 => Some(4),
                13..=15 => Some(3),
                16.. => Some(2),
                _ => None,
            },
            Self::InlTree => match m {
                9..=12 => Some(2),
                13..=15 => Some(4),
                16.. => Some(3),
                _ => None,
            },
            Self::OpenCodedDeferInfo => match m {
                14 | 15 => Some(5),
                16.. => Some(4),
                _ => None,
            },
            Self::ArgInfo => (m >= 17).then_some(5),
            Self::ArgLiveInfo => (m >= 18).then_some(6),
            Self::WrapInfo => (m >= 18).then_some(7),
        }
    }
}

/// A kind of per-PC table (`PCDATA_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcDataKind {
    /// Whether a PC is safe for asynchronous preemption (Go 1.16+).
    UnsafePoint,
    /// The index of the pointer map in effect at a PC (Go 1.3+).
    StackMapIndex,
    /// The inlining-tree node in effect at a PC, or `-1` (Go 1.9+).
    InlTreeIndex,
    /// The register pointer map in effect at a PC (Go 1.11-1.15).
    RegMapIndex,
    /// The argument-liveness bitmap in effect at a PC (Go 1.18+).
    ArgLiveIndex,
    /// How a bounds-check panic at a PC finds its operands (Go 1.26+).
    PanicBounds,
}

impl PcDataKind {
    /// The `PCDATA` index of this kind in Go 1.`go_minor`, or `None` when
    /// that version has no such kind.
    pub fn index(self, go_minor: u32) -> Option<u32> {
        let m = go_minor;
        match self {
            Self::UnsafePoint => (m >= 16).then_some(0),
            Self::StackMapIndex => match m {
                3..=12 => Some(0),
                13.. => Some(1),
                _ => None,
            },
            Self::InlTreeIndex => match m {
                9..=12 => Some(1),
                13.. => Some(2),
                _ => None,
            },
            Self::RegMapIndex => match m {
                11 | 12 => Some(2),
                13..=15 => Some(0),
                _ => None,
            },
            Self::ArgLiveIndex => (m >= 18).then_some(3),
            Self::PanicBounds => (m >= 26).then_some(4),
        }
    }
}

/// The text offset a wrapper's `WrapInfo` block names: the function it
/// wraps (`runtime.startPCForTrace`). Resolve it with
/// [`crate::GoBinary::text_addr`].
pub fn parse_wrap_info(block: &[u8]) -> Option<u32> {
    read_u32(block, 0)
}

/// The longest `ArgInfo` encoding the runtime reads (`abi.TraceArgsMaxLen`:
/// ten elements at depth five, three bytes each, plus the end marker).
const ARG_INFO_MAX_LEN: usize = (5 * 3 + 2) * 10;

/// `ArgInfo` marker: end of the sequence.
const ARG_END_SEQ: u8 = 0xff;
/// `ArgInfo` marker: an aggregate (struct, array) begins.
const ARG_START_AGG: u8 = 0xfe;
/// `ArgInfo` marker: the current aggregate ends.
const ARG_END_AGG: u8 = 0xfd;
/// `ArgInfo` marker: more arguments follow that were not recorded.
const ARG_DOTDOTDOT: u8 = 0xfc;
/// `ArgInfo` marker: an argument whose offset does not fit a byte.
const ARG_OFFSET_TOO_LARGE: u8 = 0xfb;

/// One element of a function's argument layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgItem {
    /// A scalar the traceback prints: `size` bytes at `offset` from the
    /// argument area (register arguments: their spill slots).
    Value {
        /// Offset from the start of the argument area.
        offset: u8,
        /// Size in bytes.
        size: u8,
    },
    /// A struct or array, laid out element by element.
    Aggregate(Vec<ArgItem>),
    /// An element whose offset does not fit the encoding's byte.
    OffsetTooLarge,
    /// The compiler stopped recording here: more arguments (or elements) follow.
    Truncated,
}

/// A function's argument layout (`FUNCDATA_ArgInfo`, Go 1.17+): what a
/// traceback prints as the call's arguments.
///
/// The compiler records the first ten elements at each level, scalar fields
/// of aggregates included, nested up to five deep; the rest is
/// [`ArgItem::Truncated`]. It gives the shape of a function's parameters even
/// where no other record of its signature survives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgLayout {
    /// The top-level arguments, in order.
    pub items: Vec<ArgItem>,
}

impl ArgLayout {
    /// Decode an `ArgInfo` block (`runtime.printArgs`). `None` when the
    /// encoding does not end within the runtime's bound or is unbalanced.
    pub fn parse(block: &[u8]) -> Option<Self> {
        let bytes = block.get(..ARG_INFO_MAX_LEN.min(block.len()))?;
        let mut stack: Vec<Vec<ArgItem>> = vec![Vec::new()];
        let mut pos = 0usize;
        loop {
            let op = *bytes.get(pos)?;
            pos = pos.checked_add(1)?;
            match op {
                ARG_END_SEQ => {
                    let items = stack.pop()?;
                    return stack.is_empty().then_some(Self { items });
                }
                ARG_START_AGG => stack.push(Vec::new()),
                ARG_END_AGG => {
                    let agg = stack.pop()?;
                    stack.last_mut()?.push(ArgItem::Aggregate(agg));
                }
                ARG_DOTDOTDOT => stack.last_mut()?.push(ArgItem::Truncated),
                ARG_OFFSET_TOO_LARGE => stack.last_mut()?.push(ArgItem::OffsetTooLarge),
                offset => {
                    let size = *bytes.get(pos)?;
                    pos = pos.checked_add(1)?;
                    stack.last_mut()?.push(ArgItem::Value { offset, size });
                }
            }
        }
    }

    /// The number of top-level arguments recorded, aggregates counting as
    /// one; `None` when the compiler truncated the list.
    pub fn count(&self) -> Option<usize> {
        if self.items.contains(&ArgItem::Truncated) {
            return None;
        }
        Some(self.items.len())
    }
}

/// One open-coded defer of a Go 1.14-1.17 function, with the arguments the
/// frame saved for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenDeferCall {
    /// Total size of the deferred call's arguments (Go 1.14-1.17).
    pub arg_width: Option<u32>,
    /// Frame offset (below `varp`) of the deferred closure.
    pub closure_offset: u32,
    /// Each saved argument: its frame offset (below `varp`), length and
    /// offset in the call's argument area (Go 1.14-1.17).
    pub args: Vec<OpenDeferArg>,
}

/// One argument an open-coded defer saved in the frame (Go 1.14-1.17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenDeferArg {
    /// Frame offset (below `varp`) where the argument was saved.
    pub frame_offset: u32,
    /// Length in bytes.
    pub len: u32,
    /// Offset in the deferred call's argument area.
    pub call_offset: u32,
}

/// Where a function's open-coded defers keep their state
/// (`FUNCDATA_OpenCodedDeferInfo`, Go 1.14+): a function the compiler gave
/// at most eight defers, none in a loop, runs them inline at return instead
/// of through the runtime's defer records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenDefers {
    /// Go 1.14-1.21: the defers are listed, each with its closure slot (and,
    /// to Go 1.17, its saved arguments).
    Listed {
        /// Frame offset (below `varp`) of the byte whose bits mark which
        /// defers are armed.
        defer_bits_offset: u32,
        /// The largest argument area of the deferred calls (Go 1.14-1.17).
        max_arg_size: Option<u32>,
        /// The defers, in source order.
        calls: Vec<OpenDeferCall>,
    },
    /// Go 1.22+: the defers' closures fill consecutive slots from
    /// `slots_offset`, one per bit of the defer byte; their count is not
    /// recorded.
    Slots {
        /// Frame offset (below `varp`) of the defer bits byte.
        defer_bits_offset: u32,
        /// Frame offset (below `varp`) of the first closure slot.
        slots_offset: u32,
    },
}

impl OpenDefers {
    /// Decode an `OpenCodedDeferInfo` block in the format of Go 1.`go_minor`
    /// (`runtime.runOpenDeferFrame`; then `openDeferInfo` from Go 1.22).
    /// `None` when it does not decode within the eight defers the compiler
    /// allows.
    pub fn parse(block: &[u8], go_minor: u32) -> Option<Self> {
        let mut pos = 0usize;
        let mut next = || -> Option<u32> {
            let (value, len) = read_uvarint(block.get(pos..)?)?;
            pos = pos.checked_add(len)?;
            u32::try_from(value).ok()
        };
        if go_minor >= 22 {
            let defer_bits_offset = next()?;
            let slots_offset = next()?;
            return Some(Self::Slots {
                defer_bits_offset,
                slots_offset,
            });
        }
        let with_args = go_minor <= 17;
        let max_arg_size = if with_args { Some(next()?) } else { None };
        let defer_bits_offset = next()?;
        let n = next()?;
        if n > 8 {
            return None;
        }
        let mut calls = Vec::new();
        for _ in 0..n {
            let arg_width = if with_args { Some(next()?) } else { None };
            let closure_offset = next()?;
            let mut args = Vec::new();
            if with_args {
                let nargs = next()?;
                for _ in 0..nargs.min(64) {
                    args.push(OpenDeferArg {
                        frame_offset: next()?,
                        len: next()?,
                        call_offset: next()?,
                    });
                }
            }
            calls.push(OpenDeferCall {
                arg_width,
                closure_offset,
                args,
            });
        }
        Some(Self::Listed {
            defer_bits_offset,
            max_arg_size,
            calls,
        })
    }

    /// The number of open-coded defers, where the format records it (Go
    /// 1.14-1.21).
    pub fn count(&self) -> Option<usize> {
        match self {
            Self::Listed { calls, .. } => Some(calls.len()),
            Self::Slots { .. } => None,
        }
    }
}

/// One stack object of a frame: an addressable local (or argument) the
/// garbage collector traces by its type (`FUNCDATA_StackObjects`, Go 1.12+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackObject {
    /// Offset in the frame: from `varp` when negative (a local), from `argp`
    /// otherwise (an argument).
    pub frame_offset: i64,
    /// Size in bytes (Go 1.17+; before, the type's).
    pub size: Option<u32>,
    /// Bytes of the object that hold pointers (Go 1.17+; negative when its
    /// pointer layout is a GC program, Go 1.17 only).
    pub ptr_bytes: Option<i32>,
    /// The object's type descriptor (Go 1.12-1.16, which recorded the type).
    pub type_va: Option<u64>,
    /// Its pointer bitmap (Go 1.17+; from Go 1.18 relative to
    /// `moduledata.rodata`, resolved here when `rodata` is given).
    pub gcdata_va: Option<u64>,
}

/// Decode a `StackObjects` block of Go 1.`go_minor` (`runtime.getStackMap`):
/// a pointer-sized count, then one `stackObjectRecord` per object, in the
/// record shape of that version. `rodata` is `moduledata.rodata`, against
/// which Go 1.18+ records place their bitmap. At most 1 Mi objects are read.
pub fn parse_stack_objects(
    block: &[u8],
    ps: u8,
    go_minor: u32,
    rodata: Option<u64>,
) -> Option<Vec<StackObject>> {
    let p = usize::from(ps);
    let count = usize::try_from(read_uintptr(block, 0, ps)?).ok()?;
    if count > 1 << 20 {
        return None;
    }
    let record = match go_minor {
        // {off int, typ *_type}
        ..=16 => p.checked_mul(2)?,
        // {off, size, _ptrdata int32, gcdata *byte}, gcdata pointer-aligned.
        17 => 12usize.next_multiple_of(p).checked_add(p)?,
        // {off, size, ptrBytes int32, gcdataoff uint32}
        _ => 16,
    };
    let mut out = Vec::with_capacity(count.min(4096));
    for i in 0..count {
        let at = i.checked_mul(record)?.checked_add(p)?;
        let object = match go_minor {
            ..=16 => {
                let off = read_uintptr(block, at, ps)?;
                let off = if ps == 4 {
                    i64::from(off as u32 as i32)
                } else {
                    off as i64
                };
                StackObject {
                    frame_offset: off,
                    size: None,
                    ptr_bytes: None,
                    type_va: Some(read_uintptr(block, at.checked_add(p)?, ps)?),
                    gcdata_va: None,
                }
            }
            _ => {
                let frame_offset = i64::from(read_i32(block, at)?);
                let size = u32::try_from(read_i32(block, at.checked_add(4)?)?).ok()?;
                let ptr_bytes = read_i32(block, at.checked_add(8)?)?;
                let gcdata_va = if go_minor == 17 {
                    let field = 12usize.next_multiple_of(p);
                    Some(read_uintptr(block, at.checked_add(field)?, ps)?)
                } else {
                    let off = read_u32(block, at.checked_add(12)?)?;
                    rodata.and_then(|base| base.checked_add(u64::from(off)))
                };
                StackObject {
                    frame_offset,
                    size: Some(size),
                    ptr_bytes: Some(ptr_bytes),
                    type_va: None,
                    gcdata_va,
                }
            }
        };
        out.push(object);
    }
    Some(out)
}

/// The shape of a GC pointer-map block, which changed three times.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerMapFormat {
    /// Go 1.2: one bitvector (`n` bits, then `uint32` words), two bits per
    /// word.
    Go12,
    /// Go 1.3-1.4: `n` maps of `nbit` bits, each padded to 32-bit words, two
    /// bits per word.
    Go13,
    /// Go 1.5-1.7: as Go 1.3, one bit per word.
    Go15,
    /// Go 1.8+: `n` maps of `nbit` bits, each padded to a byte, one bit per
    /// word.
    Go18,
}

impl PointerMapFormat {
    /// The format of Go 1.`go_minor`.
    pub fn for_go_minor(go_minor: u32) -> Self {
        match go_minor {
            ..=2 => Self::Go12,
            3 | 4 => Self::Go13,
            5..=7 => Self::Go15,
            _ => Self::Go18,
        }
    }

    /// Bits of a map that describe one pointer-sized word.
    pub fn bits_per_word(self) -> u32 {
        match self {
            Self::Go12 | Self::Go13 => 2,
            Self::Go15 | Self::Go18 => 1,
        }
    }

    /// Bytes from one map to the next, for maps of `bits` bits.
    fn stride(self, bits: u32) -> u32 {
        match self {
            Self::Go12 | Self::Go13 | Self::Go15 => bits.div_ceil(32).saturating_mul(4),
            Self::Go18 => bits.div_ceil(8),
        }
    }
}

/// What a Go 1.2-1.4 two-bit pointer-map entry says of a word
/// (`BitsDead`, `BitsScalar`, `BitsPointer`, `BitsMultiWord`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordKind {
    /// Not live (`BitsDead`).
    Dead,
    /// Live, holds no pointer (`BitsScalar`).
    Scalar,
    /// Live, holds a pointer (`BitsPointer`).
    Pointer,
    /// The first word of a multi-word value, a string, slice or interface
    /// (`BitsMultiWord`); the next entry says which.
    MultiWord,
}

/// A function's GC pointer maps (`FUNCDATA_ArgsPointerMaps` or
/// `LocalsPointerMaps`; the runtime's `stackmap`): one bitmap per safe point
/// over the pointer-sized words of the arguments or locals.
/// `PCDATA_StackMapIndex` selects the map in effect at a PC. Borrowed from
/// the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerMaps<'a> {
    /// The block's shape.
    pub format: PointerMapFormat,
    /// Number of bitmaps.
    pub count: u32,
    /// Bits in each bitmap ([`PointerMapFormat::bits_per_word`] per word).
    pub bits: u32,
    /// The bitmaps, back to back.
    pub data: &'a [u8],
}

impl<'a> PointerMaps<'a> {
    /// Decode a pointer-map block in `format` (`runtime.stackmapdata`).
    /// `None` when the bitmaps would run past the block.
    pub fn parse(block: &'a [u8], format: PointerMapFormat) -> Option<Self> {
        let (count, bits, start) = match format {
            PointerMapFormat::Go12 => (1, u32::try_from(read_i32(block, 0)?).ok()?, 4),
            _ => (
                u32::try_from(read_i32(block, 0)?).ok()?,
                u32::try_from(read_i32(block, 4)?).ok()?,
                8,
            ),
        };
        let len = usize::try_from(format.stride(bits))
            .ok()?
            .checked_mul(usize::try_from(count).ok()?)?;
        let data = block.get(start..)?.get(..len)?;
        Some(Self {
            format,
            count,
            bits,
            data,
        })
    }

    /// The number of pointer-sized words each map describes.
    pub fn words(&self) -> u32 {
        self.bits
            .checked_div(self.format.bits_per_word())
            .unwrap_or(0)
    }

    /// The `i`-th bitmap, padded as its format pads it.
    pub fn map(&self, i: u32) -> Option<&'a [u8]> {
        let stride = usize::try_from(self.format.stride(self.bits)).ok()?;
        let start = usize::try_from(i).ok()?.checked_mul(stride)?;
        self.data.get(start..start.checked_add(stride)?)
    }

    /// Whether word `word` holds a live pointer in the `i`-th bitmap.
    pub fn is_pointer(&self, i: u32, word: u32) -> Option<bool> {
        Some(self.word_kind(i, word)? == WordKind::Pointer)
    }

    /// What the `i`-th bitmap says of word `word`. One-bit formats (Go
    /// 1.5+) say [`WordKind::Pointer`] or [`WordKind::Scalar`].
    pub fn word_kind(&self, i: u32, word: u32) -> Option<WordKind> {
        if word >= self.words() {
            return None;
        }
        let width = self.format.bits_per_word();
        let bit = word.checked_mul(width)?;
        let byte = *self.map(i)?.get(usize::try_from(bit / 8).ok()?)?;
        let value = (byte >> (bit % 8)) & if width == 2 { 3 } else { 1 };
        Some(match (width, value) {
            (1, 1) | (2, 2) => WordKind::Pointer,
            (1, _) | (2, 1) => WordKind::Scalar,
            (_, 0) => WordKind::Dead,
            _ => WordKind::MultiWord,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indices_follow_the_go_version() {
        assert_eq!(FuncDataKind::InlTree.index(10), Some(2));
        assert_eq!(FuncDataKind::InlTree.index(14), Some(4));
        assert_eq!(FuncDataKind::InlTree.index(27), Some(3));
        assert_eq!(FuncDataKind::InlTree.index(8), None);
        assert_eq!(FuncDataKind::StackObjects.index(12), Some(4));
        assert_eq!(FuncDataKind::StackObjects.index(13), Some(3));
        assert_eq!(FuncDataKind::StackObjects.index(16), Some(2));
        assert_eq!(FuncDataKind::WrapInfo.index(17), None);
        assert_eq!(FuncDataKind::WrapInfo.index(18), Some(7));
        assert_eq!(PcDataKind::StackMapIndex.index(12), Some(0));
        assert_eq!(PcDataKind::StackMapIndex.index(13), Some(1));
        assert_eq!(PcDataKind::InlTreeIndex.index(12), Some(1));
        assert_eq!(PcDataKind::InlTreeIndex.index(20), Some(2));
        assert_eq!(PcDataKind::PanicBounds.index(25), None);
    }

    #[test]
    fn arg_layout_decodes_values_aggregates_and_markers() {
        // (0,8) {(8,8) (16,8)} ... end
        let block = [
            0,
            8,
            ARG_START_AGG,
            8,
            8,
            16,
            8,
            ARG_END_AGG,
            ARG_DOTDOTDOT,
            ARG_END_SEQ,
        ];
        let layout = ArgLayout::parse(&block).unwrap();
        assert_eq!(
            layout.items,
            vec![
                ArgItem::Value { offset: 0, size: 8 },
                ArgItem::Aggregate(vec![
                    ArgItem::Value { offset: 8, size: 8 },
                    ArgItem::Value {
                        offset: 16,
                        size: 8
                    },
                ]),
                ArgItem::Truncated,
            ]
        );
        assert_eq!(layout.count(), None);
        // Unterminated, unbalanced, or cut off mid-pair: no layout.
        assert!(ArgLayout::parse(&[0, 8]).is_none());
        assert!(ArgLayout::parse(&[ARG_START_AGG, ARG_END_SEQ]).is_none());
        assert!(ArgLayout::parse(&[ARG_END_AGG, ARG_END_SEQ]).is_none());
        assert!(ArgLayout::parse(&[0]).is_none());
        assert_eq!(ArgLayout::parse(&[ARG_END_SEQ]).unwrap().count(), Some(0));
    }

    #[test]
    fn open_defers_decode_each_format() {
        // Go 1.22+: deferBits, slots.
        assert_eq!(
            OpenDefers::parse(&[0x10, 0x30], 22),
            Some(OpenDefers::Slots {
                defer_bits_offset: 0x10,
                slots_offset: 0x30
            })
        );
        // Go 1.18-1.21: deferBits, n, closure offsets.
        let listed = OpenDefers::parse(&[0x09, 2, 0x18, 0x20], 21).unwrap();
        assert_eq!(listed.count(), Some(2));
        // Go 1.14-1.17: maxargsize, deferBits, n, {argWidth, closure, nArgs, args}.
        let old = OpenDefers::parse(&[8, 0x09, 1, 8, 0x18, 1, 0x28, 8, 0], 17).unwrap();
        assert_eq!(
            old,
            OpenDefers::Listed {
                defer_bits_offset: 0x09,
                max_arg_size: Some(8),
                calls: vec![OpenDeferCall {
                    arg_width: Some(8),
                    closure_offset: 0x18,
                    args: vec![OpenDeferArg {
                        frame_offset: 0x28,
                        len: 8,
                        call_offset: 0
                    }],
                }],
            }
        );
        // More defers than the compiler allows, or cut short: rejected.
        assert!(OpenDefers::parse(&[0x09, 9], 20).is_none());
        assert!(OpenDefers::parse(&[0x09, 2, 0x18], 20).is_none());
    }

    #[test]
    fn stack_objects_decode_each_record_shape() {
        let mut block = 2u64.to_le_bytes().to_vec();
        // Go 1.18+: {off, size, ptrBytes, gcdataoff}
        for (off, size, ptr, gc) in [(-16i32, 16i32, 8i32, 0x40u32), (-40, 24, 0, 0)] {
            block.extend_from_slice(&off.to_le_bytes());
            block.extend_from_slice(&size.to_le_bytes());
            block.extend_from_slice(&ptr.to_le_bytes());
            block.extend_from_slice(&gc.to_le_bytes());
        }
        let objects = parse_stack_objects(&block, 8, 20, Some(0x1000)).unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].frame_offset, -16);
        assert_eq!(objects[0].size, Some(16));
        assert_eq!(objects[0].gcdata_va, Some(0x1040));
        // Go 1.12-1.16: {off int, typ *_type}
        let mut old = 1u64.to_le_bytes().to_vec();
        old.extend_from_slice(&(-24i64).to_le_bytes());
        old.extend_from_slice(&0x4a_1000u64.to_le_bytes());
        let objects = parse_stack_objects(&old, 8, 16, None).unwrap();
        assert_eq!(objects[0].frame_offset, -24);
        assert_eq!(objects[0].type_va, Some(0x4a_1000));
        // A count past the block, or past the bound: rejected.
        assert!(parse_stack_objects(&3u64.to_le_bytes(), 8, 20, None).is_none());
        assert!(parse_stack_objects(&u64::MAX.to_le_bytes(), 8, 20, None).is_none());
    }

    #[test]
    fn pointer_maps_index_their_bitmaps() {
        // Go 1.8+: two maps of 10 bits, 2 bytes each.
        let block = [2, 0, 0, 0, 10, 0, 0, 0, 0b0000_0101, 0b10, 0xff, 0];
        let maps = PointerMaps::parse(&block, PointerMapFormat::Go18).unwrap();
        assert_eq!((maps.count, maps.bits, maps.words()), (2, 10, 10));
        assert_eq!(maps.map(1), Some(&[0xff, 0][..]));
        assert_eq!(maps.is_pointer(0, 0), Some(true));
        assert_eq!(maps.is_pointer(0, 1), Some(false));
        assert_eq!(maps.is_pointer(0, 9), Some(true));
        assert_eq!(maps.is_pointer(0, 10), None);
        assert!(maps.map(2).is_none());
        assert!(PointerMaps::parse(&block[..10], PointerMapFormat::Go18).is_none());
        // Go 1.5-1.7: the same maps padded to 4 bytes each.
        let mut padded = vec![2, 0, 0, 0, 10, 0, 0, 0];
        padded.extend_from_slice(&[0b0000_0101, 0b10, 0, 0, 0xff, 0, 0, 0]);
        let maps = PointerMaps::parse(&padded, PointerMapFormat::Go15).unwrap();
        assert_eq!(maps.map(1), Some(&[0xff, 0, 0, 0][..]));
        assert_eq!(maps.is_pointer(0, 9), Some(true));
        // Go 1.3-1.4: two bits per word; 0b10_01_00 is dead, scalar, pointer.
        let two_bit = [1, 0, 0, 0, 6, 0, 0, 0, 0b0010_0100, 0, 0, 0];
        let maps = PointerMaps::parse(&two_bit, PointerMapFormat::Go13).unwrap();
        assert_eq!(maps.words(), 3);
        assert_eq!(maps.word_kind(0, 0), Some(WordKind::Dead));
        assert_eq!(maps.word_kind(0, 1), Some(WordKind::Scalar));
        assert_eq!(maps.word_kind(0, 2), Some(WordKind::Pointer));
        // Go 1.2: one bitvector, no map count.
        let single = [4, 0, 0, 0, 0b0000_1100, 0, 0, 0];
        let maps = PointerMaps::parse(&single, PointerMapFormat::Go12).unwrap();
        assert_eq!((maps.count, maps.words()), (1, 2));
        assert_eq!(maps.word_kind(0, 1), Some(WordKind::MultiWord));
    }
}
