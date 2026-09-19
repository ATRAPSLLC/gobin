//! Go map type extra fields (`abi.MapType` / `abi.SwissMapType` /
//! `abi.OldMapType` / `runtime.maptype`).
//!
//! The map extra follows the embedded `abi.Type` in the binary layout for types
//! of kind `Map`. It is by a wide margin the least stable concrete-type extra:
//! its shape has changed **five** times across the releases gobin parses (six
//! layouts in all), and
//! the meaning of its flag bits changed once more on top of that. Reading one
//! layout with another's field list silently shifts every field past the
//! pointer block and - because the extra's size feeds
//! [`crate::structures::descriptor::descriptor_size`] - mislocates the trailing
//! `UncommonType`, which then yields a garbage method count.
//!
//! ## Layouts
//!
//! Every layout is a run of pointer-sized fields followed by an 8-byte tail
//! (padded to pointer alignment on 64-bit), so the size is
//! `pointers * ptrSize + 8` throughout.
//!
//! | Go        | [`MapLayout`]         | Pointer fields                                                                 | Tail                                                                                  | ps=8 | ps=4 |
//! |-----------|-----------------------|--------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|------|------|
//! | ≤ 1.10    | `HmapWithHmapType`    | `Key`, `Elem`, `Bucket`, `Hmap`                                                  | `keysize u8`, `indirectkey bool`, `valuesize u8`, `indirectvalue bool`, `bucketsize u16`, `reflexivekey bool`, `needkeyupdate bool` | 40 | 24 |
//! | 1.11      | `HmapBools`           | `Key`, `Elem`, `Bucket`                                                          | same bool tail                                                                        | 32   | 20   |
//! | 1.12-1.13 | `HmapFlags`           | `Key`, `Elem`, `Bucket`                                                          | `keysize u8`, `elemsize u8`, `bucketsize u16`, `flags u32`                            | 32   | 20   |
//! | 1.14-1.23 | `HmapHasher`          | `Key`, `Elem`, `Bucket`, `Hasher`                                                | same as above                                                                         | 40   | 24   |
//! | 1.24-1.26 | `Swiss`               | + `GroupSize`, `SlotSize`, `ElemOff` (7 total)                                    | `flags u32`                                                                           | 64   | 32   |
//! | 1.27+     | `SwissSplitGroup`     | + `GroupSize`, `KeysOff`, `KeyStride`, `ElemsOff`, `ElemStride`, `ElemOff` (10)   | `flags u32`                                                                           | 88   | 44   |
//!
//! What each change did: Go 1.11 dropped the `hmap` type pointer; 1.12 folded
//! the four tail booleans into a `flags` word; 1.14 added the `hasher` function
//! pointer; 1.24 replaced bucket-based `hmap` with Swiss tables; 1.27 split the
//! single `SlotSize`/`ElemOff` pair into explicit key/elem offsets and strides
//! so one descriptor can describe both the interleaved (`KVKVKV…`) and the
//! split (`KKKVVV…`, `GOEXPERIMENT=mapsplitgroup`) group layouts.
//!
//! ## Flag bits
//!
//! The `flags` word is **not** comparable across the hmap/Swiss boundary - Go
//! renumbered the bits when it introduced Swiss maps:
//!
//! | Property        | hmap (1.12-1.23) | Swiss (1.24+) |
//! |-----------------|------------------|---------------|
//! | indirect key    | `1 << 0`         | `1 << 2`      |
//! | indirect elem   | `1 << 1`         | `1 << 3`      |
//! | reflexive key   | `1 << 2`         | - (dropped)   |
//! | need key update | `1 << 3`         | `1 << 0`      |
//! | hash might panic| `1 << 4`         | `1 << 1`      |
//!
//! Read them through [`MapTypeExtra::flags`], a [`MapFlags`] that normalizes
//! all three encodings - including the pre-1.12 booleans - into `Option<bool>`
//! per property. [`MapTypeExtra::raw_flags`] keeps the undecoded word for
//! callers that want it.
//!
//! Sources: `src/runtime/type.go` (Go 1.7-1.20), `src/internal/abi/type.go`
//! (Go 1.21-1.23), `src/internal/abi/map_noswiss.go` + `map_swiss.go` (Go
//! 1.24-1.25), `src/internal/abi/map.go` (Go 1.26, 1.27). Sizes cross-checked
//! against `abi.RTypeSize` in `src/internal/abi/compiletype.go` (Go 1.27),
//! which gives `Map => CommonSize + 10*ptrSize + 4 (+4 padding when
//! ptrSize == 8)`.

use crate::structures::util::{read_u16, read_u32, read_uintptr};

/// Which `abi` map-descriptor layout a binary uses.
///
/// Determined from the Go version where one is available, and otherwise from
/// the structural evidence the rest of the binary carries - see
/// [`MapLayout::infer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapLayout {
    /// Go ≤ 1.10: `Key`, `Elem`, `Bucket`, `Hmap` plus the bool-flag tail.
    HmapWithHmapType,
    /// Go 1.11: the `Hmap` type pointer is gone; bool-flag tail retained.
    HmapBools,
    /// Go 1.12-1.13: the tail booleans became a `flags uint32`.
    HmapFlags,
    /// Go 1.14-1.23: `Hasher` reinstated as the fourth pointer field.
    HmapHasher,
    /// Go 1.24-1.26: Swiss tables with a single `SlotSize` / `ElemOff` pair.
    Swiss,
    /// Go 1.27+: Swiss tables carrying explicit key/elem offsets and strides.
    SwissSplitGroup,
    /// Go 1.20-1.25 with no recoverable version string - the moduledata layout
    /// narrows the window but cannot separate `HmapHasher` (1.20-1.23) from
    /// `Swiss` (1.24-1.25). Each descriptor is then classified from its own
    /// bytes by [`MapLayout::resolve_for`].
    Probe,
}

impl MapLayout {
    /// Pick the layout from the Go minor version. Exact.
    pub fn for_go_minor(minor: u32) -> Self {
        match minor {
            0..=10 => Self::HmapWithHmapType,
            11 => Self::HmapBools,
            12 | 13 => Self::HmapFlags,
            14..=23 => Self::HmapHasher,
            24..=26 => Self::Swiss,
            _ => Self::SwissSplitGroup,
        }
    }

    /// Pick the layout from whatever evidence the binary offers.
    ///
    /// The Go version string settles it outright. Without one, the moduledata
    /// layout still dates the binary exactly at two boundaries - `V5` is Go
    /// 1.27+ and `V4` is Go 1.26 - and the pclntab magic gives a floor: Swiss
    /// maps arrived in Go 1.24 and therefore imply the Go 1.20 magic, while
    /// anything below that magic is at most Go 1.19 and so `HmapHasher`
    /// (the layout in force from 1.14; older magics narrow it no further, and
    /// [`Self::resolve_for`] is not consulted because the ambiguity there is
    /// between same-size layouts that no local evidence separates).
    ///
    /// The one window that stays open is a `V3` moduledata with the Go 1.20
    /// magic (Go 1.20-1.25), which straddles the 1.24 Swiss switch; that
    /// resolves per descriptor via [`Self::Probe`].
    ///
    /// `md_is_v5` / `md_is_v4` come from
    /// [`crate::structures::moduledata::ModuledataVersion`]; `go120_magic` is
    /// true for [`crate::structures::PclntabVersion::Go120`].
    pub fn infer(go_minor: Option<u32>, go120_magic: bool, md_is_v5: bool, md_is_v4: bool) -> Self {
        if let Some(m) = go_minor {
            return Self::for_go_minor(m);
        }
        if md_is_v5 {
            return Self::SwissSplitGroup;
        }
        if md_is_v4 {
            return Self::Swiss;
        }
        if !go120_magic {
            return Self::HmapHasher;
        }
        Self::Probe
    }

    /// Resolve [`Self::Probe`] against one descriptor's extra bytes; every
    /// other variant returns itself.
    ///
    /// The two candidates in the ambiguous window - `HmapHasher` (Go
    /// 1.20-1.23) and `Swiss` (Go 1.24-1.25) - both start with four
    /// pointer-sized fields, so they diverge at `extra + 4*ptrSize`, and the
    /// two readings of that word are disjoint in range:
    ///
    /// - **Swiss** reads `GroupSize uintptr` = `8 + 8*SlotSize`, and `SlotSize`
    ///   is at most 256 bytes because Go stores keys and elements larger than
    ///   128 bytes indirectly (as pointers). So `GroupSize <= 2056` and every
    ///   bit above 15 is zero.
    /// - **HmapHasher** packs `KeySize u8`, `ValueSize u8`, `BucketSize u16`,
    ///   `Flags u32` into the same word, and `BucketSize` - which lands in bits
    ///   16..31 - is `8 + 8*(KeySize+ValueSize) + ptrSize`, never zero.
    ///
    /// A non-zero value above bit 15 therefore means `HmapHasher`; anything
    /// else is `Swiss`. On 32-bit the same reasoning applies to the `u32` at
    /// that offset, whose bits 16..31 hold `BucketSize` in the hmap reading.
    pub fn resolve_for(self, extra: &[u8], ps: u8) -> Self {
        if self != Self::Probe {
            return self;
        }
        let Some(off) = (ps as usize).checked_mul(4) else {
            return Self::Swiss;
        };
        let Some(word) = read_uintptr(extra, off, ps) else {
            return Self::Swiss;
        };
        if word >> 16 != 0 {
            Self::HmapHasher
        } else {
            Self::Swiss
        }
    }

    /// Whether the layout is one of the bucket-based `hmap` shapes (Go ≤ 1.23).
    pub fn is_hmap(self) -> bool {
        matches!(
            self,
            Self::HmapWithHmapType | Self::HmapBools | Self::HmapFlags | Self::HmapHasher
        )
    }

    /// Number of pointer-sized fields the layout carries before its 8-byte
    /// tail.
    fn pointer_field_count(self) -> usize {
        match self {
            // Key, Elem, Bucket, Hmap.
            Self::HmapWithHmapType => 4,
            // Key, Elem, Bucket.
            Self::HmapBools | Self::HmapFlags => 3,
            // Key, Elem, Bucket, Hasher.
            Self::HmapHasher => 4,
            // …plus GroupSize, SlotSize, ElemOff.
            Self::Swiss => 7,
            // …plus KeysOff, KeyStride, ElemsOff, ElemStride.
            Self::SwissSplitGroup => 10,
            // Never reached: `Probe` is resolved before sizing.
            Self::Probe => 7,
        }
    }
}

/// Semantic map properties, decoded from whichever flag encoding the
/// descriptor's layout uses.
///
/// Each is `None` when the layout does not record that property (Swiss maps
/// dropped `reflexive_key`; the pre-1.12 bool tail has no `hash_might_panic`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MapFlags {
    /// Keys are stored indirectly, as pointers.
    pub indirect_key: Option<bool>,
    /// Elements are stored indirectly, as pointers.
    pub indirect_elem: Option<bool>,
    /// `k == k` holds for every key (no NaN-like keys).
    pub reflexive_key: Option<bool>,
    /// An overwrite must update the stored key, not just the element.
    pub need_key_update: Option<bool>,
    /// The hash function can panic (interface-keyed maps).
    pub hash_might_panic: Option<bool>,
}

/// Parsed extra fields for a map type descriptor.
///
/// Fields absent from the descriptor's [`MapLayout`] are `None` so callers can
/// tell "this Go version does not record it" from a genuine zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapTypeExtra {
    /// Which layout the descriptor was parsed with.
    pub layout: MapLayout,
    /// Virtual address of the key type descriptor.
    pub key: u64,
    /// Virtual address of the element type descriptor.
    pub elem: u64,
    /// Virtual address of the bucket (hmap) or slot-group (Swiss) type
    /// descriptor.
    pub group: u64,
    /// Virtual address of the `hmap` type descriptor
    /// ([`MapLayout::HmapWithHmapType`] only - Go 1.11 removed the field).
    pub hmap: Option<u64>,
    /// Virtual address of the key-hashing function. `None` for Go 1.11-1.13,
    /// which had no `hasher` field.
    pub hasher: Option<u64>,
    /// Size of a slot group in bytes (`GroupSize`). Swiss layouts only.
    pub group_size: Option<u64>,
    /// Size of one key/elem slot (`SlotSize`). [`MapLayout::Swiss`] only -
    /// Go 1.27 replaced it with the explicit stride fields below.
    pub slot_size: Option<u64>,
    /// Offset of the keys array within a group (`KeysOff`).
    /// [`MapLayout::SwissSplitGroup`] only.
    pub keys_off: Option<u64>,
    /// Stride between consecutive keys (`KeyStride`).
    /// [`MapLayout::SwissSplitGroup`] only.
    pub key_stride: Option<u64>,
    /// Offset of the elements array within a group (`ElemsOff`).
    /// [`MapLayout::SwissSplitGroup`] only.
    pub elems_off: Option<u64>,
    /// Stride between consecutive elements (`ElemStride`).
    /// [`MapLayout::SwissSplitGroup`] only.
    pub elem_stride: Option<u64>,
    /// Offset from a key to its element within a slot (`ElemOff`). Present in
    /// both Swiss layouts.
    pub elem_off: Option<u64>,
    /// Size of a key slot in bytes (`KeySize`). hmap layouts only.
    pub key_size: Option<u8>,
    /// Size of a value slot in bytes (`ValueSize` / `elemsize`). hmap layouts
    /// only.
    pub value_size: Option<u8>,
    /// Size of a bucket in bytes (`BucketSize`). hmap layouts only.
    pub bucket_size: Option<u16>,
    /// Raw `flags` word. `None` for the pre-1.12 layouts, which encoded the
    /// same properties as separate booleans. **Bit meanings differ between the
    /// hmap and Swiss eras** - prefer [`Self::flags`], which normalizes them.
    pub raw_flags: Option<u32>,
    /// Semantic flags, normalized across all three encodings.
    pub flags: MapFlags,
}

impl MapTypeExtra {
    /// Binary size of the extra for the given pointer size and layout.
    ///
    /// Every layout is `pointer_fields * ptrSize` followed by an 8-byte tail -
    /// either four small integers plus four booleans, or `u8 + u8 + u16 + u32`,
    /// or (Swiss) a `u32` padded out to pointer alignment. That comes to
    /// `pointers * ps + 8` on 64-bit and `pointers * ps + 8` on 32-bit for the
    /// hmap layouts, and `pointers * ps + 4 (+4)` for the Swiss ones.
    pub fn size(ps: u8, layout: MapLayout) -> usize {
        let p = ps as usize;
        let pointers = p.saturating_mul(layout.pointer_field_count());
        if layout.is_hmap() {
            // u8 + u8 + u16 + (u32 | 4 bools) = 8 bytes, pointer-aligned on
            // both 32- and 64-bit.
            return pointers.saturating_add(8);
        }
        let base = pointers.saturating_add(4);
        if ps == 8 {
            base.saturating_add(4) // alignment padding for the trailing u32
        } else {
            base
        }
    }

    /// Parse from `data`, which must start at the map type's extra fields
    /// (i.e. just past the embedded `abi.Type`).
    ///
    /// A [`MapLayout::Probe`] layout is resolved against these bytes first, so
    /// the returned [`Self::layout`] is always a concrete variant.
    ///
    /// Returns `None` if the buffer is too small for the resolved layout.
    pub fn parse(data: &[u8], ps: u8, layout: MapLayout) -> Option<Self> {
        let layout = layout.resolve_for(data, ps);
        let p = ps as usize;
        if data.len() < Self::size(ps, layout) {
            return None;
        }

        let mut off: usize = 0;
        // Read the next pointer-sized field and advance.
        let next = |off: &mut usize| -> Option<u64> {
            let v = read_uintptr(data, *off, ps)?;
            *off = off.checked_add(p)?;
            Some(v)
        };

        let key = next(&mut off)?;
        let elem = next(&mut off)?;
        let group = next(&mut off)?;

        let mut out = Self {
            layout,
            key,
            elem,
            group,
            hmap: None,
            hasher: None,
            group_size: None,
            slot_size: None,
            keys_off: None,
            key_stride: None,
            elems_off: None,
            elem_stride: None,
            elem_off: None,
            key_size: None,
            value_size: None,
            bucket_size: None,
            raw_flags: None,
            flags: MapFlags::default(),
        };

        match layout {
            MapLayout::HmapWithHmapType => {
                out.hmap = Some(next(&mut off)?);
                out.read_hmap_sizes(data, off)?;
                out.read_bool_tail(data, off)?;
            }
            MapLayout::HmapBools => {
                out.read_hmap_sizes(data, off)?;
                out.read_bool_tail(data, off)?;
            }
            MapLayout::HmapFlags => {
                out.read_hmap_sizes(data, off)?;
                out.read_hmap_flags(data, off.checked_add(4)?)?;
            }
            MapLayout::HmapHasher => {
                out.hasher = Some(next(&mut off)?);
                out.read_hmap_sizes(data, off)?;
                out.read_hmap_flags(data, off.checked_add(4)?)?;
            }
            MapLayout::Swiss => {
                out.hasher = Some(next(&mut off)?);
                out.group_size = Some(next(&mut off)?);
                out.slot_size = Some(next(&mut off)?);
                out.elem_off = Some(next(&mut off)?);
                out.read_swiss_flags(data, off)?;
            }
            // `Probe` cannot survive `resolve_for`; treat it as the Go 1.27
            // layout so the match stays total without an unreachable arm.
            MapLayout::SwissSplitGroup | MapLayout::Probe => {
                out.hasher = Some(next(&mut off)?);
                out.group_size = Some(next(&mut off)?);
                out.keys_off = Some(next(&mut off)?);
                out.key_stride = Some(next(&mut off)?);
                out.elems_off = Some(next(&mut off)?);
                out.elem_stride = Some(next(&mut off)?);
                out.elem_off = Some(next(&mut off)?);
                out.read_swiss_flags(data, off)?;
            }
        }

        Some(out)
    }

    /// Read the `keysize u8`, `valuesize u8`, `bucketsize u16` block shared by
    /// every hmap layout. `off` is the start of the 8-byte tail.
    ///
    /// The pre-1.12 layouts interleave booleans between the sizes
    /// (`keysize, indirectkey, valuesize, indirectvalue, bucketsize`), so the
    /// sizes sit at `+0` / `+2` there and at `+0` / `+1` from Go 1.12; the
    /// bucket size is at `+4` and `+2` respectively.
    fn read_hmap_sizes(&mut self, data: &[u8], off: usize) -> Option<()> {
        let bools = matches!(
            self.layout,
            MapLayout::HmapWithHmapType | MapLayout::HmapBools
        );
        let (value_at, bucket_at) = if bools {
            (2usize, 4usize)
        } else {
            (1usize, 2usize)
        };
        self.key_size = data.get(off).copied();
        self.value_size = data.get(off.checked_add(value_at)?).copied();
        self.bucket_size = read_u16(data, off.checked_add(bucket_at)?);
        Some(())
    }

    /// Decode the Go ≤ 1.11 boolean tail into [`MapFlags`]. `off` is the start
    /// of the 8-byte tail: `keysize, indirectkey, valuesize, indirectvalue,
    /// bucketsize(2), reflexivekey, needkeyupdate`.
    fn read_bool_tail(&mut self, data: &[u8], off: usize) -> Option<()> {
        let at = |i: usize| -> Option<bool> {
            off.checked_add(i)
                .and_then(|o| data.get(o))
                .map(|&b| b != 0)
        };
        self.flags = MapFlags {
            indirect_key: at(1),
            indirect_elem: at(3),
            reflexive_key: at(6),
            need_key_update: at(7),
            // Introduced with the flags word in Go 1.12.
            hash_might_panic: None,
        };
        Some(())
    }

    /// Decode the Go 1.12-1.23 `flags uint32` (`runtime/map.go`:
    /// `indirectkey 1`, `indirectvalue 2`, `reflexivekey 4`, `needkeyupdate 8`,
    /// `hashMightPanic 16`).
    fn read_hmap_flags(&mut self, data: &[u8], off: usize) -> Option<()> {
        let f = read_u32(data, off)?;
        self.raw_flags = Some(f);
        self.flags = MapFlags {
            indirect_key: Some(f & 1 != 0),
            indirect_elem: Some(f & 2 != 0),
            reflexive_key: Some(f & 4 != 0),
            need_key_update: Some(f & 8 != 0),
            hash_might_panic: Some(f & 16 != 0),
        };
        Some(())
    }

    /// Decode the Go 1.24+ `Flags uint32` (`internal/abi/map.go`:
    /// `MapNeedKeyUpdate 1`, `MapHashMightPanic 2`, `MapIndirectKey 4`,
    /// `MapIndirectElem 8`). Swiss maps dropped `reflexivekey`.
    fn read_swiss_flags(&mut self, data: &[u8], off: usize) -> Option<()> {
        let f = read_u32(data, off)?;
        self.raw_flags = Some(f);
        self.flags = MapFlags {
            indirect_key: Some(f & 4 != 0),
            indirect_elem: Some(f & 8 != 0),
            reflexive_key: None,
            need_key_update: Some(f & 1 != 0),
            hash_might_panic: Some(f & 2 != 0),
        };
        Some(())
    }

    /// Byte stride between consecutive keys in a bucket / group, however the
    /// descriptor's layout happens to record it.
    ///
    /// `SwissSplitGroup` states it directly as `KeyStride`; `Swiss` uses the
    /// key/elem `SlotSize` as the stride for both; the hmap layouts pack keys
    /// of `KeySize` contiguously in the bucket. `None` when the descriptor did
    /// not carry the value.
    pub fn key_stride(&self) -> Option<u64> {
        match self.layout {
            l if l.is_hmap() => self.key_size.map(u64::from),
            MapLayout::Swiss => self.slot_size,
            _ => self.key_stride,
        }
    }

    /// Byte stride between consecutive elements, however the descriptor's
    /// layout records it. See [`Self::key_stride`].
    pub fn elem_stride(&self) -> Option<u64> {
        match self.layout {
            l if l.is_hmap() => self.value_size.map(u64::from),
            MapLayout::Swiss => self.slot_size,
            _ => self.elem_stride,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_upstream() {
        // 64-bit: CommonSize is added by the caller; these are the extras only.
        assert_eq!(MapTypeExtra::size(8, MapLayout::HmapWithHmapType), 40);
        assert_eq!(MapTypeExtra::size(8, MapLayout::HmapBools), 32);
        assert_eq!(MapTypeExtra::size(8, MapLayout::HmapFlags), 32);
        assert_eq!(MapTypeExtra::size(8, MapLayout::HmapHasher), 40);
        assert_eq!(MapTypeExtra::size(8, MapLayout::Swiss), 64);
        assert_eq!(MapTypeExtra::size(8, MapLayout::SwissSplitGroup), 88);
        // 32-bit: the trailing u32 needs no padding.
        assert_eq!(MapTypeExtra::size(4, MapLayout::HmapWithHmapType), 24);
        assert_eq!(MapTypeExtra::size(4, MapLayout::HmapBools), 20);
        assert_eq!(MapTypeExtra::size(4, MapLayout::HmapFlags), 20);
        assert_eq!(MapTypeExtra::size(4, MapLayout::HmapHasher), 24);
        assert_eq!(MapTypeExtra::size(4, MapLayout::Swiss), 32);
        assert_eq!(MapTypeExtra::size(4, MapLayout::SwissSplitGroup), 44);
    }

    #[test]
    fn for_go_minor_covers_every_boundary() {
        use MapLayout::*;
        let cases = [
            (7, HmapWithHmapType),
            (10, HmapWithHmapType),
            (11, HmapBools),
            (12, HmapFlags),
            (13, HmapFlags),
            (14, HmapHasher),
            (23, HmapHasher),
            (24, Swiss),
            (26, Swiss),
            (27, SwissSplitGroup),
            (28, SwissSplitGroup),
        ];
        for (minor, want) in cases {
            assert_eq!(MapLayout::for_go_minor(minor), want, "go1.{minor}");
        }
    }

    #[test]
    fn infer_without_a_version_uses_structural_evidence() {
        // V5 and V4 date the binary exactly.
        assert_eq!(
            MapLayout::infer(None, true, true, false),
            MapLayout::SwissSplitGroup
        );
        assert_eq!(MapLayout::infer(None, true, false, true), MapLayout::Swiss);
        // Pre-Go120 magic rules out Swiss maps entirely.
        assert_eq!(
            MapLayout::infer(None, false, false, false),
            MapLayout::HmapHasher
        );
        // Go 1.20-1.25 stays ambiguous and is resolved per descriptor.
        assert_eq!(MapLayout::infer(None, true, false, false), MapLayout::Probe);
        // A version string always wins.
        assert_eq!(
            MapLayout::infer(Some(11), true, true, true),
            MapLayout::HmapBools
        );
    }

    /// `map[string]float64` as Go 1.26 emits it, taken byte-for-byte from
    /// `tests/samples/types_go126_linux_amd64` at VA `0x4b06a0 + 0x30`.
    fn go126_map_string_float64() -> Vec<u8> {
        let mut d = Vec::new();
        for w in [
            0x4a9ae0u64, // Key   -> string
            0x4a9ea0,    // Elem  -> float64
            0x4b2320,    // Group
            0x4cf168,    // Hasher
            0xc8,        // GroupSize = 200
            0x18,        // SlotSize  = 24 (16-byte string + 8-byte float64)
            0x10,        // ElemOff   = 16
            0x1,         // Flags = MapNeedKeyUpdate, then 4 bytes of padding
        ] {
            d.extend_from_slice(&w.to_le_bytes());
        }
        d
    }

    #[test]
    fn swiss_layout_reads_go126_fields() {
        let d = go126_map_string_float64();
        let m = MapTypeExtra::parse(&d, 8, MapLayout::Swiss).unwrap();
        assert_eq!(m.layout, MapLayout::Swiss);
        assert_eq!(m.key, 0x4a9ae0);
        assert_eq!(m.elem, 0x4a9ea0);
        assert_eq!(m.group, 0x4b2320);
        assert_eq!(m.hasher, Some(0x4cf168));
        assert_eq!(m.group_size, Some(0xc8));
        assert_eq!(m.slot_size, Some(0x18));
        assert_eq!(m.elem_off, Some(0x10));
        assert_eq!(m.raw_flags, Some(1));
        assert_eq!(m.flags.need_key_update, Some(true));
        assert_eq!(m.flags.indirect_key, Some(false));
        assert_eq!(m.flags.reflexive_key, None, "Swiss maps dropped it");
        // Go 1.27-only fields must read as absent, not as zero.
        assert!(m.keys_off.is_none());
        assert!(m.key_stride.is_none());
        assert!(m.elems_off.is_none());
        assert!(m.elem_stride.is_none());
    }

    #[test]
    fn go126_descriptor_is_not_read_with_the_go127_layout() {
        // Regression guard for the bug this layout gating fixes: the Go 1.27
        // extra is 88 bytes, so applied to a 64-byte Go 1.26 descriptor it
        // over-reads into whatever follows.
        let d = go126_map_string_float64();
        assert_eq!(d.len(), 64);
        assert!(
            MapTypeExtra::parse(&d, 8, MapLayout::SwissSplitGroup).is_none(),
            "the 1.27 layout must not fit a 1.26 descriptor"
        );
    }

    #[test]
    fn probe_picks_swiss_for_a_go126_descriptor() {
        let d = go126_map_string_float64();
        assert_eq!(MapLayout::Probe.resolve_for(&d, 8), MapLayout::Swiss);
        let m = MapTypeExtra::parse(&d, 8, MapLayout::Probe).unwrap();
        assert_eq!(m.layout, MapLayout::Swiss);
        assert_eq!(m.group_size, Some(0xc8));
    }

    /// Go 1.14-1.23 `map[string]float64`: KeySize 16, ValueSize 8,
    /// BucketSize `8 + 8*24 + 8 = 208`, Flags 4 (`reflexivekey`).
    fn hmap_hasher_map_string_float64() -> Vec<u8> {
        let mut d = Vec::new();
        for w in [0x4a9ae0u64, 0x4a9ea0, 0x4b2320, 0x4cf168] {
            d.extend_from_slice(&w.to_le_bytes());
        }
        d.push(16); // KeySize
        d.push(8); // ValueSize
        d.extend_from_slice(&208u16.to_le_bytes()); // BucketSize
        d.extend_from_slice(&4u32.to_le_bytes()); // Flags = reflexivekey
        d
    }

    #[test]
    fn probe_picks_hmap_for_a_bucket_descriptor() {
        // BucketSize occupies bits 16..31 of the probe word, so it exceeds
        // 0xFFFF and reads as hmap rather than as a Swiss GroupSize.
        let d = hmap_hasher_map_string_float64();
        assert_eq!(MapLayout::Probe.resolve_for(&d, 8), MapLayout::HmapHasher);
        let m = MapTypeExtra::parse(&d, 8, MapLayout::Probe).unwrap();
        assert_eq!(m.layout, MapLayout::HmapHasher);
        assert_eq!(m.hasher, Some(0x4cf168));
        assert_eq!(m.key_size, Some(16));
        assert_eq!(m.value_size, Some(8));
        assert_eq!(m.bucket_size, Some(208));
        assert_eq!(m.raw_flags, Some(4));
        assert_eq!(m.flags.reflexive_key, Some(true));
        assert_eq!(m.flags.indirect_key, Some(false));
        assert_eq!(m.key_stride(), Some(16));
        assert_eq!(m.elem_stride(), Some(8));
        // Swiss-only fields must read as absent.
        assert!(m.group_size.is_none());
        assert!(m.slot_size.is_none());
    }

    #[test]
    fn pre_112_bool_tail_decodes_without_a_flags_word() {
        // Go ≤1.10 `map[string]float64`: Key, Elem, Bucket, Hmap, then
        // keysize 16, indirectkey 0, valuesize 8, indirectvalue 0,
        // bucketsize 208, reflexivekey 1, needkeyupdate 0.
        let mut d = Vec::new();
        for w in [0x4a9ae0u64, 0x4a9ea0, 0x4b2320, 0x4b3000] {
            d.extend_from_slice(&w.to_le_bytes());
        }
        d.extend_from_slice(&[16, 0, 8, 0]);
        d.extend_from_slice(&208u16.to_le_bytes());
        d.extend_from_slice(&[1, 0]);

        let m = MapTypeExtra::parse(&d, 8, MapLayout::HmapWithHmapType).unwrap();
        assert_eq!(m.hmap, Some(0x4b3000));
        assert_eq!(m.hasher, None, "no hasher field before Go 1.14");
        assert_eq!(m.key_size, Some(16));
        assert_eq!(m.value_size, Some(8));
        assert_eq!(m.bucket_size, Some(208));
        assert_eq!(
            m.raw_flags, None,
            "the bool tail has no flags word to report"
        );
        assert_eq!(m.flags.indirect_key, Some(false));
        assert_eq!(m.flags.indirect_elem, Some(false));
        assert_eq!(m.flags.reflexive_key, Some(true));
        assert_eq!(m.flags.need_key_update, Some(false));
        assert_eq!(m.flags.hash_might_panic, None);
    }

    #[test]
    fn go111_drops_the_hmap_pointer() {
        let mut d = Vec::new();
        for w in [0x4a9ae0u64, 0x4a9ea0, 0x4b2320] {
            d.extend_from_slice(&w.to_le_bytes());
        }
        d.extend_from_slice(&[16, 1, 8, 0]);
        d.extend_from_slice(&208u16.to_le_bytes());
        d.extend_from_slice(&[0, 1]);

        let m = MapTypeExtra::parse(&d, 8, MapLayout::HmapBools).unwrap();
        assert_eq!(m.group, 0x4b2320);
        assert_eq!(m.hmap, None);
        assert_eq!(m.key_size, Some(16));
        assert_eq!(m.value_size, Some(8));
        assert_eq!(m.bucket_size, Some(208));
        assert_eq!(m.flags.indirect_key, Some(true));
        assert_eq!(m.flags.need_key_update, Some(true));
    }

    #[test]
    fn go112_flags_word_replaces_the_bools() {
        let mut d = Vec::new();
        for w in [0x4a9ae0u64, 0x4a9ea0, 0x4b2320] {
            d.extend_from_slice(&w.to_le_bytes());
        }
        d.push(16);
        d.push(8);
        d.extend_from_slice(&208u16.to_le_bytes());
        d.extend_from_slice(&(1u32 | 16).to_le_bytes()); // indirectkey|hashMightPanic

        let m = MapTypeExtra::parse(&d, 8, MapLayout::HmapFlags).unwrap();
        assert_eq!(m.hasher, None, "hasher arrives in Go 1.14");
        assert_eq!(m.key_size, Some(16));
        assert_eq!(m.bucket_size, Some(208));
        assert_eq!(m.flags.indirect_key, Some(true));
        assert_eq!(m.flags.hash_might_panic, Some(true));
        assert_eq!(m.flags.reflexive_key, Some(false));
    }

    #[test]
    fn split_group_layout_reads_every_stride() {
        let mut d = Vec::new();
        for w in [
            0x551000u64, // Key
            0x551100,    // Elem
            0x551200,    // Group
            0x551300,    // Hasher
            0xc8,        // GroupSize
            0x8,         // KeysOff
            0x18,        // KeyStride
            0x18,        // ElemsOff
            0x18,        // ElemStride
            0x10,        // ElemOff
            0xc,         // Flags = MapIndirectKey|MapIndirectElem
        ] {
            d.extend_from_slice(&w.to_le_bytes());
        }
        let m = MapTypeExtra::parse(&d, 8, MapLayout::SwissSplitGroup).unwrap();
        assert_eq!(m.keys_off, Some(0x8));
        assert_eq!(m.key_stride(), Some(0x18));
        assert_eq!(m.elem_stride(), Some(0x18));
        assert_eq!(m.elem_off, Some(0x10));
        assert_eq!(m.flags.indirect_key, Some(true));
        assert_eq!(m.flags.indirect_elem, Some(true));
        assert_eq!(m.flags.need_key_update, Some(false));
        assert!(m.slot_size.is_none());
    }

    #[test]
    fn too_short_returns_none() {
        let d = vec![0u8; 16];
        assert!(MapTypeExtra::parse(&d, 8, MapLayout::Swiss).is_none());
        assert!(MapTypeExtra::parse(&d, 8, MapLayout::HmapHasher).is_none());
        assert!(MapTypeExtra::parse(&d, 8, MapLayout::HmapWithHmapType).is_none());
    }
}
