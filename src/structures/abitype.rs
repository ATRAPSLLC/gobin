//! Go base type descriptor (`abi.Type`).
//!
//! Every Go type at runtime starts with an `abi.Type` struct, which is the
//! base type descriptor embedded in all concrete type descriptors (array,
//! chan, func, interface, map, pointer, slice, struct).
//!
//! Binary layout (64-bit, ps=8): 48 bytes = 4*ps + 16.
//! Binary layout (32-bit, ps=4): 32 bytes = 4*ps + 16.
//!
//! Fields in order:
//! - `Size_`       (uintptr)
//! - `PtrBytes`    (uintptr)
//! - `Hash`        (u32)
//! - `TFlag`       (u8)
//! - `Align_`      (u8)
//! - `FieldAlign_` (u8)
//! - `Kind_`       (u8)
//! - `Equal`       (uintptr, equality function pointer)
//! - `GCData`      (uintptr, GC pointer-mask bitmap - or a pointer to one; see
//!   [`TFLAG_GC_MASK_ON_DEMAND`])
//! - `Str`         (NameOff / i32)
//! - `PtrToThis`   (TypeOff / i32)
//!
//! Source: `src/internal/abi/type.go`. The struct itself has been stable since
//! Go 1.21; what changed in Go 1.27 is how `GCData` is populated - see
//! [`TFLAG_GC_MASK_ON_DEMAND`].

use crate::structures::util::{read_i32, read_u32, read_uintptr};

/// `TFlag` bit: type has an `UncommonType` following the type-specific extra fields.
pub const TFLAG_UNCOMMON: u8 = 0x01;

/// `TFlag` bit: the `Str` name has a leading `*` that should be stripped.
pub const TFLAG_EXTRA_STAR: u8 = 0x02;

/// `TFlag` bit: the type has a user-defined name (not a composite literal type).
pub const TFLAG_NAMED: u8 = 0x04;

/// `TFlag` bit: the type's `Equal` and hash functions may treat values as plain
/// memory (`TFlagRegularMemory`).
pub const TFLAG_REGULAR_MEMORY: u8 = 0x08;

/// `TFlag` bit: `GCData` is **not** a pointer mask but a `**byte` - a slot the
/// runtime fills in with a lazily-built mask on first use
/// (`runtime.getGCMaskOnDemand`).
///
/// The flag exists from Go 1.22, but its reach changed sharply in Go 1.27:
/// that release deleted type-level GC *programs* (the `type:.gcprog.*` symbols
/// became `type:.gcmask.*` under a new `runtime.gcmask.*` BSS carrier) and
/// dropped `abi.MaxPtrmaskBytes` from 2048 to 16. Below 1.27 almost no type
/// took the on-demand path; from 1.27 most non-trivial ones do. Check this bit
/// before treating [`AbiType::gcdata`] as the address of a bitmap.
pub const TFLAG_GC_MASK_ON_DEMAND: u8 = 0x10;

/// `TFlag` bit: a value of this type is stored directly in an interface word
/// rather than behind a pointer (`TFlagDirectIface`). Mirrors the legacy
/// `KindDirectIface` bit in `Kind_`, which `AbiType::kind` masks off.
pub const TFLAG_DIRECT_IFACE: u8 = 0x20;

/// Parsed `abi.Type` -- the base type descriptor found at the start of every
/// Go runtime type.
#[derive(Debug, Clone, Copy, Default)]
pub struct AbiType {
    /// Total size of the type in bytes.
    pub size_: u64,
    /// Number of bytes in the type that contain pointers.
    pub ptr_bytes: u64,
    /// Hash of the type, used for map key comparison.
    pub hash: u32,
    /// Type flags (`TFLAG_*` constants).
    pub tflag: u8,
    /// Alignment of a variable of this type.
    pub align_: u8,
    /// Alignment of a struct field of this type.
    pub field_align_: u8,
    /// Kind of the type (low 5 bits encode `abi.Kind`).
    pub kind_: u8,
    /// VA of the type's equality function (`Equal`), or `0` if none.
    pub equal: u64,
    /// VA of the type's GC pointer-mask bitmap (`GCData`), or `0` if none.
    ///
    /// When [`TFLAG_GC_MASK_ON_DEMAND`] is set this is instead the address of
    /// a `*byte` slot the runtime populates at run time, so statically it
    /// points at zeroed BSS rather than at a mask. Use
    /// [`AbiType::gc_mask_va`] to get the bitmap address only when one is
    /// actually present.
    pub gcdata: u64,
    /// Offset into the names table for this type's string representation.
    pub str_off: i32,
    /// Offset into the typelinks table for a pointer-to-this-type descriptor.
    pub ptr_to_this: i32,
}

impl AbiType {
    /// Binary size of an `abi.Type` for the given pointer size.
    ///
    /// Layout: 4 * ps + 16 bytes.
    pub fn size(ps: u8) -> usize {
        (ps as usize).saturating_mul(4).saturating_add(16)
    }

    /// Parse an `abi.Type` from `data`. Data must start at the type.
    ///
    /// Returns `None` if the buffer is too small or a read fails.
    pub fn parse(data: &[u8], ps: u8) -> Option<Self> {
        let p = ps as usize;
        let total = Self::size(ps);
        if data.len() < total {
            return None;
        }

        let mut off: usize = 0;

        let size_ = read_uintptr(data, off, ps)?;
        off = off.checked_add(p)?;

        let ptr_bytes = read_uintptr(data, off, ps)?;
        off = off.checked_add(p)?;

        let hash = read_u32(data, off)?;
        off = off.checked_add(4)?;

        let tflag = *data.get(off)?;
        let align_ = *data.get(off.checked_add(1)?)?;
        let field_align_ = *data.get(off.checked_add(2)?)?;
        let kind_ = *data.get(off.checked_add(3)?)?;
        off = off.checked_add(4)?;

        let equal = read_uintptr(data, off, ps)?;
        off = off.checked_add(p)?;
        let gcdata = read_uintptr(data, off, ps)?;
        off = off.checked_add(p)?;

        let str_off = read_i32(data, off)?;
        off = off.checked_add(4)?;

        let ptr_to_this = read_i32(data, off)?;

        Some(Self {
            size_,
            ptr_bytes,
            hash,
            tflag,
            align_,
            field_align_,
            kind_,
            equal,
            gcdata,
            str_off,
            ptr_to_this,
        })
    }

    /// The type kind, masked to the low 5 bits of `Kind_`.
    pub fn kind(&self) -> u8 {
        self.kind_ & 0x1f
    }

    /// Whether this type has an `UncommonType` appended after the extra fields.
    pub fn has_uncommon(&self) -> bool {
        self.tflag & TFLAG_UNCOMMON != 0
    }

    /// Whether the name in `Str` has an extra leading `*` to strip.
    pub fn has_extra_star(&self) -> bool {
        self.tflag & TFLAG_EXTRA_STAR != 0
    }

    /// Whether this type has a user-defined name.
    pub fn is_named(&self) -> bool {
        self.tflag & TFLAG_NAMED != 0
    }

    /// Whether `Equal`/hash may treat values of this type as plain memory.
    pub fn is_regular_memory(&self) -> bool {
        self.tflag & TFLAG_REGULAR_MEMORY != 0
    }

    /// Whether [`Self::gcdata`] addresses a runtime-populated `*byte` slot
    /// instead of a statically-emitted pointer mask. See
    /// [`TFLAG_GC_MASK_ON_DEMAND`].
    pub fn gc_mask_on_demand(&self) -> bool {
        self.tflag & TFLAG_GC_MASK_ON_DEMAND != 0
    }

    /// Whether a value of this type is stored directly in an interface word.
    ///
    /// Go carried this as `KindDirectIface` (bit 5 of `Kind_`) before moving it
    /// into `TFlag`, and still sets both, so either bit is accepted.
    pub fn is_direct_iface(&self) -> bool {
        self.tflag & TFLAG_DIRECT_IFACE != 0 || self.kind_ & 0x20 != 0
    }

    /// VA of this type's statically-emitted GC pointer mask, or `None` when
    /// the type has none or defers mask construction to run time.
    ///
    /// Prefer this over reading [`Self::gcdata`] directly: from Go 1.27 the
    /// on-demand path is the common case, and the raw field then addresses an
    /// empty BSS slot rather than a bitmap.
    pub fn gc_mask_va(&self) -> Option<u64> {
        if self.gcdata == 0 || self.gc_mask_on_demand() {
            None
        } else {
            Some(self.gcdata)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 48-byte (ps=8) AbiType buffer with known field values.
    fn make_abitype_64() -> Vec<u8> {
        let mut buf = vec![0u8; 48];
        // Size_ = 0x100 (8 bytes)
        buf[0..8].copy_from_slice(&0x100u64.to_le_bytes());
        // PtrBytes = 0x40 (8 bytes)
        buf[8..16].copy_from_slice(&0x40u64.to_le_bytes());
        // Hash = 0xDEADBEEF (4 bytes)
        buf[16..20].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        // TFlag = TFLAG_UNCOMMON | TFLAG_NAMED = 0x05
        buf[20] = 0x05;
        // Align_ = 8
        buf[21] = 8;
        // FieldAlign_ = 8
        buf[22] = 8;
        // Kind_ = 25 (struct) | 0x20 (indirect bit) = 0x39
        buf[23] = 0x39;
        // Equal (8 bytes) -- skip (zeros)
        // GCData (8 bytes) -- skip (zeros)
        // Str (i32) at offset 40
        buf[40..44].copy_from_slice(&42i32.to_le_bytes());
        // PtrToThis (i32) at offset 44
        buf[44..48].copy_from_slice(&(-1i32).to_le_bytes());
        buf
    }

    #[test]
    fn parse_64bit_buffer() {
        let buf = make_abitype_64();
        let t = AbiType::parse(&buf, 8).unwrap();
        assert_eq!(t.size_, 0x100);
        assert_eq!(t.ptr_bytes, 0x40);
        assert_eq!(t.hash, 0xDEADBEEF);
        assert_eq!(t.tflag, 0x05);
        assert_eq!(t.align_, 8);
        assert_eq!(t.field_align_, 8);
        assert_eq!(t.kind_, 0x39);
        assert_eq!(t.str_off, 42);
        assert_eq!(t.ptr_to_this, -1);
    }

    #[test]
    fn parse_32bit_buffer() {
        let mut buf = vec![0u8; 32];
        // Size_ = 0x20 (4 bytes)
        buf[0..4].copy_from_slice(&0x20u32.to_le_bytes());
        // PtrBytes = 0x08
        buf[4..8].copy_from_slice(&0x08u32.to_le_bytes());
        // Hash = 0xCAFEBABE
        buf[8..12].copy_from_slice(&0xCAFEBABEu32.to_le_bytes());
        // TFlag=0, Align_=4, FieldAlign_=4, Kind_=17 (array)
        buf[12] = 0x00;
        buf[13] = 4;
        buf[14] = 4;
        buf[15] = 17;
        // Equal (4 bytes) + GCData (4 bytes) -- skip
        // Str at offset 24
        buf[24..28].copy_from_slice(&100i32.to_le_bytes());
        // PtrToThis at offset 28
        buf[28..32].copy_from_slice(&200i32.to_le_bytes());

        let t = AbiType::parse(&buf, 4).unwrap();
        assert_eq!(t.size_, 0x20);
        assert_eq!(t.ptr_bytes, 0x08);
        assert_eq!(t.hash, 0xCAFEBABE);
        assert_eq!(t.kind_, 17);
        assert_eq!(t.str_off, 100);
        assert_eq!(t.ptr_to_this, 200);
    }

    #[test]
    fn kind_masks_low_5_bits() {
        let buf = make_abitype_64();
        let t = AbiType::parse(&buf, 8).unwrap();
        // kind_ = 0x39, low 5 bits = 0x19 = 25 (struct)
        assert_eq!(t.kind(), 25);
    }

    #[test]
    fn tflag_methods() {
        let buf = make_abitype_64();
        let t = AbiType::parse(&buf, 8).unwrap();
        // tflag = 0x05 = TFLAG_UNCOMMON | TFLAG_NAMED
        assert!(t.has_uncommon());
        assert!(!t.has_extra_star());
        assert!(t.is_named());
    }

    #[test]
    fn too_short_buffer_returns_none() {
        let buf = vec![0u8; 40]; // need 48 for ps=8
        assert!(AbiType::parse(&buf, 8).is_none());
    }
}
