//! Go element-pointer type extra fields, shared by Pointer and Slice types.
//!
//! Both `abi.PtrType` and `abi.SliceType` have the same extra layout:
//! a single `Elem` field pointing to the element type descriptor.
//!
//! Binary layout: 1 * pointer_size bytes.
//!
//! Fields:
//! - `Elem` (uintptr) -- pointer to the element `abi.Type`
//!
//! Source: `src/internal/abi/type.go:422-430` (PtrType), `src/internal/abi/type.go:432-435` (SliceType)

use crate::util::read_uintptr;

/// Parsed extra field for pointer (`*T`) and slice (`[]T`) type descriptors.
///
/// Both types embed only a single `Elem` pointer after the base `abi.Type`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElemTypeExtra {
    /// Virtual address of the element type descriptor.
    pub elem: u64,
}

impl ElemTypeExtra {
    /// Binary size: 1 * pointer_size.
    pub fn size(ps: u8) -> usize {
        ps as usize
    }

    /// Parse from `data`. Data must start at the elem type extra fields.
    ///
    /// Returns `None` if the buffer is too small.
    pub fn parse(data: &[u8], ps: u8) -> Option<Self> {
        if data.len() < Self::size(ps) {
            return None;
        }

        Some(Self {
            elem: read_uintptr(data, 0, ps)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_64bit() {
        let mut buf = vec![0u8; 8];
        buf[0..8].copy_from_slice(&0xDEADu64.to_le_bytes());

        let e = ElemTypeExtra::parse(&buf, 8).unwrap();
        assert_eq!(e.elem, 0xDEAD);
    }

    #[test]
    fn parse_32bit() {
        let mut buf = vec![0u8; 4];
        buf[0..4].copy_from_slice(&0xBEEFu32.to_le_bytes());

        let e = ElemTypeExtra::parse(&buf, 4).unwrap();
        assert_eq!(e.elem, 0xBEEF);
    }

    #[test]
    fn too_short_returns_none() {
        let buf = vec![0u8; 6];
        assert!(ElemTypeExtra::parse(&buf, 8).is_none());
    }

    #[test]
    fn parse_different_value() {
        let mut buf = vec![0u8; 8];
        buf[0..8].copy_from_slice(&0xCAFEu64.to_le_bytes());

        let e = ElemTypeExtra::parse(&buf, 8).unwrap();
        assert_eq!(e.elem, 0xCAFE);
    }

    #[test]
    fn size_calculations() {
        assert_eq!(ElemTypeExtra::size(4), 4);
        assert_eq!(ElemTypeExtra::size(8), 8);
    }
}
