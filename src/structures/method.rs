//! Go method descriptors (`abi.Method` and `abi.Imethod`).
//!
//! These structs describe methods attached to concrete types and interfaces.
//!
//! `abi.Method` (16 bytes) describes a method on a concrete type:
//! - `Name` (NameOff / i32) -- offset to method name
//! - `Mtyp` (TypeOff / i32) -- offset to method type descriptor
//! - `Ifn`  (TextOff / i32) -- offset to interface method implementation
//! - `Tfn`  (TextOff / i32) -- offset to direct method implementation
//!
//! `abi.Imethod` (8 bytes) describes a method required by an interface:
//! - `Name` (NameOff / i32) -- offset to method name
//! - `Typ`  (TypeOff / i32) -- offset to method type descriptor
//!
//! Source: `src/internal/abi/type.go:238-250`

use crate::util::read_i32;

/// Parsed `abi.Method` -- a method on a concrete (non-interface) type.
///
/// Each method is 16 bytes: four `i32` offsets.
#[derive(Debug, Clone, Copy, Default)]
pub struct GoMethod {
    /// Offset into the names table for this method's name.
    pub name: i32,
    /// Offset into the types table for this method's type.
    pub mtyp: i32,
    /// Text offset for the interface-call wrapper.
    pub ifn: i32,
    /// Text offset for the direct-call entry point.
    pub tfn: i32,
}

impl GoMethod {
    /// Binary size: always 16 bytes.
    pub const SIZE: usize = 16;

    /// Parse a `GoMethod` from `data`. Data must start at the method.
    ///
    /// Returns `None` if the buffer is too small.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        Some(Self {
            name: read_i32(data, 0)?,
            mtyp: read_i32(data, 4)?,
            ifn: read_i32(data, 8)?,
            tfn: read_i32(data, 12)?,
        })
    }
}

/// Parsed `abi.Imethod` -- a method required by an interface type.
///
/// Each imethod is 8 bytes: two `i32` offsets.
#[derive(Debug, Clone, Copy, Default)]
pub struct GoImethod {
    /// Offset into the names table for this method's name.
    pub name: i32,
    /// Offset into the types table for this method's type.
    pub typ: i32,
}

impl GoImethod {
    /// Binary size: always 8 bytes.
    pub const SIZE: usize = 8;

    /// Parse a `GoImethod` from `data`. Data must start at the imethod.
    ///
    /// Returns `None` if the buffer is too small.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        Some(Self {
            name: read_i32(data, 0)?,
            typ: read_i32(data, 4)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gomethod_valid() {
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&10i32.to_le_bytes());
        buf[4..8].copy_from_slice(&20i32.to_le_bytes());
        buf[8..12].copy_from_slice(&(-30i32).to_le_bytes());
        buf[12..16].copy_from_slice(&40i32.to_le_bytes());

        let m = GoMethod::parse(&buf).unwrap();
        assert_eq!(m.name, 10);
        assert_eq!(m.mtyp, 20);
        assert_eq!(m.ifn, -30);
        assert_eq!(m.tfn, 40);
    }

    #[test]
    fn parse_gomethod_too_short() {
        let buf = vec![0u8; 15];
        assert!(GoMethod::parse(&buf).is_none());
    }

    #[test]
    fn parse_goimethod_valid() {
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&100i32.to_le_bytes());
        buf[4..8].copy_from_slice(&(-200i32).to_le_bytes());

        let im = GoImethod::parse(&buf).unwrap();
        assert_eq!(im.name, 100);
        assert_eq!(im.typ, -200);
    }

    #[test]
    fn parse_goimethod_too_short() {
        let buf = vec![0u8; 7];
        assert!(GoImethod::parse(&buf).is_none());
    }
}
