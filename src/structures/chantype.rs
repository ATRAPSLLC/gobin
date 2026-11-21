//! Go channel type extra fields (`abi.ChanType`).
//!
//! The `ChanType` follows the embedded `abi.Type` in the binary layout
//! for types of kind `Chan`. It carries a pointer to the element type
//! and the channel direction.
//!
//! Binary layout: 2 * pointer_size bytes.
//!
//! Fields:
//! - `Elem` (uintptr) -- pointer to the element `abi.Type`
//! - `Dir`  (uintptr) -- channel direction (1=recv, 2=send, 3=both)
//!
//! Source: `src/internal/abi/type.go:347-356`

use crate::util::read_uintptr;

/// Parsed extra fields for a channel type descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChanTypeExtra {
    /// Virtual address of the element type descriptor.
    pub elem: u64,
    /// Channel direction: 1 = receive only, 2 = send only, 3 = bidirectional.
    pub dir: u64,
}

impl ChanTypeExtra {
    /// Binary size: 2 * pointer_size.
    pub fn size(ps: u8) -> usize {
        (ps as usize).saturating_mul(2)
    }

    /// Parse from `data`. Data must start at the chan type extra fields.
    ///
    /// Returns `None` if the buffer is too small.
    pub fn parse(data: &[u8], ps: u8) -> Option<Self> {
        let p = ps as usize;
        if data.len() < Self::size(ps) {
            return None;
        }

        Some(Self {
            elem: read_uintptr(data, 0, ps)?,
            dir: read_uintptr(data, p, ps)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_recv_only() {
        let mut buf = vec![0u8; 16];
        buf[0..8].copy_from_slice(&0x5000u64.to_le_bytes());
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());

        let c = ChanTypeExtra::parse(&buf, 8).unwrap();
        assert_eq!(c.elem, 0x5000);
        assert_eq!(c.dir, 1); // recv
    }

    #[test]
    fn parse_send_only() {
        let mut buf = vec![0u8; 16];
        buf[0..8].copy_from_slice(&0x6000u64.to_le_bytes());
        buf[8..16].copy_from_slice(&2u64.to_le_bytes());

        let c = ChanTypeExtra::parse(&buf, 8).unwrap();
        assert_eq!(c.dir, 2); // send
    }

    #[test]
    fn parse_bidirectional() {
        let mut buf = vec![0u8; 16];
        buf[0..8].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[8..16].copy_from_slice(&3u64.to_le_bytes());

        let c = ChanTypeExtra::parse(&buf, 8).unwrap();
        assert_eq!(c.dir, 3); // both
    }

    #[test]
    fn parse_32bit() {
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&0x8000u32.to_le_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());

        let c = ChanTypeExtra::parse(&buf, 4).unwrap();
        assert_eq!(c.elem, 0x8000);
        assert_eq!(c.dir, 1);
    }

    #[test]
    fn too_short_returns_none() {
        let buf = vec![0u8; 12];
        assert!(ChanTypeExtra::parse(&buf, 8).is_none());
    }

    #[test]
    fn size_calculations() {
        assert_eq!(ChanTypeExtra::size(4), 8);
        assert_eq!(ChanTypeExtra::size(8), 16);
    }
}
