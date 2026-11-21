//! Type descriptor size computation.
//!
//! Go's `abi.Type.DescriptorSize()` computes the total size of a concrete type
//! descriptor including the base `abi.Type`, the concrete-type extra fields,
//! an optional `UncommonType`, variable-length data (parameters, fields, methods),
//! and the method array.
//!
//! Source: `src/internal/abi/type.go:750-799`

use crate::{
    structures::{
        abitype::AbiType,
        arraytype::ArrayTypeExtra,
        chantype::ChanTypeExtra,
        elemtype::ElemTypeExtra,
        functype::FuncTypeExtra,
        interfacetype::InterfaceTypeExtra,
        kind,
        maptype::{MapLayout, MapTypeExtra},
        method::{GoImethod, GoMethod},
        structtype::{GoStructField, StructTypeExtra},
        uncommon::UncommonType,
    },
    util::align_up,
};

/// Compute the total descriptor size for a type, equivalent to Go's
/// `abi.Type.DescriptorSize()` from `src/internal/abi/type.go`.
///
/// The total is: concrete_type_size + uncommon_type_size + variable_data + methods.
///
/// `map_layout` selects the [`MapTypeExtra`] shape, which changed in both Go
/// 1.24 and Go 1.27; getting it wrong mis-sizes every map descriptor and, with
/// it, the position of the trailing `UncommonType`.
pub fn descriptor_size(
    type_data: &[u8],
    abi_type: &AbiType,
    ps: u8,
    map_layout: MapLayout,
) -> Option<usize> {
    let p = ps as usize;
    let base_sz = AbiType::size(ps);

    let (concrete_sz, var_sz) = match abi_type.kind() {
        kind::ARRAY => (base_sz.checked_add(ArrayTypeExtra::size(ps))?, 0usize),
        kind::CHAN => (base_sz.checked_add(ChanTypeExtra::size(ps))?, 0),
        kind::FUNC => {
            let extra_off = base_sz;
            let extra = FuncTypeExtra::parse(type_data.get(extra_off..)?)?;
            let param_count = (extra.in_count as usize).checked_add(extra.num_out() as usize)?;
            // Params follow FuncTypeExtra after ptr-aligned padding.
            let after_extra = base_sz.checked_add(FuncTypeExtra::SIZE)?;
            let params_off = align_up(after_extra, p)?;
            let pad = params_off.checked_sub(after_extra)?;
            let extra_total = FuncTypeExtra::SIZE.checked_add(pad)?;
            (
                base_sz.checked_add(extra_total)?,
                param_count.checked_mul(p)?,
            )
        }
        kind::INTERFACE => {
            let extra_off = base_sz;
            let extra = InterfaceTypeExtra::parse(type_data.get(extra_off..)?, ps)?;
            (
                base_sz.checked_add(InterfaceTypeExtra::size(ps))?,
                (extra.methods.len as usize).checked_mul(GoImethod::SIZE)?,
            )
        }
        kind::MAP => {
            // `Probe` has to be resolved against this descriptor's own bytes
            // before it can be sized.
            let resolved = map_layout.resolve_for(type_data.get(base_sz..)?, ps);
            (
                base_sz.checked_add(MapTypeExtra::size(ps, resolved))?,
                0usize,
            )
        }
        kind::POINTER => (base_sz.checked_add(ElemTypeExtra::size(ps))?, 0),
        kind::SLICE => (base_sz.checked_add(ElemTypeExtra::size(ps))?, 0),
        kind::STRUCT => {
            let extra_off = base_sz;
            let extra = StructTypeExtra::parse(type_data.get(extra_off..)?, ps)?;
            (
                base_sz.checked_add(StructTypeExtra::size(ps))?,
                (extra.fields.len as usize).checked_mul(GoStructField::size(ps))?,
            )
        }
        kind::BOOL
        | kind::INT
        | kind::INT8
        | kind::INT16
        | kind::INT32
        | kind::INT64
        | kind::UINT
        | kind::UINT8
        | kind::UINT16
        | kind::UINT32
        | kind::UINT64
        | kind::UINTPTR
        | kind::FLOAT32
        | kind::FLOAT64
        | kind::COMPLEX64
        | kind::COMPLEX128
        | kind::STRING
        | kind::UNSAFE_POINTER => (base_sz, 0),
        _ => return None,
    };

    let mut total = concrete_sz;

    let mcount = if abi_type.has_uncommon() {
        let ut_off = concrete_sz;
        let ut = UncommonType::parse(type_data.get(ut_off..)?)?;
        total = total.checked_add(UncommonType::SIZE)?;
        ut.mcount as usize
    } else {
        0
    };

    total = total.checked_add(var_sz)?;
    total = total.checked_add(mcount.checked_mul(GoMethod::SIZE)?)?;

    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_abitype_buf(ps: u8, kind: u8, tflag: u8) -> Vec<u8> {
        let size = AbiType::size(ps);
        let mut buf = vec![0u8; size];
        let p = ps as usize;
        // Kind_ is at offset 2*ps + 7
        buf[2 * p + 7] = kind;
        // TFlag is at offset 2*ps + 4
        buf[2 * p + 4] = tflag;
        buf
    }

    #[test]
    fn scalar_type_size() {
        let buf = make_abitype_buf(8, kind::INT, 0);
        let abi = AbiType::parse(&buf, 8).unwrap();
        let sz = descriptor_size(&buf, &abi, 8, MapLayout::SwissSplitGroup).unwrap();
        assert_eq!(sz, AbiType::size(8));
    }

    #[test]
    fn pointer_type_size() {
        let mut buf = make_abitype_buf(8, kind::POINTER, 0);
        buf.extend(vec![0u8; ElemTypeExtra::size(8)]);
        let abi = AbiType::parse(&buf, 8).unwrap();
        let sz = descriptor_size(&buf, &abi, 8, MapLayout::SwissSplitGroup).unwrap();
        assert_eq!(sz, AbiType::size(8) + ElemTypeExtra::size(8));
    }

    #[test]
    fn unknown_kind_returns_none() {
        let buf = make_abitype_buf(8, 0xFF, 0);
        let abi = AbiType::parse(&buf, 8).unwrap();
        assert!(descriptor_size(&buf, &abi, 8, MapLayout::SwissSplitGroup).is_none());
    }
}
