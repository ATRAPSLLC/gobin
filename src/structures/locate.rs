//! Finding the `moduledata` in a binary.
//!
//! Every Go binary has exactly one `runtime.firstmoduledata`, but where it is
//! and how to reach it depends on the format and the toolchain version:
//!
//! | Case                          | Strategy                                     |
//! |-------------------------------|----------------------------------------------|
//! | ELF / Mach-O, Go 1.26+        | the dedicated `.go.module` / `__go_module` section |
//! | ELF / Mach-O, Go ≤ 1.25       | scan for the `pcHeader` pointer               |
//! | PE (every version)            | scan - the Go PE linker emits no named Go sections |
//! | wasm                          | scan the reconstructed linear-memory image    |
//!
//! The scan works because `moduledata`'s first field is `pcHeader *pcHeader`,
//! which points at the pclntab: a pointer-aligned word equal to the pclntab's
//! address, whose surroundings then parse as a plausible moduledata, is the
//! moduledata. Candidates are validated rather than trusted - a pointer to the
//! pclntab can legitimately appear elsewhere in the image.
//!
//! [`ModuledataLocator`] owns all of that so the type reader and the top-level
//! [`crate::GoBinary`] share one implementation instead of each carrying a
//! copy of the scan.

use crate::{
    formats::{BinaryContext, BinaryFormat},
    structures::moduledata::{LayoutHints, Moduledata, ModuledataVersion},
};

/// Locates and parses a binary's `moduledata`.
///
/// Construct once per binary and call [`Self::locate`]; the result is worth
/// caching, since the scan path is proportional to the size of the searched
/// region.
pub struct ModuledataLocator<'a> {
    /// The binary being searched.
    ctx: &'a BinaryContext<'a>,
    /// Pointer size in bytes (4 or 8).
    ptr_size: u8,
    /// Offset of the pclntab within [`BinaryContext::structure_search_data`].
    pclntab_offset: usize,
    /// Signals that decide the moduledata layout once bytes are found.
    hints: LayoutHints,
}

impl<'a> ModuledataLocator<'a> {
    /// Build a locator for `ctx`.
    ///
    /// `pclntab_offset` is the pclntab's offset into the address-space view
    /// ([`BinaryContext::structure_search_data`]), which is what both the
    /// scan target and the wasm linear-memory addressing are derived from.
    pub fn new(
        ctx: &'a BinaryContext<'a>,
        ptr_size: u8,
        pclntab_offset: usize,
        hints: LayoutHints,
    ) -> Self {
        Self {
            ctx,
            ptr_size,
            pclntab_offset,
            hints,
        }
    }

    /// Find and parse the moduledata, or return `None` if neither strategy
    /// yields a structurally valid one.
    pub fn locate(&self) -> Option<Moduledata> {
        if !self.ctx.has_va_mapping() || self.ptr_size == 0 {
            return None;
        }
        self.in_section().or_else(|| self.by_scan())
    }

    /// Parse the moduledata out of the dedicated `.go.module` / `__go_module`
    /// section (Go 1.26+ ELF and Mach-O). No search needed - the section *is*
    /// the structure.
    fn in_section(&self) -> Option<Moduledata> {
        let range = self.ctx.sections().go_module.as_ref()?;
        let data = self.ctx.structure_search_data();
        let end = range.offset.checked_add(range.size)?;
        Moduledata::parse(data.get(range.offset..end)?, self.ptr_size, self.hints)
    }

    /// Scan the address-space view for the `pcHeader` pointer and parse the
    /// first candidate whose fields validate.
    ///
    /// Writable data regions are searched first when the section table names
    /// them: the moduledata is emitted into `.noptrdata` (ELF / Mach-O) or the
    /// merged `.data` (PE), which on a real binary is a small fraction of the
    /// image, and searching it first turns a whole-file sweep into a few tens
    /// of kilobytes. The full image remains the fallback, so a stripped or
    /// unusual section table costs correctness nothing.
    fn by_scan(&self) -> Option<Moduledata> {
        let data = self.ctx.structure_search_data();
        let target = self.scan_target()?;

        // The section ranges are file offsets. They index the same bytes the
        // scan walks for ELF, Mach-O and PE, but for wasm the searched view is
        // the reconstructed linear-memory image, where a file offset means
        // nothing - so wasm scans the image whole. It is the smaller of the
        // two anyway, being only the module's initialized data.
        if self.ctx.format() != BinaryFormat::Wasm {
            let sections = self.ctx.sections();
            for range in [sections.noptrdata.as_ref(), sections.data_section.as_ref()]
                .into_iter()
                .flatten()
            {
                if let Some(found) = self.scan_region(data, range.offset, range.size, target) {
                    return Some(found);
                }
            }
        }
        self.scan_region(data, 0, data.len(), target)
    }

    /// The pointer value the scan looks for: the pclntab's address in whatever
    /// address space `structure_search_data` presents.
    ///
    /// For wasm that view *is* linear memory, so the pclntab's offset into it
    /// is already the address the runtime stored. Every other format needs the
    /// file-offset-to-VA translation. On chained-fixup Mach-O the view is the
    /// rebased copy, so the stored pointer is a real VA by the time we see it.
    fn scan_target(&self) -> Option<u64> {
        if self.ctx.format() == BinaryFormat::Wasm {
            Some(self.pclntab_offset as u64)
        } else {
            self.ctx.file_to_va(self.pclntab_offset)
        }
    }

    /// Scan `[start, start + len)` of `data` for `target` at pointer-aligned
    /// positions, parsing and validating each hit.
    ///
    /// The comparison is done on whole words rather than byte slices: the
    /// region is walked with `chunks_exact`, which the compiler turns into a
    /// straight-line integer scan, and only an equal word costs a parse.
    fn scan_region(
        &self,
        data: &[u8],
        start: usize,
        len: usize,
        target: u64,
    ) -> Option<Moduledata> {
        let p = self.ptr_size as usize;
        // Align the start up to a pointer boundary; the linker never places
        // moduledata unaligned, and a misaligned scan would double the work.
        let start = start.checked_next_multiple_of(p)?;
        let end = start.checked_add(len)?.min(data.len());
        let region = data.get(start..end)?;

        for (i, word) in region.chunks_exact(p).enumerate() {
            let value = match p {
                4 => u32::from_le_bytes(word.try_into().ok()?) as u64,
                8 => u64::from_le_bytes(word.try_into().ok()?),
                _ => return None,
            };
            if value != target {
                continue;
            }
            let Some(at) = i.checked_mul(p).and_then(|o| o.checked_add(start)) else {
                continue;
            };
            if let Some(md) = data
                .get(at..)
                .and_then(|rest| Moduledata::parse(rest, self.ptr_size, self.hints))
                && self.accept(&md)
            {
                return Some(md);
            }
        }
        None
    }

    /// Whether a scanned candidate is a real moduledata.
    ///
    /// A pointer to the pclntab can appear outside the moduledata, so a hit is
    /// only accepted when the fields around it also hold: the PC range must be
    /// non-empty, and the structure must be anchored by a field that maps back
    /// into the image. The legacy (Go 1.5-1.15) layout has no `funcnametab`
    /// and - before Go 1.7 - no `types` base, so it is anchored through its
    /// always-present `text` boundary instead.
    fn accept(&self, md: &Moduledata) -> bool {
        if md.minpc >= md.maxpc {
            return false;
        }
        match md.version {
            ModuledataVersion::V1 => md.text != 0 && self.ctx.va_to_file(md.text).is_some(),
            _ => md.types != 0 && self.ctx.va_to_file(md.funcnametab.ptr).is_some(),
        }
    }
}
