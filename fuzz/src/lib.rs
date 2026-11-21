//! Shared driver for the gobin fuzz targets.
//!
//! [`exercise`] calls every public accessor of a parsed [`GoBinary`] and
//! formats what each returns, so a hang, an unbounded allocation or a deep
//! recursion anywhere behind the public API shows up as a libFuzzer crash
//! (timeout, `-rss_limit_mb`, `-malloc_limit_mb` or a stack overflow).
//! The crate's own lints already forbid panics, indexing and unchecked
//! arithmetic, so those are not what the targets look for.

use std::fmt::Debug;
use std::fmt::Write;
use std::hint::black_box;

use gobin::GoBinary;
use gobin::detection::ParseError;
use gobin::structures::funcdata::{FuncDataKind, PcDataKind};

/// A formatter target that only counts, so formatting runs in full
/// (`std::io::sink` skips formatting altogether).
struct Count(usize);

impl std::fmt::Write for Count {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0 = self.0.wrapping_add(s.len());
        Ok(())
    }
}

/// Format `value` so every field is read.
pub fn touch<T: Debug>(value: T) {
    let mut count = Count(0);
    let _ = write!(count, "{value:?}");
    black_box(count.0);
    black_box(value);
}

/// Format `value` with `Display`.
pub fn show<T: std::fmt::Display>(value: T) {
    let mut count = Count(0);
    let _ = write!(count, "{value}");
    black_box(count.0);
}

const FUNCDATA_KINDS: [FuncDataKind; 9] = [
    FuncDataKind::ArgsPointerMaps,
    FuncDataKind::LocalsPointerMaps,
    FuncDataKind::RegPointerMaps,
    FuncDataKind::StackObjects,
    FuncDataKind::InlTree,
    FuncDataKind::OpenCodedDeferInfo,
    FuncDataKind::ArgInfo,
    FuncDataKind::ArgLiveInfo,
    FuncDataKind::WrapInfo,
];

const PCDATA_KINDS: [PcDataKind; 6] = [
    PcDataKind::UnsafePoint,
    PcDataKind::StackMapIndex,
    PcDataKind::InlTreeIndex,
    PcDataKind::RegMapIndex,
    PcDataKind::ArgLiveIndex,
    PcDataKind::PanicBounds,
];

/// Parse `data` and, when it parses, exercise every accessor.
pub fn parse_and_exercise(data: &[u8]) {
    touch(gobin::detect(data));
    touch(gobin::formats::macho_slices(data));
    match GoBinary::try_parse(data) {
        Ok(bin) => exercise(&bin),
        // A universal Mach-O: each slice is a binary of its own. Slices lie
        // inside `data` by construction, which `get` still checks.
        Err(ParseError::Universal { slices }) => {
            for slice in &slices {
                if let Some(bin) = data.get(slice.range.clone()).and_then(GoBinary::parse) {
                    exercise(&bin);
                }
            }
        }
        Err(err) => {
            show(&err);
            touch(err);
        }
    }
}

/// The accessor groups [`exercise`] runs, by name, so a probe can time each.
pub const SECTIONS: &[(&str, fn(&GoBinary<'_>))] = &[
    ("info", exercise_info),
    ("symbols", exercise_symbols),
    ("module", exercise_module),
    ("pclntab", exercise_pclntab),
    ("functions", exercise_functions),
    ("types", exercise_types),
    ("itabs", exercise_itabs),
    ("coverage", exercise_coverage),
    ("assets", exercise_assets),
    ("strings", exercise_strings),
];

/// Call every public accessor of `bin`.
pub fn exercise(bin: &GoBinary<'_>) {
    for (_, section) in SECTIONS {
        section(bin);
    }
}

fn exercise_info(bin: &GoBinary<'_>) {
    touch(bin.confidence());
    touch(bin.report());
    touch(bin.go_version());
    touch(bin.go_experiments());
    touch(bin.build_paths());
    touch(bin.build_id());
    touch(bin.build_id_source());
    touch(bin.arch());
    touch(bin.compiler());
    touch(bin.obfuscation());
    touch(bin.is_likely_garbled());
    touch(bin.runtime_commit());
    touch(bin.fips_info());
    touch(bin.legacy_names());
    touch(bin.has_cgo());
    touch(bin.runtime_hooks());
    touch(bin.itab_layout());
    touch(bin.map_layout());

    if let Some(info) = bin.build_info() {
        touch(info);
        touch(info.goos());
        touch(info.goarch());
        touch(info.cgo_mode());
        touch(info.build_mode());
        touch(info.vendored());
        touch(info.vcs_revision());
        touch(info.vcs_time());
        touch(info.vcs_modified());
        touch(info.module_sum());
        touch(info.build_tags().collect::<Vec<_>>());
        touch(info.dependencies().collect::<Vec<_>>());
        touch(info.deps_full().collect::<Vec<_>>());
        touch(info.build_settings_iter().collect::<Vec<_>>());
        touch(info.setting("GOOS"));
    }
}

fn exercise_coverage(bin: &GoBinary<'_>) {
    for package in bin.coverage() {
        touch(package.files());
        for function in &package.functions {
            let slots = function.counter_slots();
            touch(slots);
            for slot in 0..slots.min(64).saturating_add(4) {
                touch(function.unit_for_slot(slot));
            }
        }
        touch(package);
    }
}

fn exercise_assets(bin: &GoBinary<'_>) {
    touch(bin.embedded_assets());
    touch(bin.init_order());
}

fn exercise_strings(bin: &GoBinary<'_>) {
    touch(bin.strings().take(100_000).count());
}

fn exercise_symbols(bin: &GoBinary<'_>) {
    let symbols = bin.symbols();
    touch(symbols.len());
    for symbol in symbols.iter().take(4096) {
        touch(symbols.at(symbol.va));
        touch(symbols.named(symbol.name));
        touch(bin.coverage_meta_at(symbol.va));
        touch(symbol.contains(symbol.va));
    }
    touch(symbols.as_slice());
}

fn exercise_module(bin: &GoBinary<'_>) {
    touch(bin.moduledata());
    touch(bin.modules());
    touch(bin.text_va());
    touch(bin.etext_va());
    touch(bin.text_section_end_va());
    touch(bin.text_bound_words());
    touch(bin.is_main_module());
    touch(bin.module_name());
    touch(bin.plugin_path());
    touch(bin.is_coverage_build());
    touch(bin.text_sections());
    touch(bin.plugin_exports());
    touch(bin.package_hashes());
    touch(bin.module_hashes());
    if let Some(map) = bin.data_pointer_map() {
        touch(map.pointer_count());
        touch(map.pointer_vas().take(100_000).count());
    }
    if let Some(map) = bin.bss_pointer_map() {
        touch(map.pointer_count());
        touch(map.pointer_vas().take(100_000).count());
    }
    for off in [0u32, 1, 0x1000, u32::MAX] {
        if let Some(va) = bin.text_addr(off) {
            touch(bin.text_off(va));
            touch(bin.function_at(va));
        }
    }
}

fn exercise_pclntab(bin: &GoBinary<'_>) {
    if let Some(pcl) = bin.pclntab() {
        touch(pcl.meta());
        touch(pcl.arch());
        touch(pcl.file_names().count());
        for (_entry, func_off) in pcl.func_entries() {
            let Some(func) = pcl.parse_func(func_off) else {
                continue;
            };
            touch(pcl.decode_pcvalue(func.pcsp).count());
            touch(pcl.decode_pcln_with_files(&func).count());
            touch(pcl.decode_pcfile_paths(&func).count());
            touch(pcl.inline_index_table(&func).map(Iterator::count));
            touch(pcl.own_code(&func));
            touch(pcl.max_frame_size(&func));
            touch(pcl.funcdata_slots(&func));
        }
    }
}

fn exercise_functions(bin: &GoBinary<'_>) {
    for func in bin.functions() {
        touch(func.package());
        touch(func.short_name());
        touch(func.receiver_type());
        touch(func.method_name());
        touch(func.generic_args());
        touch(func.uses_defer());
        touch(func.func_flags());
        touch(bin.entry_va(&func));
        touch(bin.entry_rva(&func));
        if let Some(va) = bin.entry_va(&func) {
            touch(bin.function_at(va));
        }
        touch(bin.inline_tree(&func).take(100_000).collect::<Vec<_>>());
        for kind in FUNCDATA_KINDS {
            touch(bin.funcdata(&func, kind));
        }
        for kind in PCDATA_KINDS {
            touch(bin.pcdata(&func, kind).map(|it| it.take(100_000).count()));
        }
        touch(bin.wrapped_function(&func));
        touch(bin.arg_layout(&func));
        if let Some(defers) = bin.open_defers(&func) {
            touch(defers.count());
            touch(defers);
        }
        touch(bin.stack_objects(&func));
        for kind in [
            FuncDataKind::ArgsPointerMaps,
            FuncDataKind::LocalsPointerMaps,
            FuncDataKind::RegPointerMaps,
        ] {
            if let Some(maps) = bin.pointer_maps(&func, kind) {
                let words = maps.words();
                for i in 0..4 {
                    touch(maps.map(i));
                    for word in 0..words.min(64) {
                        touch(maps.word_kind(i, word));
                    }
                }
                touch(maps);
            }
        }
        touch(func);
    }
}

fn exercise_types(bin: &GoBinary<'_>) {
    for ty in bin.types() {
        touch(ty.package());
        touch(ty.is_runtime());
        touch(ty.is_internal());
        touch(ty.is_stdlib());
        touch(ty.detail.kind_str());
        touch(ty.detail.array_len());
        touch(ty.detail.chan_dir());
        touch(ty.detail.func_arity());
        touch(ty.detail.struct_field_count());
        touch(ty.detail.interface_method_count());
        for method in &ty.methods {
            touch(bin.method_functions(method));
        }
        touch(bin.type_at(ty.descriptor_va));
        touch(ty);
    }
    touch(bin.all_types().len());
    touch(bin.laid_out_types().len());
}

fn exercise_itabs(bin: &GoBinary<'_>) {
    for pair in bin.itab_pairs() {
        touch(bin.itab_methods(&pair));
        touch(pair);
    }
}
