//! The decoders that take a standalone blob, fed arbitrary bytes.
//!
//! The first byte picks the decoder and the next one its small parameters
//! (Go minor, pointer size, legacy flag); the rest is the blob. These run far
//! faster than a whole binary, so the fuzzer reaches deep into each format.

#![no_main]

use gobin::detection;
use gobin::formats;
use gobin::metadata::{self, BuildMode, BuildPaths, CgoMode, HookKind};
use gobin::structures::{buildinfo, coverage, funcdata, gcprog, name, pclntab::FuncId, wasm};
use gobin_fuzz::touch;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [which, param, blob @ ..] = data else {
        return;
    };
    let go_minor = u32::from(param % 32);
    let ps = if param & 0x80 == 0 { 8 } else { 4 };
    let legacy = param & 0x40 != 0;
    let text = std::str::from_utf8(blob).ok();
    match which % 14 {
        0 => {
            if let Some(package) = coverage::CoveragePackage::parse(blob) {
                touch(package.files());
                for function in &package.functions {
                    let slots = function.counter_slots();
                    for slot in 0..slots.min(64).saturating_add(4) {
                        touch(function.unit_for_slot(slot));
                    }
                }
                touch(package);
            }
            touch(coverage::CounterMode::from_raw(*param));
            touch(coverage::CounterGranularity::from_raw(*param));
        }
        1 => {
            touch(funcdata::parse_wrap_info(blob));
            touch(funcdata::ArgLayout::parse(blob));
        }
        2 => {
            if let Some(defers) = funcdata::OpenDefers::parse(blob, go_minor) {
                touch(defers.count());
                touch(defers);
            }
        }
        3 => touch(funcdata::parse_stack_objects(
            blob,
            ps,
            go_minor,
            Some(0x1000),
        )),
        4 => {
            let format = funcdata::PointerMapFormat::for_go_minor(go_minor);
            if let Some(maps) = funcdata::PointerMaps::parse(blob, format) {
                let words = maps.words();
                for i in 0..4 {
                    touch(maps.map(i));
                    for word in 0..words.min(256) {
                        touch(maps.is_pointer(i, word));
                        touch(maps.word_kind(i, word));
                    }
                }
                touch(maps);
            }
        }
        5 => {
            touch(name::decode_name(blob, legacy));
            touch(name::decode_name_with_flags(blob, legacy));
            touch(name::decode_name_and_tag(blob, legacy));
        }
        6 => {
            touch(buildinfo::find_version_string(blob));
            touch(buildinfo::find_version_experiments(blob));
            if let Some(text) = text {
                touch(buildinfo::version_experiments(text));
            }
        }
        7 => {
            if let Some(text) = text {
                touch(BuildMode::parse(text).as_str());
                touch(CgoMode::parse(text).as_str());
                touch(HookKind::of(text));
                touch(FuncId::special(text));
                touch(FuncId::classify(*param, text, Some(*param)));
                touch(metadata::is_runtime_path(text));
                touch(metadata::is_internal_path(text));
                touch(metadata::is_stdlib_path(text));
            }
        }
        8 => {
            touch(formats::detect_format(blob));
            touch(formats::macho_slices(blob));
            touch(detection::heuristic_check(blob));
            touch(detection::heuristic_hits(blob));
        }
        9 => {
            touch(wasm::walk(blob).count());
            touch(wasm::data_segments(blob));
            touch(wasm::go_producer_version(blob));
            touch(wasm::LinearMemory::assemble(blob, 1 << 24).is_some());
        }
        10 => touch(gcprog::run_gc_prog(blob, 1 << 16).len()),
        11 => {
            // Function names joined with their entry files: build paths.
            if let Some(text) = text {
                let pairs = text.lines().filter_map(|line| line.split_once('\t'));
                touch(BuildPaths::from_files(pairs));
            }
        }
        12 => {
            let ctx = formats::BinaryContext::new(blob);
            touch(ctx.format());
            let sections = ctx.sections();
            touch((
                sections.gopclntab,
                sections.go_buildinfo,
                sections.go_module,
            ));
            touch((
                sections.typelink,
                sections.itablink,
                sections.go_type,
                sections.go_func,
            ));
            touch(ctx.data_regions());
            touch(ctx.search_regions());
            touch(ctx.mapped_file_ranges());
            touch(ctx.structure_search_data().len());
            touch(ctx.elf_note_segments().count());
        }
        _ => gobin_fuzz::parse_and_exercise(blob),
    }
});
