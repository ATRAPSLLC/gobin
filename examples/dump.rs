//! Complete Go binary metadata dump.
//!
//! Usage: `cargo run --example dump -- [--explain] <path-to-go-binary>`
//!
//! Outputs ALL extractable metadata in a structured, grep-friendly format.
//! User code is listed first, followed by standard library, then runtime internals.
//!
//! `--explain` prints the structured detection report regardless of outcome,
//! making it the right mode for diagnosing "why was this binary not detected
//! as Go?" or "why is the confidence Medium instead of High?".

use std::collections::BTreeMap;

use gobin::{
    GoBinary,
    detection::{ConfidenceReport, ConfidenceSignal, ParseError},
    metadata::{CgoMode, FunctionInfo},
    structures::{
        Arch,
        pclntab::FuncId,
        types::{GoType, TypeDetail},
    },
};

fn main() {
    let raw: Vec<String> = std::env::args().collect();
    let prog = raw.first().map(String::as_str).unwrap_or("dump");
    let mut explain = false;
    let mut path: Option<String> = None;
    for arg in raw.iter().skip(1) {
        match arg.as_str() {
            "--explain" => explain = true,
            "-h" | "--help" => {
                println!("Usage: {prog} [--explain] <go-binary>");
                return;
            }
            other if path.is_none() => path = Some(other.to_string()),
            other => {
                eprintln!("Unexpected argument: {other}");
                eprintln!("Usage: {prog} [--explain] <go-binary>");
                std::process::exit(2);
            }
        }
    }
    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("Usage: {prog} [--explain] <go-binary>");
            std::process::exit(2);
        }
    };

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            std::process::exit(1);
        }
    };

    dump(&data, &path, explain);
}

/// Dump one image; a universal Mach-O file is dumped slice by slice.
fn dump(data: &[u8], path: &str, explain: bool) {
    let bin = match GoBinary::try_parse(data) {
        Ok(b) => b,
        Err(ParseError::NotAGoBinary { report }) => {
            eprintln!("{path}: not a Go binary");
            print_report(&report, None);
            std::process::exit(1);
        }
        Err(ParseError::Universal { slices }) => {
            for slice in slices {
                let label = format!("{path} [{:?}]", slice.arch);
                if let Some(image) = data.get(slice.range.clone()) {
                    dump(image, &label, explain);
                }
            }
            return;
        }
    };

    if explain {
        print_report(bin.report(), bin.go_version());
        println!();
    }

    let pclntab = bin.pclntab();
    let funcs: Vec<FunctionInfo<'_>> = bin.functions().collect();
    let files: Vec<&str> = pclntab
        .map(|p| p.file_names().collect())
        .unwrap_or_default();
    let types: Vec<_> = bin.types().collect();

    print_header(&bin, &funcs, &files, path, data.len());
    print_build_info(&bin);
    print_extras(&bin);
    print_functions_and_packages(&funcs, &types);
    print_source_files(&files);
}

/// FIPS mode, embedded assets, interface tables, and package init order.
fn print_extras(bin: &GoBinary<'_>) {
    let fips = bin.fips_info();
    let assets = bin.embedded_assets();
    let itab_count = bin.itab_pairs().count();
    let init_tasks = bin.init_order();

    if fips.is_none() && assets.is_empty() && itab_count == 0 && init_tasks.is_empty() {
        return;
    }

    println!("================================================================================");
    println!("  Runtime & Linker Surfaces");
    println!("================================================================================");
    println!();

    if let Some(f) = fips {
        let sum: String = f.module_sum.map_or_else(
            || "(no section)".to_string(),
            |s| s.iter().take(8).map(|b| format!("{b:02x}")).collect(),
        );
        println!("[FIPS-140]");
        println!("  GOFIPS140    : {}", f.version);
        println!("  Enforced     : {}", f.enforced_by_default);
        println!("  Module sum   : {sum}...");
        println!();
    }

    println!("[Interface tables]");
    println!("  itab pairs   : {itab_count}");
    println!();

    if let Some(dp) = bin.data_pointer_map() {
        let bss = bin.bss_pointer_map();
        println!("[Global pointers (GC map)]");
        println!(
            "  data         : {} of {} words are pointers",
            dp.pointer_count(),
            dp.words.len()
        );
        if let Some(bp) = bss {
            println!(
                "  bss          : {} of {} words are pointers",
                bp.pointer_count(),
                bp.words.len()
            );
        }
        println!();
    }

    if let Some(md) = bin.moduledata() {
        println!("[Module]");
        println!(
            "  Main module  : {}",
            bin.is_main_module()
                .map(|b| b.to_string())
                .unwrap_or_else(|| "?".into())
        );
        if let Some(name) = bin.module_name() {
            println!("  Module name  : {name}");
        }
        if let Some(path) = bin.plugin_path() {
            println!("  Plugin path  : {path}");
        }
        println!("  Coverage     : {}", bin.is_coverage_build());
        println!("  Text sects   : {}", md.textsectmap.len);
        println!(
            "  Data segs    : noptrdata={}B data={}B bss={}B noptrbss={}B",
            md.noptrdata.size(),
            md.data.size(),
            md.bss.size(),
            md.noptrbss.size()
        );
        println!();
    }

    if !assets.is_empty() {
        println!("[Embedded assets ({})]", assets.len());
        for a in &assets {
            if a.is_dir {
                println!("  {:<40} <dir>", a.path);
            } else {
                println!("  {:<40} {} bytes", a.path, a.data.len());
            }
        }
        println!();
    }

    if !init_tasks.is_empty() {
        let total_fns: usize = init_tasks.iter().map(|t| t.functions.len()).sum();
        println!(
            "[Package init order ({} tasks, {total_fns} fns)]",
            init_tasks.len()
        );
        for t in init_tasks.iter().take(20) {
            let pkg = t.package.unwrap_or("(unresolved)");
            println!("  {pkg} ({} init fn)", t.functions.len());
        }
        if init_tasks.len() > 20 {
            println!("  … and {} more", init_tasks.len().saturating_sub(20));
        }
        println!();
    }
}

fn print_report(report: &ConfidenceReport, go_version: Option<&str>) {
    eprintln!("[Detection report] tier = {:?}", report.tier);
    if report.signals.is_empty() {
        eprintln!("  (no signals collected)");
        return;
    }
    for signal in &report.signals {
        match signal {
            ConfidenceSignal::GopclntabSectionPresent => {
                eprintln!("  [+] gopclntab section present")
            }
            ConfidenceSignal::BuildinfoSectionPresent => {
                eprintln!("  [+] buildinfo section present")
            }
            ConfidenceSignal::BuildidNotePresent => eprintln!("  [+] build-id note present"),
            ConfidenceSignal::TypeSectionPresent { section } => {
                eprintln!("  [+] type-metadata section present: {section}");
            }
            ConfidenceSignal::BuildIdMarkerFound => eprintln!("  [+] build-id raw marker found"),
            ConfidenceSignal::BuildinfoParsed => eprintln!("  [+] buildinfo blob parsed"),
            ConfidenceSignal::BuildinfoMissing { reason } => {
                eprintln!("  [-] buildinfo missing: {reason}")
            }
            ConfidenceSignal::PclntabParsed { version, nfunc } => {
                eprintln!("  [+] pclntab parsed: {version:?} ({nfunc} funcs)")
            }
            ConfidenceSignal::PclntabMissing { reason } => {
                eprintln!("  [-] pclntab missing: {reason}")
            }
            ConfidenceSignal::GoVersionString { source } => {
                let version = go_version.unwrap_or("?");
                eprintln!("  [+] go version: {version} (source: {source:?})")
            }
            ConfidenceSignal::HeuristicStringsMatched { hits } => {
                eprintln!("  [+] heuristic strings matched: {hits}")
            }
            ConfidenceSignal::ModuledataLocated { version, source } => {
                eprintln!("  [+] moduledata {version:?} found by {source:?}")
            }
            ConfidenceSignal::ModuledataMissing => eprintln!("  [-] moduledata missing"),
            ConfidenceSignal::LayoutsChosen {
                itab,
                map,
                text_offsets_indexed,
                decided_by,
            } => eprintln!(
                "  [+] layouts: itab {itab:?}, map {map:?}, indexed text offsets \
                 {text_offsets_indexed} (from {decided_by:?})"
            ),
            ConfidenceSignal::SymbolTable => eprintln!("  [+] symbol table present"),
            ConfidenceSignal::SymbolTableStripped => eprintln!("  [-] symbol table stripped"),
        }
    }
}

fn print_header(
    bin: &GoBinary<'_>,
    funcs: &[FunctionInfo<'_>],
    files: &[&str],
    path: &str,
    size: usize,
) {
    println!("================================================================================");
    println!("  Go Binary Analysis: {path}");
    println!("================================================================================");
    println!();
    println!("[Binary]");
    println!(
        "  File size    : {} bytes ({:.1} MB)",
        size,
        size as f64 / 1_048_576.0
    );
    println!("  Format       : {:?}", bin.context().format());
    println!("  Confidence   : {:?}", bin.confidence());
    println!();

    println!("[Go Toolchain]");
    println!("  Go version   : {}", bin.go_version().unwrap_or("unknown"));
    if let Some(p) = bin.pclntab() {
        println!(
            "  pclntab ver  : {:?} ({})",
            p.version,
            p.version.go_version_range()
        );
    }
    println!("  Build ID     : {}", bin.build_id().unwrap_or("none"));
    let experiments = bin.go_experiments();
    if !experiments.is_empty() {
        println!("  Experiments  : {}", experiments.join(","));
    }
    let paths = bin.build_paths();
    for (label, path) in [
        ("GOROOT", paths.goroot),
        ("GOPATH", paths.gopath),
        ("Module cache", paths.module_cache),
        ("Main dir", paths.main_dir),
        ("Home", paths.home),
    ] {
        if let Some(path) = path {
            println!("  {label:<13}: {path}");
        }
    }
    println!();

    println!("[Target]");
    println!("  Architecture : {:?}", bin.arch());
    if let Some(p) = bin.pclntab() {
        println!("  Pointer size : {} bytes", p.ptr_size);
    }
    let _ = Arch::Unknown;
    if let Some(info) = bin.build_info() {
        println!("  GOOS         : {}", info.goos().unwrap_or("unknown"));
        println!("  GOARCH       : {}", info.goarch().unwrap_or("unknown"));
        if let Some(cgo) = info.cgo_mode() {
            let mode = match cgo {
                CgoMode::Disabled => "disabled".into(),
                CgoMode::Enabled => "enabled".into(),
                CgoMode::Bindings => "bindings".into(),
                CgoMode::Other(value) => format!("CGO_ENABLED={value}"),
            };
            println!("  CGO          : {mode}");
        }
    }
    println!();

    println!("[Counts]");
    println!("  Functions    : {}", funcs.len());
    println!("  Source files : {}", files.len());
    println!("  Symbols      : {}", bin.symbols().len());
    println!("  Runtime hooks: {}", bin.runtime_hooks().len());
    println!("  Links cgo    : {}", bin.has_cgo());
    println!();
}

fn print_build_info(bin: &GoBinary<'_>) {
    let info = match bin.build_info() {
        Some(i) => i,
        None => return,
    };

    println!("================================================================================");
    println!("  Build Info");
    println!("================================================================================");
    println!();

    if let Some(ref path) = info.main_path {
        println!("  Main path    : {path}");
    }
    if let Some(ref module) = info.main_module {
        let ver = info.main_version.unwrap_or("");
        println!("  Module       : {module} {ver}");
    }

    // VCS info
    if let Some(vcs) = info.setting("vcs") {
        print!("  VCS          : {vcs}");
        if let Some(rev) = info.vcs_revision() {
            print!(" @ {rev}");
        }
        if info.vcs_modified() == Some(true) {
            print!(" (dirty)");
        }
        println!();
    }
    println!();

    // Build settings
    if !info.build_settings.is_empty() {
        println!("  Build settings:");
        for (key, value) in &info.build_settings {
            if !value.is_empty() {
                println!("    {key} = {value}");
            } else {
                println!("    {key}");
            }
        }
        println!();
    }

    // Dependencies
    if !info.deps.is_empty() {
        println!("  Dependencies ({}):", info.deps.len());
        for dep in &info.deps {
            print!("    {} {}", dep.path, dep.version.unwrap_or(""),);
            if let Some(ref sum) = dep.sum {
                print!("  {sum}");
            }
            println!();
            if let Some(ref r) = dep.replacement {
                println!(
                    "      => {} {}{}",
                    r.path,
                    r.version.unwrap_or(""),
                    r.sum.map(|s| format!("  {s}")).unwrap_or_default(),
                );
            }
        }
        println!();
    }
}

/// Classify a package into a tier for output ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PackageTier {
    User,
    Stdlib,
    Internal,
}

fn classify_package(pkg: &str) -> PackageTier {
    if pkg == "main" || pkg.contains('.') {
        PackageTier::User
    } else if pkg.starts_with("runtime")
        || pkg.starts_with("internal/")
        || pkg.starts_with("vendor/")
        || pkg.starts_with("type:")
        || pkg == "(unknown)"
    {
        PackageTier::Internal
    } else {
        PackageTier::Stdlib
    }
}

fn tier_label(tier: PackageTier) -> &'static str {
    match tier {
        PackageTier::User => "USER CODE",
        PackageTier::Stdlib => "STANDARD LIBRARY",
        PackageTier::Internal => "RUNTIME & INTERNAL",
    }
}

fn print_functions_and_packages(funcs: &[FunctionInfo<'_>], types: &[GoType]) {
    println!("================================================================================");
    println!("  Packages, Functions & Types");
    println!("================================================================================");
    println!();

    let mut packages: BTreeMap<String, Vec<&FunctionInfo<'_>>> = BTreeMap::new();
    for f in funcs {
        let pkg = f.package().unwrap_or("(unknown)").to_string();
        packages.entry(pkg).or_default().push(f);
    }

    let mut type_by_pkg: BTreeMap<String, Vec<&GoType>> = BTreeMap::new();
    for t in types {
        let pkg = t.package().unwrap_or("(unknown)").to_string();
        type_by_pkg.entry(pkg).or_default().push(t);
    }

    let mut all_pkgs: Vec<(PackageTier, &str)> = packages
        .keys()
        .map(|p| (classify_package(p), p.as_str()))
        .collect();
    for pkg in type_by_pkg.keys() {
        if !packages.contains_key(pkg.as_str()) {
            all_pkgs.push((classify_package(pkg), pkg.as_str()));
        }
    }
    all_pkgs.sort();
    all_pkgs.dedup();

    let mut current_tier: Option<PackageTier> = None;

    for (tier, pkg) in &all_pkgs {
        if current_tier != Some(*tier) {
            if current_tier.is_some() {
                println!();
            }
            println!("  --- {} {:-<60}", tier_label(*tier), "");
            println!();
            current_tier = Some(*tier);
        }

        let pkg_funcs = packages.get(*pkg);
        let pkg_types = type_by_pkg.get(*pkg);
        let func_count = pkg_funcs.map(|f| f.len()).unwrap_or(0);
        let type_count = pkg_types.map(|t| t.len()).unwrap_or(0);

        print!("  [{pkg}]");
        if func_count > 0 {
            print!("  {func_count} functions");
        }
        if type_count > 0 {
            print!("  {type_count} types");
        }
        println!();

        if let Some(pkg_types) = pkg_types {
            for t in pkg_types {
                let mut tags = Vec::new();
                tags.push(format!("{}", t.kind));
                tags.push(format!("size:{}", t.size));
                tags.push(format!("align:{}", t.align));
                if t.field_align != t.align {
                    tags.push(format!("field_align:{}", t.field_align));
                }
                if t.ptr_bytes > 0 {
                    tags.push(format!("ptrbytes:{}", t.ptr_bytes));
                }
                tags.push(format!("hash:0x{:08x}", t.hash));
                match &t.detail {
                    TypeDetail::Array { len, .. } => tags.push(format!("len:{len}")),
                    TypeDetail::Chan { dir, .. } => {
                        let d = match dir {
                            1 => "<-chan",
                            2 => "chan<-",
                            _ => "chan",
                        };
                        tags.push(format!("dir:{d}"));
                    }
                    TypeDetail::Func {
                        in_count,
                        out_count,
                        is_variadic,
                        ..
                    } => {
                        tags.push(format!("in:{in_count}"));
                        tags.push(format!("out:{out_count}"));
                        if *is_variadic {
                            tags.push("variadic".into());
                        }
                    }
                    TypeDetail::Interface { method_count, .. } => {
                        tags.push(format!("iface_methods:{method_count}"));
                    }
                    TypeDetail::Map { .. } => {}
                    TypeDetail::Pointer { .. } | TypeDetail::Slice { .. } => {}
                    TypeDetail::Struct { field_count, .. } => {
                        tags.push(format!("fields:{field_count}"));
                    }
                    TypeDetail::None => {}
                }
                if t.method_count > 0 {
                    if t.exported_method_count == t.method_count {
                        tags.push(format!("methods:{}", t.method_count));
                    } else {
                        tags.push(format!(
                            "methods:{}/{}exported",
                            t.method_count, t.exported_method_count
                        ));
                    }
                }
                if t.is_named {
                    tags.push("named".into());
                }
                println!("    type {}  [{}]", t.name, tags.join(", "));
            }
        }

        if let Some(pkg_funcs) = pkg_funcs {
            let mut sorted: Vec<&&FunctionInfo<'_>> = pkg_funcs.iter().collect();
            sorted.sort_by(|a, b| {
                let a_closure = a.is_closure();
                let b_closure = b.is_closure();
                let a_method = a.is_method();
                let b_method = b.is_method();
                match (a_method, b_method) {
                    (true, false) if !b_closure => return std::cmp::Ordering::Less,
                    (false, true) if !a_closure => return std::cmp::Ordering::Greater,
                    _ => {}
                }
                match (a_closure, b_closure) {
                    (true, false) => return std::cmp::Ordering::Greater,
                    (false, true) => return std::cmp::Ordering::Less,
                    _ => {}
                }
                a.name.cmp(b.name)
            });

            for f in sorted {
                let mut tags = Vec::new();
                if f.func.start_line > 0 {
                    if f.end_line > f.func.start_line {
                        tags.push(format!("lines:{}-{}", f.func.start_line, f.end_line));
                    } else {
                        tags.push(format!("line:{}", f.func.start_line));
                    }
                }
                tags.push(format!("off:0x{:x}", f.func.entry_off));
                if f.func.args > 0 {
                    tags.push(format!("args:{}B", f.func.args));
                }
                if f.frame_size > 0 {
                    tags.push(format!("frame:{}B", f.frame_size));
                }
                if f.uses_defer() {
                    tags.push(format!("defer:0x{:x}", f.func.deferreturn));
                }
                if f.func.nfuncdata > 0 {
                    tags.push(format!("funcdata:{}", f.func.nfuncdata));
                }
                if f.func.npcdata > 0 {
                    tags.push(format!("pcdata:{}", f.func.npcdata));
                }
                let func_id = f.func_id;
                if func_id != FuncId::Normal {
                    tags.push(format!("funcID:{func_id}"));
                }
                if f.func.flag != 0 {
                    let mut flag_parts = Vec::new();
                    if f.func.flag & 0x01 != 0 {
                        flag_parts.push("TopFrame");
                    }
                    if f.func.flag & 0x02 != 0 {
                        flag_parts.push("SPWrite");
                    }
                    if f.func.flag & 0x04 != 0 {
                        flag_parts.push("Asm");
                    }
                    if !flag_parts.is_empty() {
                        tags.push(flag_parts.join("|"));
                    }
                }

                let tag_str = if tags.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", tags.join(", "))
                };

                let prefix = if f.is_method() {
                    "method"
                } else if f.is_closure() {
                    "closure"
                } else {
                    "func"
                };

                println!("    {} {}{}", prefix, f.short_name(), tag_str);
                if let Some(src) = f.source_file
                    && *tier == PackageTier::User
                {
                    println!("           src: {src}");
                }
            }
        }

        println!();
    }

    let user_funcs = funcs
        .iter()
        .filter(|f| classify_package(f.package().unwrap_or("")) == PackageTier::User)
        .count();
    let stdlib_funcs = funcs
        .iter()
        .filter(|f| classify_package(f.package().unwrap_or("")) == PackageTier::Stdlib)
        .count();
    let internal_funcs = funcs
        .iter()
        .filter(|f| classify_package(f.package().unwrap_or("")) == PackageTier::Internal)
        .count();
    let defer_funcs = funcs.iter().filter(|f| f.uses_defer()).count();
    let method_funcs = funcs.iter().filter(|f| f.is_method()).count();
    let closure_funcs = funcs.iter().filter(|f| f.is_closure()).count();

    println!("  --- SUMMARY {:-<65}", "");
    println!();
    println!("  Total functions : {}", funcs.len());
    println!("    User code     : {user_funcs}");
    println!("    Stdlib        : {stdlib_funcs}");
    println!("    Internal      : {internal_funcs}");
    println!("  Methods         : {method_funcs}");
    println!("  Closures        : {closure_funcs}");
    println!("  Using defer     : {defer_funcs}");
    println!("  Total packages  : {}", packages.len());
    println!("  Total types     : {}", types.len());
    println!();
}

fn print_source_files(files: &[&str]) {
    println!("================================================================================");
    println!("  Source Files ({})", files.len());
    println!("================================================================================");
    println!();

    let mut user_files: Vec<&&str> = Vec::new();
    let mut sdk_files: BTreeMap<String, Vec<&&str>> = BTreeMap::new();

    for f in files {
        if f.contains("/libexec/src/") || f.contains("/go/src/") || f.contains("GOROOT") {
            if let Some(src_idx) = f.rfind("/src/") {
                let after_src = match src_idx.checked_add(5).and_then(|start| f.get(start..)) {
                    Some(s) => s,
                    None => continue,
                };
                let pkg = if let Some(last_slash) = after_src.rfind('/') {
                    &after_src[..last_slash]
                } else {
                    after_src
                };
                sdk_files.entry(pkg.to_string()).or_default().push(f);
            } else {
                sdk_files.entry("(other)".to_string()).or_default().push(f);
            }
        } else {
            user_files.push(f);
        }
    }

    if !user_files.is_empty() {
        println!("  --- USER SOURCE FILES {:-<56}", "");
        println!();
        for f in &user_files {
            println!("  {f}");
        }
        println!();
    }

    if !sdk_files.is_empty() {
        println!(
            "  --- SDK SOURCE FILES ({} packages, {} files) {:-<33}",
            sdk_files.len(),
            sdk_files.values().map(|v| v.len()).sum::<usize>(),
            ""
        );
        println!();

        for (pkg, pkg_files) in &sdk_files {
            println!("  [{}]  ({} files)", pkg, pkg_files.len());
            for f in pkg_files {
                let basename = f.rsplit('/').next().unwrap_or(f);
                println!("    {basename}");
            }
        }
        println!();
    }
}
