// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

mod config;
mod cross;
mod diagnostics;
mod kconfig;
mod makefile;
mod output;
mod walk;

use config::{ColorMode, OutputFormat, parse_args};
use diagnostics::Severity;
use std::collections::HashSet;
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::Instant;

fn main() -> ExitCode {
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("kconfiglint: error: {e}");
            return ExitCode::from(2);
        }
    };

    let start = Instant::now();

    // Phase 1: Discover files
    if cfg.verbose {
        eprintln!("Discovering files in {}...", cfg.srctree.display());
    }

    // Discover ALL Kconfig files on disk (not just those reachable via source chain).
    // This is critical because many Kconfig files are sourced conditionally via macros
    // like source "arch/$(SRCARCH)/Kconfig" which we cannot resolve statically.
    let kconfig_files = if cfg.should_run_kconfig() || cfg.should_run_cross() {
        walk::discover_all_kconfig_files_on_disk(&cfg.srctree)
    } else {
        Vec::new()
    };

    let makefile_files = if cfg.should_run_makefile() || cfg.should_run_cross() {
        walk::discover_makefile_files(&cfg.srctree)
    } else {
        Vec::new()
    };

    if cfg.verbose {
        eprintln!(
            "Found {} Kconfig files, {} Makefiles",
            kconfig_files.len(),
            makefile_files.len(),
        );
    }

    // Phase 2: Parse files in parallel
    let kconfig_index = Mutex::new(kconfig::KconfigIndex::default());
    let makefile_index = Mutex::new(makefile::MakefileIndex::default());

    // For X006 (unreachable Kconfig file check), we also need the set of files
    // reachable via the source chain.
    let kconfig_sourced: HashSet<std::path::PathBuf> = if cfg.should_run_cross() {
        walk::discover_kconfig_files(&cfg.srctree)
            .into_iter()
            .collect()
    } else {
        HashSet::new()
    };

    // Parse Kconfig files
    std::thread::scope(|s| {
        let chunk_size = (kconfig_files.len() / cfg.jobs).max(1);
        let chunks: Vec<_> = kconfig_files.chunks(chunk_size).collect();

        for chunk in chunks {
            let kconfig_index = &kconfig_index;
            s.spawn(move || {
                for path in chunk {
                    let source = match std::fs::read_to_string(path) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let kfile = kconfig::parser::parse_kconfig(path, &source);
                    kconfig_index.lock().unwrap().add_file(kfile);
                }
            });
        }
    });

    // Parse Makefile files
    std::thread::scope(|s| {
        let chunk_size = (makefile_files.len() / cfg.jobs).max(1);
        let chunks: Vec<_> = makefile_files.chunks(chunk_size).collect();

        for chunk in chunks {
            let makefile_index = &makefile_index;
            s.spawn(move || {
                for path in chunk {
                    let source = match std::fs::read_to_string(path) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let mfile = makefile::parser::parse_makefile(path, &source);
                    makefile_index.lock().unwrap().add_file(mfile);
                }
            });
        }
    });

    let kconfig_index = kconfig_index.into_inner().unwrap();
    let makefile_index = makefile_index.into_inner().unwrap();

    // Store sourced files in the index for X006
    // (We already have the set from walk discovery)
    let mut kconfig_index = kconfig_index;
    kconfig_index.sourced_files = kconfig_sourced;

    if cfg.verbose {
        eprintln!(
            "Parsed {} Kconfig symbols in {:.1}s",
            kconfig_index.symbol_count(),
            start.elapsed().as_secs_f64(),
        );
    }

    // Scan source files for CONFIG_ references (needed by X002, X005)
    let source_refs = if cfg.should_run_cross() {
        if cfg.verbose {
            eprintln!("Scanning source files for CONFIG_ references...");
        }
        walk::scan_source_config_refs(&cfg.srctree)
    } else {
        std::collections::HashSet::new()
    };

    if cfg.verbose && !source_refs.is_empty() {
        eprintln!(
            "Found {} CONFIG_ symbols in source files in {:.1}s",
            source_refs.len(),
            start.elapsed().as_secs_f64(),
        );
    }

    // Phase 3: Run checks
    let enabled = |id: &str| cfg.is_check_enabled(id);
    let mut all_diags = Vec::new();

    if cfg.should_run_kconfig() {
        all_diags.extend(kconfig::checks::run_kconfig_checks(&kconfig_index, &enabled));
    }

    if cfg.should_run_makefile() {
        all_diags.extend(makefile::checks::run_makefile_checks(
            &makefile_index,
            &enabled,
        ));
    }

    if cfg.should_run_cross() {
        all_diags.extend(cross::checks::run_cross_checks(
            &kconfig_index,
            &makefile_index,
            &source_refs,
            &enabled,
        ));

        // X006: unreachable Kconfig files
        // Build the set of files referenced by any source directive across
        // ALL parsed Kconfig files (not just the walker-reachable ones).
        // This avoids false positives from files sourced via macros like
        // source "arch/$(SRCARCH)/Kconfig".
        if enabled("X006") {
            let mut all_sourced = kconfig_index.sourced_files.clone();

            // Expand macro-based source directives. The main one is
            // source "arch/$(SRCARCH)/Kconfig" — expand it to all
            // arch dirs that exist on disk.
            for kfile in &kconfig_index.files {
                for source in &kfile.sources {
                    if !source.path.contains('$') {
                        let resolved = cfg.srctree.join(&source.path);
                        if let Ok(canonical) = std::fs::canonicalize(&resolved) {
                            all_sourced.insert(canonical);
                        }
                        all_sourced.insert(resolved);
                    } else {
                        // Try expanding known arch-related macros like
                        // $(SRCARCH) and $(HEADER_ARCH) to all arch dirs
                        let macros = ["$(SRCARCH)", "$(HEADER_ARCH)", "$(ARCH)"];
                        for mac in &macros {
                            if source.path.contains(mac) {
                                let arch_dir = cfg.srctree.join("arch");
                                if let Ok(entries) = std::fs::read_dir(&arch_dir) {
                                    for entry in entries.flatten() {
                                        if entry.path().is_dir() {
                                            let expanded = source.path.replace(
                                                mac,
                                                &entry.file_name().to_string_lossy(),
                                            );
                                            let resolved = cfg.srctree.join(&expanded);
                                            if let Ok(canonical) =
                                                std::fs::canonicalize(&resolved)
                                            {
                                                all_sourced.insert(canonical);
                                            }
                                            all_sourced.insert(resolved);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let all_on_disk = walk::discover_all_kconfig_files_on_disk(&cfg.srctree);
            for path in &all_on_disk {
                let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                if all_sourced.contains(path) || all_sourced.contains(&canonical) {
                    continue;
                }
                let rel = path
                    .strip_prefix(&cfg.srctree)
                    .unwrap_or(path)
                    .to_string_lossy();
                if rel.starts_with("Documentation/")
                    || rel.starts_with("tools/")
                    || rel.starts_with("scripts/kconfig/tests/")
                {
                    continue;
                }
                all_diags.push(diagnostics::Diagnostic::new(
                    "X006",
                    Severity::Warning,
                    format!(
                        "Kconfig file {} is not source'd from the Kconfig tree",
                        rel,
                    ),
                    diagnostics::Span::new(path, 1),
                ));
            }
        }
    }

    // Phase 4: Filter and output
    all_diags.retain(|d| d.severity >= cfg.min_severity);

    // Sort by file, then line
    all_diags.sort_by(|a, b| {
        a.span
            .file
            .cmp(&b.span.file)
            .then(a.span.line.cmp(&b.span.line))
    });

    let use_color = match cfg.color {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => atty_is_terminal(),
    };

    let error_count = all_diags.iter().filter(|d| d.severity == Severity::Error).count();
    let warn_count = all_diags
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .count();
    let info_count = all_diags.iter().filter(|d| d.severity == Severity::Info).count();

    match cfg.format {
        OutputFormat::Text => {
            output::text::print_diagnostics(&all_diags, &cfg.srctree, use_color);
            if cfg.verbose {
                let elapsed = start.elapsed();
                eprintln!(
                    "\nkconfiglint: {} error(s), {} warning(s), {} info(s) in {:.1}s \
                     ({} Kconfig symbols, {} files)",
                    error_count,
                    warn_count,
                    info_count,
                    elapsed.as_secs_f64(),
                    kconfig_index.symbol_count(),
                    kconfig_files.len() + makefile_files.len(),
                );
            }
        }
        OutputFormat::Json => {
            let stats = output::json::OutputStats {
                files_parsed: kconfig_files.len() + makefile_files.len(),
                kconfig_symbols: kconfig_index.symbol_count(),
                errors: error_count,
                warnings: warn_count,
                infos: info_count,
            };
            if let Err(e) = output::json::print_diagnostics(&all_diags, &cfg.srctree, &stats) {
                eprintln!("kconfiglint: error writing JSON: {e}");
                return ExitCode::from(2);
            }
        }
    }

    if error_count > 0 || warn_count > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn atty_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
}
