// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Discover all Kconfig files by following `source` directives from the root.
pub fn discover_kconfig_files(srctree: &Path) -> Vec<PathBuf> {
    let mut visited = HashSet::new();
    let mut result = Vec::new();
    let root = srctree.join("Kconfig");
    if root.is_file() {
        follow_kconfig_sources(srctree, &root, &mut visited, &mut result);
    }
    result
}

fn follow_kconfig_sources(
    srctree: &Path,
    file: &Path,
    visited: &mut HashSet<PathBuf>,
    result: &mut Vec<PathBuf>,
) {
    let canonical = match fs::canonicalize(file) {
        Ok(p) => p,
        Err(_) => return,
    };
    if !visited.insert(canonical.clone()) {
        return;
    }
    result.push(file.to_path_buf());

    let content = match fs::read_to_string(file) {
        Ok(c) => c,
        Err(_) => return,
    };

    let dir = file.parent().unwrap_or(srctree);

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("source") {
            let rest = rest.trim();
            // Remove quotes
            let path_str = rest
                .trim_start_matches('"')
                .trim_end_matches('"')
                .trim_start_matches('\'')
                .trim_end_matches('\'');
            if path_str.is_empty() || path_str.contains('$') {
                // Skip macro-based source paths — we can't resolve them without
                // evaluating the Kconfig macro system. Instead, fall back to
                // filesystem discovery for files we miss.
                continue;
            }
            let source_path = if path_str.starts_with('/') {
                PathBuf::from(path_str)
            } else {
                srctree.join(path_str)
            };
            // Handle glob-like patterns (e.g., source "arch/*/Kconfig") — rare
            // but used in some Kconfig files. For now, just try literal path.
            if source_path.is_file() {
                follow_kconfig_sources(srctree, &source_path, visited, result);
            } else if let Some(parent) = source_path.parent() {
                if let Some(filename) = source_path.file_name() {
                    let fname = filename.to_string_lossy();
                    if fname.contains('*') || fname.contains('?') {
                        // Basic glob: just scan directory
                        if let Ok(entries) = fs::read_dir(parent) {
                            for entry in entries.flatten() {
                                let p = entry.path();
                                if p.is_file() {
                                    let name = p.file_name().unwrap().to_string_lossy();
                                    if glob_match(&fname, &name) {
                                        follow_kconfig_sources(srctree, &p, visited, result);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Also look for sourced files relative to the file's own directory
    // (some Kconfig files use relative paths)
    let _ = dir;
}

/// Discover all Makefile and Kbuild files in the tree.
pub fn discover_makefile_files(srctree: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    walk_makefiles(srctree, &mut result);
    result
}

fn walk_makefiles(dir: &Path, result: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Kbuild takes precedence over Makefile for kbuild rules, but both
    // may contain CONFIG_ references. Parse both when they coexist.
    let kbuild = dir.join("Kbuild");
    let makefile = dir.join("Makefile");

    if kbuild.is_file() {
        result.push(kbuild);
        // Also parse the Makefile if it coexists (e.g., the top-level
        // Makefile contains include-$(CONFIG_*) lines not in Kbuild)
        if makefile.is_file() {
            result.push(makefile);
        }
    } else if makefile.is_file() {
        result.push(makefile);
    }

    // Also include scripts/Makefile.* files which contain CONFIG_ references
    // (e.g., scripts/Makefile.autofdo, scripts/Makefile.lib)
    if dir.ends_with("scripts") {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("Makefile.") && entry.path().is_file() {
                    result.push(entry.path());
                }
            }
        }
    }

    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Skip hidden dirs
            if name.starts_with('.') || name == "node_modules" {
                continue;
            }
            // Skip Cargo "target" directory only inside scripts/kconfiglint
            if name == "target" && dir.ends_with("scripts/kconfiglint") {
                continue;
            }
            subdirs.push(path);
        }
    }

    for subdir in subdirs {
        walk_makefiles(&subdir, result);
    }
}

/// Discover Kconfig files that exist on disk but were NOT reached via
/// the source chain. Used for the X006 (unreachable-kconfig-file) check.
pub fn discover_all_kconfig_files_on_disk(srctree: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    walk_kconfig_files(srctree, &mut result);
    result
}

fn walk_kconfig_files(dir: &Path, result: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || name == "node_modules" {
                continue;
            }
            if name == "target" && dir.ends_with("scripts/kconfiglint") {
                continue;
            }
            walk_kconfig_files(&path, result);
        } else if path.is_file() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "Kconfig"
                || name.starts_with("Kconfig.")
                || name.starts_with("Kconfig-")
            {
                result.push(path);
            }
        }
    }
}

/// Scan C, header, assembly, and Rust source files for CONFIG_ references.
/// Returns the set of symbol names (without the CONFIG_ prefix) found.
pub fn scan_source_config_refs(srctree: &Path) -> HashSet<String> {
    let mut refs = HashSet::new();
    scan_source_dir(srctree, srctree, &mut refs);
    refs
}

fn scan_source_dir(srctree: &Path, dir: &Path, refs: &mut HashSet<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Skip directories that won't contain kernel source
            if name.starts_with('.')
                || name == "node_modules"
                || (name == "target" && dir.ends_with("scripts/kconfiglint"))
            {
                continue;
            }
            scan_source_dir(srctree, &path, refs);
        } else if path.is_file() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".c")
                || name.ends_with(".h")
                || name.ends_with(".S")
                || name.ends_with(".rs")
                || name.ends_with(".dts")
                || name.ends_with(".dtsi")
            {
                scan_file_for_config_refs(&path, refs);
            }
        }
    }
}

fn scan_file_for_config_refs(path: &Path, refs: &mut HashSet<String>) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let bytes = content.as_bytes();
    let prefix = b"CONFIG_";
    let mut pos = 0;
    while pos + prefix.len() < bytes.len() {
        if let Some(idx) = content[pos..].find("CONFIG_") {
            let start = pos + idx + 7;
            let end = content[start..]
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .map(|i| start + i)
                .unwrap_or(content.len());
            if end > start {
                refs.insert(content[start..end].to_string());
            }
            pos = end;
        } else {
            break;
        }
    }
}

/// Minimal glob matching for Kconfig source directives.
fn glob_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return name.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return name.starts_with(prefix);
    }
    pattern == name
}
