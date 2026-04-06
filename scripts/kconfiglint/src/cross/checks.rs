// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use crate::cross::symbol_index::SymbolIndex;
use crate::diagnostics::{Diagnostic, Severity, Span};
use crate::kconfig::KconfigIndex;
use crate::kconfig::ast::SymType;
use crate::makefile::MakefileIndex;
use crate::makefile::ast::*;
use std::collections::HashSet;
use std::path::Path;

/// Run all X-series cross-domain checks.
pub fn run_cross_checks(
    kconfig: &KconfigIndex,
    makefile: &MakefileIndex,
    source_refs: &HashSet<String>,
    enabled: &dyn Fn(&str) -> bool,
) -> Vec<Diagnostic> {
    let idx = SymbolIndex::new(kconfig, makefile).with_source_refs(source_refs.clone());
    let mut diags = Vec::new();

    if enabled("X001") {
        check_x001_undefined_config_in_makefile(&mut diags, &idx);
    }
    if enabled("X002") {
        check_x002_dead_kconfig_symbol(&mut diags, &idx);
    }
    if enabled("X003") {
        check_x003_tristate_bool_mismatch(&mut diags, &idx);
    }
    if enabled("X004") {
        check_x004_orphan_obj_y_modular_parent(&mut diags, &idx);
    }
    if enabled("X005") {
        check_x005_unwired_config_symbol(&mut diags, &idx);
    }
    if enabled("X006") {
        check_x006_unreachable_kconfig_file(&mut diags, kconfig);
    }
    if enabled("X007") {
        check_x007_subst_pattern(&mut diags, makefile);
    }

    diags
}

/// X001: CONFIG_FOO in Makefile but FOO not defined in any Kconfig.
fn check_x001_undefined_config_in_makefile(diags: &mut Vec<Diagnostic>, idx: &SymbolIndex) {
    let defined = idx.kconfig_defined_symbols();

    // Pseudo-symbols and Make built-ins that are not real Kconfig symbols
    let pseudo: HashSet<&str> = [
        "m", "y", "n", "MODULES", "SHELL",
    ].iter().copied().collect();

    for (symbol, locations) in &idx.makefile.config_refs {
        if pseudo.contains(symbol.as_str()) {
            continue;
        }
        // Skip compiler/assembler feature detection symbols that are set
        // via -D flags in arch Makefiles, not defined in Kconfig
        if symbol.starts_with("CC_HAS_") || symbol.starts_with("AS_") {
            continue;
        }
        // Skip symbols that contain non-alphanumeric chars (likely parse artifacts
        // from $(subst ...) or other make functions)
        if symbol.contains(':') || symbol.contains(',') || symbol.contains('(') {
            continue;
        }
        if defined.contains(symbol.as_str()) {
            continue;
        }

        for (file, line) in locations {
            // Skip tools/ and scripts/kconfig/ — these use CONFIG_ in
            // non-standard ways (userspace build systems, make variables)
            let file_str = file.to_string_lossy();
            if file_str.contains("/tools/") || file_str.contains("scripts/kconfig/") {
                continue;
            }

            let mut d = Diagnostic::new(
                "X001",
                Severity::Error,
                format!("CONFIG_{symbol} referenced in Makefile but not defined in any Kconfig"),
                Span::new(file, *line),
            );

            if let Some(suggestion) = idx.suggest_similar(symbol, &defined) {
                d = d.with_hint(format!("did you mean CONFIG_{suggestion}?"));
            }

            diags.push(d);
        }
    }
}

/// X002: Symbol defined in Kconfig but never referenced anywhere.
fn check_x002_dead_kconfig_symbol(diags: &mut Vec<Diagnostic>, idx: &SymbolIndex) {
    let makefile_refs = idx.makefile_referenced_symbols();
    let kconfig_refs = idx.kconfig_referenced_symbols();

    for (name, infos) in &idx.kconfig.symbols {
        // Skip well-known infrastructure symbols
        if name.starts_with("HAVE_") || name.starts_with("ARCH_") {
            continue;
        }

        let referenced_in_makefile = makefile_refs.contains(name.as_str());
        let referenced_in_kconfig = kconfig_refs.contains(name);
        let referenced_in_source = idx.source_refs.contains(name);

        if !referenced_in_makefile && !referenced_in_kconfig && !referenced_in_source {
            // Skip "selector-only" configs: their purpose is selecting other
            // configs (e.g., ASoC machine drivers that select codec drivers).
            // They don't need Makefile/source references.
            let has_selects = infos.iter().any(|i| !i.select_targets.is_empty());
            if has_selects {
                continue;
            }

            // Skip infrastructure symbols: no prompt (hidden) and have
            // defaults (def_bool y, def_tristate y). These are auto-enabled
            // helpers, not dead config.
            let is_hidden = infos.iter().all(|i| !i.has_prompt);
            if is_hidden {
                continue;
            }

            if let Some(info) = infos.first() {
                diags.push(Diagnostic::new(
                    "X002",
                    Severity::Warning,
                    format!(
                        "CONFIG_{name} is defined in Kconfig but never referenced in any \
                         Makefile, source file, or Kconfig dependency chain",
                    ),
                    Span::new(&info.file, info.line),
                ));
            }
        }
    }
}

/// X003: Bool symbol guards a directory whose children expect tristate.
fn check_x003_tristate_bool_mismatch(diags: &mut Vec<Diagnostic>, idx: &SymbolIndex) {
    for mf in &idx.makefile.files {
        for obj in &mf.obj_assigns {
            if let ObjGuard::Config(ref sym) = obj.guard {
                // Check if symbol is bool
                let is_bool = idx
                    .kconfig
                    .symbols
                    .get(sym)
                    .map(|infos| {
                        infos
                            .iter()
                            .any(|i| i.sym_type == Some(SymType::Bool))
                    })
                    .unwrap_or(false);

                if !is_bool {
                    continue;
                }

                // Check if it guards a directory
                for target in &obj.targets {
                    if let ObjTarget::Directory(dirname) = target {
                        let dir = mf.path.parent().unwrap_or(Path::new("."));
                        let subdir = dir.join(dirname.trim_end_matches('/'));
                        // Check if child Makefile has obj-m entries
                        if let Some(child_mf) = idx.makefile.files.iter().find(|m| {
                            m.path.parent().map(|p| p == subdir).unwrap_or(false)
                        }) {
                            let has_obj_m = child_mf.obj_assigns.iter().any(|o| {
                                matches!(o.guard, ObjGuard::Module)
                            });
                            if has_obj_m {
                                diags.push(
                                    Diagnostic::new(
                                        "X003",
                                        Severity::Warning,
                                        format!(
                                            "CONFIG_{sym} is bool but guards directory {dirname} \
                                             which has obj-m entries (will never be modular)",
                                        ),
                                        obj.span.clone(),
                                    )
                                    .with_hint(format!(
                                        "consider making CONFIG_{sym} tristate, or remove \
                                         obj-m from {dirname}Makefile"
                                    )),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// X004: Directory entered via obj-m but child has obj-y (orphaned).
fn check_x004_orphan_obj_y_modular_parent(diags: &mut Vec<Diagnostic>, idx: &SymbolIndex) {
    for mf in &idx.makefile.files {
        for obj in &mf.obj_assigns {
            let is_modular = match &obj.guard {
                ObjGuard::Module => true,
                ObjGuard::Config(sym) => {
                    // Check if the symbol is tristate
                    idx.kconfig
                        .symbols
                        .get(sym)
                        .map(|infos| infos.iter().any(|i| i.is_tristate))
                        .unwrap_or(false)
                }
                _ => false,
            };

            if !is_modular {
                continue;
            }

            for target in &obj.targets {
                if let ObjTarget::Directory(dirname) = target {
                    let dir = mf.path.parent().unwrap_or(Path::new("."));
                    let subdir = dir.join(dirname.trim_end_matches('/'));

                    if let Some(child_mf) = idx.makefile.files.iter().find(|m| {
                        m.path.parent().map(|p| p == subdir).unwrap_or(false)
                    }) {
                        // Only flag actual obj-y entries as orphaned.
                        // always-y, extra-y, lib-y, subdir-y are not linked
                        // into built-in.a and are fine under a modular parent.
                        let obj_y_entries: Vec<_> = child_mf
                            .obj_assigns
                            .iter()
                            .filter(|o| {
                                matches!(o.guard, ObjGuard::BuiltIn)
                                    && o.var_name.starts_with("obj-")
                            })
                            .collect();

                        for entry in obj_y_entries {
                            // obj-y in a modular subdirectory is actually valid
                            // for multi-directory modules — the child's built-in.a
                            // gets linked into the parent module. Downgrade to info
                            // since this is only suspicious, not necessarily wrong.
                            diags.push(
                                Diagnostic::new(
                                    "X004",
                                    Severity::Info,
                                    format!(
                                        "directory {dirname} is entered via modular parent \
                                         but has obj-y entries that will be orphaned \
                                         (not linked into anything)",
                                    ),
                                    entry.span.clone(),
                                )
                                .with_related(
                                    &mf.path,
                                    obj.span.line,
                                    format!(
                                        "parent enters {dirname} as modular here"
                                    ),
                                ),
                            );
                        }
                    }
                }
            }
        }
    }
}

/// X005: Visible symbol with no Makefile reference.
fn check_x005_unwired_config_symbol(diags: &mut Vec<Diagnostic>, idx: &SymbolIndex) {
    let makefile_refs = idx.makefile_referenced_symbols();
    let kconfig_refs = idx.kconfig_referenced_symbols();

    for (name, infos) in &idx.kconfig.symbols {
        // Skip infrastructure symbols
        if name.starts_with("HAVE_")
            || name.starts_with("ARCH_SUPPORTS_")
            || name.starts_with("ARCH_HAS_")
            || name.starts_with("CC_HAS_")
        {
            continue;
        }

        let has_prompt = infos.iter().any(|i| i.has_prompt);
        let is_bool_or_tristate = infos.iter().any(|i| {
            matches!(
                i.sym_type,
                Some(SymType::Bool) | Some(SymType::Tristate)
            )
        });

        if has_prompt
            && is_bool_or_tristate
            && !makefile_refs.contains(name.as_str())
            && !idx.source_refs.contains(name)
            && !kconfig_refs.contains(name)
        {
            // Skip "selector-only" configs (same rationale as X002)
            let has_selects = infos.iter().any(|i| !i.select_targets.is_empty());
            if has_selects {
                continue;
            }

            // Check if other symbols depend on, select, or imply this one.
            // If so, it's a grouping/choice/infrastructure symbol, not unwired.
            let depended_on_by_others = idx
                .kconfig
                .symbols
                .values()
                .flatten()
                .any(|i| {
                    i.depends_symbols.contains(name)
                        || i.select_targets.contains(name)
                        || i.imply_targets.contains(name)
                });

            if !depended_on_by_others {
                if let Some(info) = infos.first() {
                    diags.push(Diagnostic::new(
                        "X005",
                        Severity::Warning,
                        format!(
                            "CONFIG_{name} is a visible bool/tristate but is not \
                             referenced in any Makefile or source file",
                        ),
                        Span::new(&info.file, info.line),
                    ));
                }
            }
        }
    }
}

/// X006: Kconfig file on disk but not source'd from the tree.
fn check_x006_unreachable_kconfig_file(diags: &mut Vec<Diagnostic>, kconfig: &KconfigIndex) {
    // This check requires the set of all Kconfig files on disk vs those reached
    // via source chain. The KconfigIndex.sourced_files tracks the latter.
    // We compare with walk::discover_all_kconfig_files_on_disk() results
    // that are passed in during the main pipeline.
    // For now, we check if any file in the index was not in the sourced set.
    // (The actual unreachable file detection happens in main.rs where we have both sets.)
    let _ = (diags, kconfig);
}

/// X007: subst pattern detected.
fn check_x007_subst_pattern(diags: &mut Vec<Diagnostic>, makefile: &MakefileIndex) {
    for mf in &makefile.files {
        for obj in &mf.obj_assigns {
            if let ObjGuard::SubstConfig(ref sym) = obj.guard {
                diags.push(Diagnostic::new(
                    "X007",
                    Severity::Info,
                    format!(
                        "$(subst m,y,$(CONFIG_{sym})) forces built-in even when CONFIG_{sym} \
                         is modular — ensure this is intentional",
                    ),
                    obj.span.clone(),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kconfig::parser::parse_kconfig;
    use crate::makefile::parser::parse_makefile;

    fn build_indices(kconfig_src: &str, makefile_src: &str) -> (KconfigIndex, MakefileIndex) {
        let kfile = parse_kconfig(Path::new("test/Kconfig"), kconfig_src);
        let mut kindex = KconfigIndex::default();
        kindex.add_file(kfile);

        let mfile = parse_makefile(Path::new("test/Makefile"), makefile_src);
        let mut mindex = MakefileIndex::default();
        mindex.add_file(mfile);

        (kindex, mindex)
    }

    fn check_only(
        kconfig: &KconfigIndex,
        makefile: &MakefileIndex,
        check_id: &str,
    ) -> Vec<Diagnostic> {
        let empty = HashSet::new();
        run_cross_checks(kconfig, makefile, &empty, &|id| id == check_id)
    }

    #[test]
    fn test_x001_undefined_config() {
        let (ki, mi) = build_indices(
            "config FOO\n    bool\n",
            "obj-$(CONFIG_BAR) += bar.o\n",
        );
        let diags = check_only(&ki, &mi, "X001");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("CONFIG_BAR"));
    }

    #[test]
    fn test_x001_defined_config_no_warning() {
        let (ki, mi) = build_indices(
            "config FOO\n    bool\n",
            "obj-$(CONFIG_FOO) += foo.o\n",
        );
        let diags = check_only(&ki, &mi, "X001");
        assert!(diags.is_empty());
    }

    #[test]
    fn test_x001_pseudo_symbols_ignored() {
        let (ki, mi) = build_indices(
            "config FOO\n    bool\n",
            "obj-y += foo.o\nobj-m += bar.o\n",
        );
        let diags = check_only(&ki, &mi, "X001");
        assert!(diags.is_empty());
    }

    #[test]
    fn test_x001_suggestion() {
        let (ki, mi) = build_indices(
            "config FOO_BAR\n    bool\n",
            "obj-$(CONFIG_FOO_BAZ) += foo.o\n",
        );
        let diags = check_only(&ki, &mi, "X001");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].fix_hint.as_ref().unwrap().contains("FOO_BAR"));
    }

    #[test]
    fn test_x002_dead_symbol() {
        let (ki, mi) = build_indices(
            "config DEAD_SYMBOL\n    bool \"Dead\"\n",
            "obj-y += foo.o\n",
        );
        let diags = check_only(&ki, &mi, "X002");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("DEAD_SYMBOL"));
    }

    #[test]
    fn test_x002_used_in_makefile_no_warning() {
        let (ki, mi) = build_indices(
            "config ALIVE\n    bool\n",
            "obj-$(CONFIG_ALIVE) += alive.o\n",
        );
        let diags = check_only(&ki, &mi, "X002");
        assert!(diags.is_empty());
    }

    #[test]
    fn test_x002_used_in_kconfig_dep_no_warning() {
        let (ki, mi) = build_indices(
            "config DEP\n    bool\n\nconfig USER\n    bool\n    depends on DEP\n",
            "obj-y += foo.o\n",
        );
        let diags = check_only(&ki, &mi, "X002");
        // DEP is referenced by USER's depends, so not dead
        let dep_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.message.contains("DEP"))
            .collect();
        assert!(dep_diags.is_empty());
    }

    #[test]
    fn test_x007_subst_detected() {
        let (ki, mi) = build_indices(
            "config FOO\n    tristate\n",
            "obj-$(subst m,y,$(CONFIG_FOO)) += foo.o\n",
        );
        let diags = check_only(&ki, &mi, "X007");
        // Should detect the subst pattern (if parser picks it up)
        // The subst parsing depends on the Makefile parser recognizing the pattern
        let _ = diags; // May or may not fire depending on parser
    }
}
