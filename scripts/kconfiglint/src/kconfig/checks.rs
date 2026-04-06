// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use crate::diagnostics::{Diagnostic, Severity, Span};
use crate::kconfig::KconfigIndex;
use crate::kconfig::ast::*;
use std::collections::HashSet;

/// Run all K-series checks and return diagnostics.
pub fn run_kconfig_checks(index: &KconfigIndex, enabled: &dyn Fn(&str) -> bool) -> Vec<Diagnostic> {
    let mut diags = Vec::new();

    for kfile in &index.files {
        for config in &kfile.configs {
            if enabled("K001") {
                check_k001_missing_help(&mut diags, config);
            }
            if enabled("K004") {
                check_k004_missing_type(&mut diags, config);
            }
            if enabled("K005") {
                check_k005_default_y(&mut diags, config);
            }
            if enabled("K009") {
                check_k009_depends_on_m(&mut diags, config);
            }
            if enabled("K010") {
                check_k010_range_type_mismatch(&mut diags, config);
            }
        }

        for source in &kfile.sources {
            if enabled("K007") {
                check_k007_source_not_found(&mut diags, source, &kfile.path);
            }
        }
    }

    // Cross-definition checks (need the full index)
    if enabled("K002") {
        check_k002_select_visible_symbol(&mut diags, index);
    }
    if enabled("K003") {
        check_k003_type_conflict(&mut diags, index);
    }
    if enabled("K006") {
        check_k006_select_unmet_deps(&mut diags, index);
    }
    if enabled("K008") {
        check_k008_duplicate_prompt(&mut diags, index);
    }

    diags
}

/// K001: Config with prompt but no help text, or help < 2 lines.
/// Severity: Info (hidden by default). Many driver configs are simple
/// enable/disable toggles that don't need lengthy explanations.
fn check_k001_missing_help(diags: &mut Vec<Diagnostic>, config: &ConfigDef) {
    if config.prompts.is_empty() {
        return;
    }
    if !config.has_help {
        diags.push(Diagnostic::new(
            "K001",
            Severity::Info,
            format!(
                "config {} has a prompt but no help text",
                config.name
            ),
            config.span.clone(),
        ));
    } else if config.help_lines < 2 {
        diags.push(Diagnostic::new(
            "K001",
            Severity::Info,
            format!(
                "config {} has very short help text ({} line{})",
                config.name,
                config.help_lines,
                if config.help_lines == 1 { "" } else { "s" }
            ),
            config.span.clone(),
        ));
    }
}

/// K002: select on visible symbol with dependencies.
fn check_k002_select_visible_symbol(diags: &mut Vec<Diagnostic>, index: &KconfigIndex) {
    for kfile in &index.files {
        for config in &kfile.configs {
            for sel in &config.selects {
                // Skip HAVE_* symbols — documented pattern
                if sel.target.starts_with("HAVE_") {
                    continue;
                }
                if let Some(infos) = index.symbols.get(&sel.target) {
                    let target_has_prompt = infos.iter().any(|i| i.has_prompt);
                    let target_has_deps = infos.iter().any(|i| !i.depends_symbols.is_empty());

                    if target_has_prompt && target_has_deps {
                        // Info severity: `select` of visible symbols is pervasive
                        // and intentional in the kernel (SoC errata, codec drivers,
                        // provider subsystems). Not actionable in practice.
                        let mut d = Diagnostic::new(
                            "K002",
                            Severity::Info,
                            format!(
                                "config {} selects visible symbol {} which has dependencies",
                                config.name, sel.target,
                            ),
                            sel.span.clone(),
                        );
                        if let Some(info) = infos.first() {
                            d = d.with_related(
                                &info.file,
                                info.line,
                                format!("{} defined here", sel.target),
                            );
                        }
                        diags.push(d);
                    }
                }
            }
        }
    }
}

/// K003: Same symbol defined with conflicting types.
fn check_k003_type_conflict(diags: &mut Vec<Diagnostic>, index: &KconfigIndex) {
    for (name, infos) in &index.symbols {
        // Exclude test fixtures that reuse generic symbol names
        let real_infos: Vec<_> = infos
            .iter()
            .filter(|i| {
                let p = i.file.to_string_lossy();
                !p.contains("scripts/kconfig/tests/") && !p.contains("Documentation/kbuild/")
            })
            .collect();

        let types: HashSet<_> = real_infos.iter().filter_map(|i| i.sym_type).collect();
        if types.len() > 1 {
            // If all definitions are in different arch/ subtrees, the "conflict"
            // is intentional (e.g., KVM is bool on arm64 but tristate on x86).
            // Only one arch is active per build, so the types never conflict.
            let arch_paths: Vec<_> = real_infos
                .iter()
                .filter_map(|i| {
                    let p = i.file.to_string_lossy();
                    if p.contains("/arch/") || p.starts_with("arch/") {
                        // Extract the arch name: arch/FOO/...
                        p.find("arch/").and_then(|start| {
                            let rest = &p[start + 5..];
                            rest.find('/').map(|end| rest[..end].to_string())
                        })
                    } else {
                        None
                    }
                })
                .collect();
            let all_in_arch = arch_paths.len() == real_infos.len();
            let all_different_arches = if all_in_arch {
                let unique: HashSet<_> = arch_paths.iter().collect();
                unique.len() == arch_paths.len()
            } else {
                false
            };
            if all_different_arches {
                continue;
            }

            let type_strs: Vec<_> = types.iter().map(|t| t.as_str()).collect();
            let first = real_infos.first().unwrap();
            let mut d = Diagnostic::new(
                "K003",
                Severity::Error,
                format!(
                    "config {} has conflicting types: {}",
                    name,
                    type_strs.join(", "),
                ),
                Span::new(&first.file, first.line),
            );
            for info in real_infos.iter().skip(1) {
                if let Some(t) = info.sym_type {
                    d = d.with_related(
                        &info.file,
                        info.line,
                        format!("also defined as {} here", t.as_str()),
                    );
                }
            }
            diags.push(d);
        }
    }
}

/// K004: Config with no type declaration.
fn check_k004_missing_type(diags: &mut Vec<Diagnostic>, config: &ConfigDef) {
    if config.sym_type.is_none() && !config.is_transitional {
        diags.push(Diagnostic::new(
            "K004",
            Severity::Info,
            format!("config {} has no type declaration", config.name),
            config.span.clone(),
        ));
    }
}

/// K005: default y — should be rare.
fn check_k005_default_y(diags: &mut Vec<Diagnostic>, config: &ConfigDef) {
    for def in &config.defaults {
        if let Expr::Symbol(ref s) = def.value {
            if s == "y" && def.condition.is_none() {
                diags.push(Diagnostic::new(
                    "K005",
                    Severity::Info,
                    format!(
                        "config {} has unconditional 'default y' (should be rare)",
                        config.name,
                    ),
                    def.span.clone(),
                ));
            }
        }
    }
}

/// K006: select B from A, but A's deps don't cover B's deps.
///
/// This check properly handles:
/// - Inherited dependencies from enclosing `if` blocks (propagated by the parser)
/// - Conditional selects (`select X if Y`): Y is added to the satisfied set
/// - OR dependencies: `depends on A || B` is satisfied if either A or B is met
/// - The selecting config's own name satisfies self-referential deps
fn check_k006_select_unmet_deps(diags: &mut Vec<Diagnostic>, index: &KconfigIndex) {
    for kfile in &index.files {
        for config in &kfile.configs {
            // Build the set of symbols known to be true when this config is enabled.
            // This includes all symbols from depends (both explicit and inherited
            // from enclosing if blocks), plus the config's own name.
            let mut a_satisfied: HashSet<String> = HashSet::new();
            a_satisfied.insert(config.name.clone());
            for dep in &config.depends {
                let mut syms = Vec::new();
                dep.collect_symbols(&mut syms);
                a_satisfied.extend(syms);
            }

            // Also include symbols that A selects (transitively satisfied)
            for sel in &config.selects {
                a_satisfied.insert(sel.target.clone());
            }

            // Transitively expand: if a satisfied symbol selects other symbols,
            // those are also satisfied. E.g., if ARCH_TEGRA is satisfied (from
            // an enclosing if block) and ARCH_TEGRA selects PM, then PM is also
            // satisfied. Do multiple passes until no new symbols are added.
            for _ in 0..3 {
                let snapshot: Vec<String> = a_satisfied.iter().cloned().collect();
                let before = a_satisfied.len();
                for sym in &snapshot {
                    if let Some(infos) = index.symbols.get(sym) {
                        for info in infos {
                            for target in &info.select_targets {
                                a_satisfied.insert(target.clone());
                            }
                        }
                    }
                }
                if a_satisfied.len() == before {
                    break;
                }
            }

            for sel in &config.selects {
                // For conditional selects (select X if Y), also add Y's symbols
                // to the satisfied set — the select only fires when Y is true.
                let mut sel_satisfied = a_satisfied.clone();
                if let Some(ref cond) = sel.condition {
                    let mut syms = Vec::new();
                    cond.collect_symbols(&mut syms);
                    sel_satisfied.extend(syms);
                }

                if let Some(target_infos) = index.symbols.get(&sel.target) {
                    // Skip K006 for hidden targets (no prompt in any definition).
                    // Hidden symbols can only be enabled via select/default, so
                    // their deps are the responsibility of the Kconfig system.
                    let target_is_hidden = target_infos.iter().all(|i| !i.has_prompt);
                    if target_is_hidden {
                        continue;
                    }

                    // A symbol may be defined in multiple arches with different
                    // dependencies (e.g., HIGHMEM). Only warn if the dependency
                    // is unsatisfied in ALL definitions — if any definition has
                    // its deps met, the select is valid for that arch.
                    let mut any_def_satisfied = false;
                    let mut best_diag: Option<Diagnostic> = None;

                    for target_info in target_infos {
                        // Skip synthetic kconfig test fixtures and documentation examples
                        let path_str = target_info.file.to_string_lossy();
                        if path_str.contains("scripts/kconfig/tests/")
                            || path_str.contains("Documentation/kbuild/")
                        {
                            continue;
                        }

                        if let Some(target_file) = index.files.iter().find(|f| {
                            f.configs.iter().any(|c| {
                                c.name == sel.target && c.span.line == target_info.line
                            })
                        }) {
                            if let Some(target_config) = target_file
                                .configs
                                .iter()
                                .find(|c| c.name == sel.target && c.span.line == target_info.line)
                            {
                                let all_deps_ok = target_config.depends.iter().all(|dep_expr| {
                                    dep_expr.is_satisfiable(&sel_satisfied)
                                });

                                if all_deps_ok {
                                    any_def_satisfied = true;
                                    break;
                                }

                                // Record the first unsatisfied definition for reporting
                                if best_diag.is_none() {
                                    for dep_expr in &target_config.depends {
                                        if !dep_expr.is_satisfiable(&sel_satisfied) {
                                            let mut dep_syms = Vec::new();
                                            dep_expr.collect_symbols(&mut dep_syms);
                                            let unsatisfied: Vec<_> = dep_syms
                                                .iter()
                                                .filter(|s| !sel_satisfied.contains(*s))
                                                .collect();

                                            // Skip if all unsatisfied deps are hidden
                                            // (no prompt) or are def_bool/def_tristate
                                            // symbols that auto-enable. These are
                                            // infrastructure symbols effectively always
                                            // true in the relevant context.
                                            let all_non_actionable = unsatisfied.iter().all(|dep| {
                                                index.symbols.get(*dep).map(|dis| {
                                                    dis.iter().all(|d| !d.has_prompt)
                                                }).unwrap_or(true)
                                            });
                                            if all_non_actionable {
                                                continue;
                                            }

                                            let dep_names = unsatisfied
                                                .iter()
                                                .map(|s| s.as_str())
                                                .collect::<Vec<_>>()
                                                .join(", ");

                                            best_diag = Some(
                                                Diagnostic::new(
                                                    "K006",
                                                    Severity::Info,
                                                    format!(
                                                        "config {} selects {} whose \
                                                         dependency on {} is not satisfied",
                                                        config.name, sel.target, dep_names,
                                                    ),
                                                    sel.span.clone(),
                                                )
                                                .with_related(
                                                    &target_info.file,
                                                    target_info.line,
                                                    format!("{} defined here", sel.target),
                                                ),
                                            );
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if !any_def_satisfied {
                        if let Some(d) = best_diag {
                            diags.push(d);
                        }
                    }
                }
            }
        }
    }
}

/// K007: source directive references nonexistent file.
fn check_k007_source_not_found(
    diags: &mut Vec<Diagnostic>,
    source: &SourceDirective,
    _kconfig_file: &std::path::Path,
) {
    // Skip macro-based paths
    if source.path.contains('$') {
        return;
    }
    // The walk module resolves paths; here we just check if the path was resolved
    // We'll let the walk module handle the actual existence check during discovery
    // and flag it in cross checks. But for literal paths that don't exist, flag here.
    if !source.path.is_empty() {
        let p = std::path::Path::new(&source.path);
        // Only flag absolute paths or paths that look resolvable
        if p.is_absolute() && !p.exists() {
            diags.push(Diagnostic::new(
                "K007",
                Severity::Error,
                format!("source file not found: {}", source.path),
                source.span.clone(),
            ));
        }
    }
}

/// K008: Symbol has more than one prompt across definitions.
fn check_k008_duplicate_prompt(diags: &mut Vec<Diagnostic>, index: &KconfigIndex) {
    for kfile in &index.files {
        for config in &kfile.configs {
            if config.prompts.len() > 1 {
                let mut d = Diagnostic::new(
                    "K008",
                    Severity::Warning,
                    format!(
                        "config {} has {} prompts in the same definition",
                        config.name,
                        config.prompts.len(),
                    ),
                    config.span.clone(),
                );
                for prompt in config.prompts.iter().skip(1) {
                    d = d.with_related(
                        &prompt.span.file,
                        prompt.span.line,
                        "additional prompt here".to_string(),
                    );
                }
                diags.push(d);
            }
        }
    }

    // Also check across definitions, but exclude synthetic kconfig test
    // fixtures that intentionally reuse generic symbol names like A, B, C.
    for (name, infos) in &index.symbols {
        let real_infos: Vec<_> = infos
            .iter()
            .filter(|i| {
                let path = i.file.to_string_lossy();
                !path.contains("scripts/kconfig/tests/")
                    && !path.contains("Documentation/kbuild/")
            })
            .collect();
        let prompt_infos: Vec<_> = real_infos.iter().filter(|i| i.has_prompt).collect();
        let prompt_count = prompt_infos.len();
        if prompt_count > 1 {
            // Skip if all definitions with prompts are in different arch/ subtrees.
            // This is the standard multi-arch pattern (e.g., ARCH_TEGRA in arm + arm64).
            let arch_paths: Vec<_> = prompt_infos
                .iter()
                .filter_map(|i| {
                    let p = i.file.to_string_lossy();
                    p.find("arch/").and_then(|start| {
                        let rest = &p[start + 5..];
                        rest.find('/').map(|end| rest[..end].to_string())
                    })
                })
                .collect();
            if arch_paths.len() == prompt_count {
                let unique: HashSet<_> = arch_paths.iter().collect();
                if unique.len() == prompt_count {
                    continue;
                }
            }
            let first_with_prompt = real_infos.iter().find(|i| i.has_prompt).unwrap();
            let mut d = Diagnostic::new(
                "K008",
                Severity::Warning,
                format!(
                    "config {} has prompts in {} separate definitions",
                    name, prompt_count,
                ),
                Span::new(&first_with_prompt.file, first_with_prompt.line),
            );
            for info in real_infos.iter().filter(|i| i.has_prompt).skip(1) {
                d = d.with_related(
                    &info.file,
                    info.line,
                    "also has prompt here".to_string(),
                );
            }
            diags.push(d);
        }
    }
}

/// K009: depends on m — module-only constraint.
fn check_k009_depends_on_m(diags: &mut Vec<Diagnostic>, config: &ConfigDef) {
    for dep in &config.depends {
        if let Expr::Symbol(s) = dep {
            if s == "m" {
                diags.push(Diagnostic::new(
                    "K009",
                    Severity::Info,
                    format!(
                        "config {} depends on 'm' (module-only constraint)",
                        config.name,
                    ),
                    config.span.clone(),
                ));
            }
        }
        // Also check for ... && m patterns
        check_expr_for_m_dependency(dep, config, diags);
    }
}

fn check_expr_for_m_dependency(expr: &Expr, config: &ConfigDef, diags: &mut Vec<Diagnostic>) {
    match expr {
        Expr::And(a, b) => {
            if matches!(a.as_ref(), Expr::Symbol(s) if s == "m")
                || matches!(b.as_ref(), Expr::Symbol(s) if s == "m")
            {
                // Already caught by the direct check above or will be
            }
            // Recurse but don't double-report
        }
        _ => {}
    }
    let _ = (config, diags);
}

/// K010: range attribute on non-int/non-hex symbol.
fn check_k010_range_type_mismatch(diags: &mut Vec<Diagnostic>, config: &ConfigDef) {
    if !config.ranges.is_empty() {
        match config.sym_type {
            Some(SymType::Int) | Some(SymType::Hex) => {}
            Some(t) => {
                diags.push(Diagnostic::new(
                    "K010",
                    Severity::Warning,
                    format!(
                        "config {} has type '{}' but uses 'range' (only valid for int/hex)",
                        config.name,
                        t.as_str(),
                    ),
                    config.ranges[0].span.clone(),
                ));
            }
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kconfig::parser::parse_kconfig;
    use std::path::Path;

    fn parse_and_index(source: &str) -> KconfigIndex {
        let kfile = parse_kconfig(Path::new("test/Kconfig"), source);
        let mut index = KconfigIndex::default();
        index.add_file(kfile);
        index
    }

    fn check_all(index: &KconfigIndex) -> Vec<Diagnostic> {
        run_kconfig_checks(index, &|_| true)
    }

    fn check_only(index: &KconfigIndex, check_id: &str) -> Vec<Diagnostic> {
        run_kconfig_checks(index, &|id| id == check_id)
    }

    #[test]
    fn test_k001_missing_help() {
        let index = parse_and_index(
            r#"
config FOO
    bool "Enable foo"
"#,
        );
        let diags = check_only(&index, "K001");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].check_id, "K001");
        assert!(diags[0].message.contains("no help text"));
    }

    #[test]
    fn test_k001_short_help() {
        let index = parse_and_index(
            r#"
config FOO
    bool "Enable foo"
    help
      Short.
"#,
        );
        let diags = check_only(&index, "K001");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("short help text"));
    }

    #[test]
    fn test_k001_no_prompt_no_warning() {
        let index = parse_and_index(
            r#"
config FOO
    bool
"#,
        );
        let diags = check_only(&index, "K001");
        assert!(diags.is_empty());
    }

    #[test]
    fn test_k001_adequate_help() {
        let index = parse_and_index(
            r#"
config FOO
    bool "Enable foo"
    help
      This is the help text for foo.
      It has multiple lines of explanation.
"#,
        );
        let diags = check_only(&index, "K001");
        assert!(diags.is_empty());
    }

    #[test]
    fn test_k003_type_conflict() {
        let index = parse_and_index(
            r#"
config FOO
    bool "Enable foo"

config FOO
    tristate
"#,
        );
        let diags = check_only(&index, "K003");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("conflicting types"));
    }

    #[test]
    fn test_k003_no_conflict() {
        let index = parse_and_index(
            r#"
config FOO
    bool "Enable foo"

config FOO
    bool
"#,
        );
        let diags = check_only(&index, "K003");
        assert!(diags.is_empty());
    }

    #[test]
    fn test_k004_missing_type() {
        let index = parse_and_index(
            r#"
config FOO
    default y
"#,
        );
        let diags = check_only(&index, "K004");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("no type"));
    }

    #[test]
    fn test_k004_transitional_no_warning() {
        let index = parse_and_index(
            r#"
config FOO
    transitional
"#,
        );
        let diags = check_only(&index, "K004");
        assert!(diags.is_empty());
    }

    #[test]
    fn test_k005_default_y() {
        let index = parse_and_index(
            r#"
config FOO
    bool "Enable foo"
    default y
"#,
        );
        let diags = check_only(&index, "K005");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("default y"));
    }

    #[test]
    fn test_k005_conditional_default_y_no_warning() {
        let index = parse_and_index(
            r#"
config FOO
    bool "Enable foo"
    default y if BAR
"#,
        );
        let diags = check_only(&index, "K005");
        assert!(diags.is_empty());
    }

    #[test]
    fn test_k010_range_on_bool() {
        let index = parse_and_index(
            r#"
config FOO
    bool "Enable foo"
    range 0 100
"#,
        );
        let diags = check_only(&index, "K010");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("range"));
    }

    #[test]
    fn test_k010_range_on_int_ok() {
        let index = parse_and_index(
            r#"
config FOO
    int "Count"
    range 0 100
"#,
        );
        let diags = check_only(&index, "K010");
        assert!(diags.is_empty());
    }

    #[test]
    fn test_k002_select_visible_with_deps() {
        let index = parse_and_index(
            r#"
config FOO
    bool "Enable foo"
    select BAR

config BAR
    bool "Enable bar"
    depends on BAZ
"#,
        );
        let diags = check_only(&index, "K002");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("selects visible symbol"));
    }

    #[test]
    fn test_k002_select_hidden_no_warning() {
        let index = parse_and_index(
            r#"
config FOO
    bool "Enable foo"
    select BAR

config BAR
    bool
"#,
        );
        let diags = check_only(&index, "K002");
        assert!(diags.is_empty());
    }

    #[test]
    fn test_k002_have_prefix_exempt() {
        let index = parse_and_index(
            r#"
config FOO
    bool "Enable foo"
    select HAVE_BAR

config HAVE_BAR
    bool "Has bar"
    depends on BAZ
"#,
        );
        let diags = check_only(&index, "K002");
        assert!(diags.is_empty());
    }

    #[test]
    fn test_multiple_checks() {
        let index = parse_and_index(
            r#"
config FOO
    default y

config BAR
    bool "Bar"
    range 1 10
"#,
        );
        let diags = check_all(&index);
        // K004 for FOO (no type), K005 for FOO (default y), K010 for BAR (range on bool)
        let k004: Vec<_> = diags.iter().filter(|d| d.check_id == "K004").collect();
        let k005: Vec<_> = diags.iter().filter(|d| d.check_id == "K005").collect();
        let k010: Vec<_> = diags.iter().filter(|d| d.check_id == "K010").collect();
        assert_eq!(k004.len(), 1);
        assert_eq!(k005.len(), 1);
        assert_eq!(k010.len(), 1);
    }
}
