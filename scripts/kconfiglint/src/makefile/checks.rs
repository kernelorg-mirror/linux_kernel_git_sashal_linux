// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use crate::diagnostics::{Diagnostic, Severity};
use crate::makefile::MakefileIndex;
use crate::makefile::ast::*;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Run all M-series checks.
pub fn run_makefile_checks(
    index: &MakefileIndex,
    enabled: &dyn Fn(&str) -> bool,
) -> Vec<Diagnostic> {
    let mut diags = Vec::new();

    for mf in &index.files {
        let dir = mf.path.parent().unwrap_or(Path::new("."));

        if enabled("M001") {
            check_m001_source_file_missing(&mut diags, mf, dir);
        }
        if enabled("M002") {
            check_m002_orphan_composite(&mut diags, mf);
        }
        if enabled("M003") {
            check_m003_directory_missing(&mut diags, mf, dir);
        }
        if enabled("M004") {
            check_m004_overwritten_assignment(&mut diags, mf);
        }
        if enabled("M006") {
            check_m006_trailing_slash_missing(&mut diags, mf, dir);
        }
        if enabled("M007") {
            check_m007_duplicate_obj(&mut diags, mf);
        }
        if enabled("M008") {
            check_m008_composite_source_missing(&mut diags, mf, dir);
        }
    }

    diags
}

/// M001: obj-* += foo.o but no foo.c/.S/.rs and no composite definition.
fn check_m001_source_file_missing(
    diags: &mut Vec<Diagnostic>,
    mf: &KbuildMakefile,
    dir: &Path,
) {
    let composite_names: HashSet<&str> = mf
        .comp_assigns
        .iter()
        .map(|c| c.module_name.as_str())
        .collect();

    for obj in &mf.obj_assigns {
        // Only check obj and lib variables
        let var_base = obj.var_name.split('-').next().unwrap_or("");
        if var_base != "obj" && var_base != "lib" {
            continue;
        }

        for target in &obj.targets {
            if let ObjTarget::Object(name) = target {
                // Skip targets containing unexpanded Make variables
                if name.contains('$') {
                    continue;
                }
                if let Some(stem) = name.strip_suffix(".o") {
                    // Check if composite module (both -y and -objs patterns)
                    if composite_names.contains(stem) {
                        continue;
                    }

                    // Skip known generated source patterns
                    if is_generated_source(stem, dir) {
                        continue;
                    }

                    // Check for source files
                    if !source_file_exists(dir, stem) {
                        // Use warning severity: some .o files come from
                        // generated sources (.S from .awk, etc.) that we
                        // cannot detect statically.
                        diags.push(Diagnostic::new(
                            "M001",
                            Severity::Info,
                            format!(
                                "{} references {} but no source file ({}.c, {}.S, or {}.rs) found",
                                name, name, stem, stem, stem,
                            ),
                            obj.span.clone(),
                        ));
                    }
                }
            }
        }
    }
}

/// M002: Composite module defined but never referenced in obj-*.
fn check_m002_orphan_composite(diags: &mut Vec<Diagnostic>, mf: &KbuildMakefile) {
    let obj_targets: HashSet<String> = mf
        .obj_assigns
        .iter()
        .flat_map(|o| o.targets.iter())
        .filter_map(|t| match t {
            ObjTarget::Object(name) => Some(name.clone()),
            ObjTarget::Directory(_) => None,
        })
        .collect();

    // Top-level kbuild variables that look like composite modules but aren't
    let toplevel_vars: HashSet<&str> =
        ["libs", "core", "drivers", "net", "virt", "init"].iter().copied().collect();

    // Build the set of all composite component .o names (for transitive check)
    let composite_components: HashSet<String> = mf
        .comp_assigns
        .iter()
        .flat_map(|c| c.objects.iter())
        .cloned()
        .collect();

    for comp in &mf.comp_assigns {
        if toplevel_vars.contains(comp.module_name.as_str()) {
            continue;
        }
        let expected = format!("{}.o", comp.module_name);
        // Check if referenced in obj-* OR as a component of another composite
        if !obj_targets.contains(&expected) && !composite_components.contains(&expected) {
            diags.push(Diagnostic::new(
                "M002",
                Severity::Info,
                format!(
                    "composite module '{}' ({}-y/objs) defined but {}.o not in any obj-* variable",
                    comp.module_name, comp.module_name, comp.module_name,
                ),
                comp.span.clone(),
            ));
        }
    }
}

/// M003: obj-* += bar/ but directory doesn't exist or has no Makefile.
fn check_m003_directory_missing(
    diags: &mut Vec<Diagnostic>,
    mf: &KbuildMakefile,
    dir: &Path,
) {
    for obj in &mf.obj_assigns {
        for target in &obj.targets {
            if let ObjTarget::Directory(dirname) = target {
                // Skip directories with unexpanded Make variables
                if dirname.contains('$') {
                    continue;
                }
                let subdir = dir.join(dirname.trim_end_matches('/'));
                if !subdir.is_dir() {
                    diags.push(Diagnostic::new(
                        "M003",
                        Severity::Warning,
                        format!("directory {} does not exist", dirname),
                        obj.span.clone(),
                    ));
                } else if !subdir.join("Makefile").is_file()
                    && !subdir.join("Kbuild").is_file()
                {
                    diags.push(Diagnostic::new(
                        "M003",
                        Severity::Warning,
                        format!(
                            "directory {} exists but has no Makefile or Kbuild",
                            dirname,
                        ),
                        obj.span.clone(),
                    ));
                }
            }
        }
    }
}

/// M004: := for a variable that was already assigned.
fn check_m004_overwritten_assignment(diags: &mut Vec<Diagnostic>, mf: &KbuildMakefile) {
    // Skip kbuild infrastructure files that use deliberate := pipelines
    // (variable initialization → include → filter → transform → prefix)
    let path_str = mf.path.to_string_lossy();
    if path_str.contains("scripts/Makefile") {
        return;
    }

    let mut seen: HashMap<String, u32> = HashMap::new();

    for obj in &mf.obj_assigns {
        let key = obj.var_name.clone();
        if obj.op == AssignOp::SimpleAssign {
            if let Some(prev_line) = seen.get(&key) {
                // Skip intentional transformations (RHS uses Make functions)
                if let Some(ref snippet) = obj.span.snippet {
                    if snippet.contains("$(") {
                        seen.insert(key, obj.span.line);
                        continue;
                    }
                }
                diags.push(
                    Diagnostic::new(
                        "M004",
                        Severity::Warning,
                        format!(
                            "'{}' assigned with ':=' but was already assigned at line {}; \
                             previous value is overwritten",
                            key, prev_line,
                        ),
                        obj.span.clone(),
                    )
                    .with_hint("use '+=' to append instead of ':=' to overwrite".to_string()),
                );
            }
        }
        seen.insert(key, obj.span.line);
    }

    // Same check for composite assigns
    let mut comp_seen: HashMap<String, u32> = HashMap::new();
    for comp in &mf.comp_assigns {
        let key = format!("{}-{}", comp.module_name, guard_suffix(&comp.guard));
        if comp.op == AssignOp::SimpleAssign {
            if let Some(prev_line) = comp_seen.get(&key) {
                // Skip intentional transformations
                if let Some(ref snippet) = comp.span.snippet {
                    if snippet.contains("$(") {
                        comp_seen.insert(key, comp.span.line);
                        continue;
                    }
                }
                diags.push(
                    Diagnostic::new(
                        "M004",
                        Severity::Warning,
                        format!(
                            "'{key}' assigned with ':=' but was already assigned at line {}; \
                             previous value is overwritten",
                            prev_line,
                        ),
                        comp.span.clone(),
                    )
                    .with_hint("use '+=' to append instead of ':=' to overwrite".to_string()),
                );
            }
        }
        comp_seen.insert(key, comp.span.line);
    }
}

/// M006: obj-* += bar where bar is a directory on disk (missing trailing slash).
fn check_m006_trailing_slash_missing(
    diags: &mut Vec<Diagnostic>,
    mf: &KbuildMakefile,
    dir: &Path,
) {
    for obj in &mf.obj_assigns {
        // Only flag obj-* entries, not subdir-* (subdir-y doesn't need trailing /)
        if !obj.var_name.starts_with("obj-") {
            continue;
        }
        for target in &obj.targets {
            if let ObjTarget::Object(name) = target {
                // If it doesn't end with .o and exists as a directory
                if !name.ends_with(".o") {
                    let subdir = dir.join(name);
                    if subdir.is_dir() {
                        diags.push(
                            Diagnostic::new(
                                "M006",
                                Severity::Warning,
                                format!(
                                    "'{}' is a directory but missing trailing '/'; \
                                     kbuild treats it as an object file without the slash",
                                    name,
                                ),
                                obj.span.clone(),
                            )
                            .with_hint(format!("use '{name}/' instead")),
                        );
                    }
                }
                // If it ends with .o but the stem is a directory
                if let Some(stem) = name.strip_suffix(".o") {
                    let subdir = dir.join(stem);
                    if subdir.is_dir()
                        && (subdir.join("Makefile").is_file()
                            || subdir.join("Kbuild").is_file())
                        && !source_file_exists(dir, stem)
                    {
                        diags.push(
                            Diagnostic::new(
                                "M006",
                                Severity::Warning,
                                format!(
                                    "'{}' looks like it should be a directory reference \
                                     (directory '{stem}/' exists with a Makefile)",
                                    name,
                                ),
                                obj.span.clone(),
                            )
                            .with_hint(format!("use '{stem}/' instead of '{name}'")),
                        );
                    }
                }
            }
        }
    }
}

/// M007: Same .o appears multiple times in same variable.
fn check_m007_duplicate_obj(diags: &mut Vec<Diagnostic>, mf: &KbuildMakefile) {
    // Group by variable name
    let mut var_targets: HashMap<String, Vec<(&ObjAssign, &ObjTarget)>> = HashMap::new();
    for obj in &mf.obj_assigns {
        for target in &obj.targets {
            var_targets
                .entry(obj.var_name.clone())
                .or_default()
                .push((obj, target));
        }
    }

    for (var_name, targets) in &var_targets {
        let mut seen: HashMap<String, u32> = HashMap::new();
        for (assign, target) in targets {
            let name = match target {
                ObjTarget::Object(n) => n,
                ObjTarget::Directory(n) => n,
            };
            if let Some(prev_line) = seen.get(name) {
                diags.push(Diagnostic::new(
                    "M007",
                    Severity::Info,
                    format!(
                        "'{}' appears multiple times in {} (first at line {})",
                        name, var_name, prev_line,
                    ),
                    assign.span.clone(),
                ));
            } else {
                seen.insert(name.clone(), assign.span.line);
            }
        }
    }
}

/// M008: In composite foo-y := bar.o baz.o, check source files exist.
fn check_m008_composite_source_missing(
    diags: &mut Vec<Diagnostic>,
    mf: &KbuildMakefile,
    dir: &Path,
) {
    let composite_names: HashSet<&str> = mf
        .comp_assigns
        .iter()
        .map(|c| c.module_name.as_str())
        .collect();

    for comp in &mf.comp_assigns {
        for obj_name in &comp.objects {
            if obj_name.ends_with('/') {
                continue; // subdirectory reference in composite
            }
            // Skip targets with unexpanded Make variables
            if obj_name.contains('$') {
                continue;
            }
            if let Some(stem) = obj_name.strip_suffix(".o") {
                // Check if it's itself a composite
                if composite_names.contains(stem) {
                    continue;
                }
                if is_generated_source(stem, dir) {
                    continue;
                }
                if !source_file_exists(dir, stem)
                    && !source_file_exists_in_ancestors(dir, stem)
                {
                    diags.push(Diagnostic::new(
                        "M008",
                        Severity::Info,
                        format!(
                            "composite module '{}': {} has no source file ({}.c, {}.S, or {}.rs)",
                            comp.module_name, obj_name, stem, stem, stem,
                        ),
                        comp.span.clone(),
                    ));
                }
            }
        }
    }
}

fn source_file_exists(dir: &Path, stem: &str) -> bool {
    // Handle subdirectory-qualified stems like "devlink/devlink"
    dir.join(format!("{stem}.c")).is_file()
        || dir.join(format!("{stem}.S")).is_file()
        || dir.join(format!("{stem}.rs")).is_file()
}

/// Check if a stem matches known generated source patterns.
fn is_generated_source(stem: &str, dir: &Path) -> bool {
    let basename = stem.rsplit('/').next().unwrap_or(stem);
    // Arch-specific generated division/modulo stubs
    if basename.starts_with("__") {
        return true;
    }
    // ASN.1 generated parsers (foo.asn1.o → foo.asn1.c generated from foo.asn1)
    if basename.contains(".asn1") {
        return true;
    }
    // Build-time generated/transformed objects
    if basename.ends_with(".stub") || basename.ends_with(".pi") {
        return true;
    }
    // Purgatory, VDSO, and EFI stub directories have generated sources
    let dir_str = dir.to_string_lossy();
    if dir_str.contains("purgatory") || dir_str.contains("vdso") || dir_str.contains("libstub") {
        return true;
    }
    false
}

/// For composite modules that use paths relative to a parent directory
/// (e.g., nouveau/nvkm Kbuild convention), try resolving the source file
/// in ancestor directories of the Kbuild file.
fn source_file_exists_in_ancestors(dir: &Path, stem: &str) -> bool {
    // Only try ancestor resolution for subdirectory-qualified paths
    if !stem.contains('/') {
        return false;
    }
    let mut parent = dir.parent();
    // Walk up at most 5 levels to avoid scanning the whole tree
    for _ in 0..5 {
        match parent {
            Some(p) => {
                if source_file_exists(p, stem) {
                    return true;
                }
                parent = p.parent();
            }
            None => break,
        }
    }
    false
}

fn guard_suffix(guard: &ObjGuard) -> &str {
    match guard {
        ObjGuard::BuiltIn => "y",
        ObjGuard::Module => "m",
        ObjGuard::Config(s) => s,
        ObjGuard::SubstConfig(s) => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::makefile::parser::parse_makefile;
    use std::path::Path;

    fn parse_and_index(source: &str) -> MakefileIndex {
        let mf = parse_makefile(Path::new("/dev/null/Makefile"), source);
        let mut index = MakefileIndex::default();
        index.add_file(mf);
        index
    }

    fn check_only(index: &MakefileIndex, check_id: &str) -> Vec<Diagnostic> {
        run_makefile_checks(index, &|id| id == check_id)
    }

    #[test]
    fn test_m002_orphan_composite() {
        let index = parse_and_index("foo-y := bar.o baz.o\n");
        let diags = check_only(&index, "M002");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("foo"));
    }

    #[test]
    fn test_m002_no_orphan() {
        let index = parse_and_index("obj-y += foo.o\nfoo-y := bar.o baz.o\n");
        let diags = check_only(&index, "M002");
        assert!(diags.is_empty());
    }

    #[test]
    fn test_m004_overwritten_assignment() {
        let index = parse_and_index("obj-y := foo.o\nobj-y := bar.o\n");
        let diags = check_only(&index, "M004");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("overwritten"));
    }

    #[test]
    fn test_m004_append_ok() {
        let index = parse_and_index("obj-y := foo.o\nobj-y += bar.o\n");
        let diags = check_only(&index, "M004");
        assert!(diags.is_empty());
    }

    #[test]
    fn test_m007_duplicate() {
        let index = parse_and_index("obj-y += foo.o\nobj-y += foo.o\n");
        let diags = check_only(&index, "M007");
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("multiple times"));
    }

    #[test]
    fn test_m007_no_duplicate() {
        let index = parse_and_index("obj-y += foo.o\nobj-y += bar.o\n");
        let diags = check_only(&index, "M007");
        assert!(diags.is_empty());
    }
}
