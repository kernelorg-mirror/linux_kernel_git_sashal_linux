// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use crate::diagnostics::Span;
use crate::makefile::ast::*;
use crate::makefile::lexer::join_continuations;
use std::path::Path;

pub fn parse_makefile(path: &Path, source: &str) -> KbuildMakefile {
    let lines = join_continuations(source);
    let mut makefile = KbuildMakefile {
        path: path.to_path_buf(),
        obj_assigns: Vec::new(),
        comp_assigns: Vec::new(),
        flag_assigns: Vec::new(),
        config_refs: Vec::new(),
        conditionals: Vec::new(),
    };

    for (lineno, content) in &lines {
        let lineno = *lineno;

        // Skip comments
        if content.starts_with('#') {
            continue;
        }

        // Check for conditionals
        if let Some(cond) = parse_conditional(content, path, lineno) {
            if let Some(ref sym) = cond.config_symbol {
                makefile.config_refs.push(ConfigRef {
                    symbol: sym.clone(),
                    span: cond.span.clone(),
                });
            }
            makefile.conditionals.push(cond);
            continue;
        }

        // Skip endif/else
        let trimmed = content.trim();
        if trimmed == "endif" || trimmed == "else" {
            continue;
        }

        // Try to parse as assignment
        if let Some((var, op, value)) = parse_assignment(content) {
            let span =
                Span::new(path, lineno).with_snippet(content.clone());

            // Extract CONFIG_ references from the variable name
            if let Some(sym) = extract_config_from_var(&var) {
                makefile.config_refs.push(ConfigRef {
                    symbol: sym.clone(),
                    span: span.clone(),
                });
            }

            // Categorize the assignment
            if let Some(obj_assign) = try_parse_obj_assign(&var, op, &value, span.clone()) {
                makefile.obj_assigns.push(obj_assign);
            } else if let Some(comp_assign) =
                try_parse_composite_assign(&var, op, &value, span.clone())
            {
                // Also extract CONFIG_ refs from the guard
                if let Some(sym) = extract_config_from_var(&var) {
                    // Already extracted above
                    let _ = sym;
                }
                makefile.comp_assigns.push(comp_assign);
            } else if is_flag_var(&var) {
                makefile.flag_assigns.push(FlagAssign {
                    var_name: var.clone(),
                    value: value.clone(),
                    op,
                    span,
                });
            }

            // Also scan the value for CONFIG_ references
            extract_config_refs_from_value(&value, path, lineno, &mut makefile.config_refs);
        }
    }

    makefile
}

fn parse_conditional(content: &str, path: &Path, lineno: u32) -> Option<ConditionalBlock> {
    let trimmed = content.trim();
    let span = Span::new(path, lineno).with_snippet(content.to_string());

    if let Some(rest) = trimmed.strip_prefix("ifdef") {
        let sym = rest.trim().strip_prefix("CONFIG_").map(|s| {
            s.split_whitespace()
                .next()
                .unwrap_or(s)
                .to_string()
        });
        Some(ConditionalBlock {
            kind: ConditionalKind::Ifdef,
            config_symbol: sym,
            span,
        })
    } else if let Some(rest) = trimmed.strip_prefix("ifndef") {
        let sym = rest.trim().strip_prefix("CONFIG_").map(|s| {
            s.split_whitespace()
                .next()
                .unwrap_or(s)
                .to_string()
        });
        Some(ConditionalBlock {
            kind: ConditionalKind::Ifndef,
            config_symbol: sym,
            span,
        })
    } else if let Some(rest) = trimmed.strip_prefix("ifeq") {
        let sym = extract_config_from_conditional_args(rest);
        Some(ConditionalBlock {
            kind: ConditionalKind::Ifeq,
            config_symbol: sym,
            span,
        })
    } else if let Some(rest) = trimmed.strip_prefix("ifneq") {
        let sym = extract_config_from_conditional_args(rest);
        Some(ConditionalBlock {
            kind: ConditionalKind::Ifneq,
            config_symbol: sym,
            span,
        })
    } else {
        None
    }
}

fn extract_config_from_conditional_args(args: &str) -> Option<String> {
    // Parse ifeq ($(CONFIG_FOO),y) or ifeq "$(CONFIG_FOO)" "y"
    if let Some(start) = args.find("CONFIG_") {
        let rest = &args[start + 7..];
        let end = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        if end > 0 {
            return Some(rest[..end].to_string());
        }
    }
    None
}

fn parse_assignment(line: &str) -> Option<(String, AssignOp, String)> {
    let trimmed = line.trim();

    // Try each operator (longest first to avoid ambiguity)
    for (pattern, op) in &[
        (":=", AssignOp::SimpleAssign),
        ("+=", AssignOp::Append),
        ("?=", AssignOp::Conditional),
    ] {
        if let Some(pos) = trimmed.find(pattern) {
            let var = trimmed[..pos].trim().to_string();
            let value = trimmed[pos + 2..].trim().to_string();
            if !var.is_empty() && !var.contains(' ') || var.contains('-') || var.contains('$') {
                return Some((var, *op, value));
            }
        }
    }

    // Plain `=` (must check after := to avoid matching the `:` part)
    if let Some(pos) = trimmed.find('=') {
        // Make sure it's not :=, +=, ?=, !=
        if pos > 0 {
            let prev = trimmed.as_bytes()[pos - 1];
            if prev == b':' || prev == b'+' || prev == b'?' || prev == b'!' {
                return None;
            }
        }
        let var = trimmed[..pos].trim().to_string();
        let value = trimmed[pos + 1..].trim().to_string();
        if !var.is_empty() {
            return Some((var, AssignOp::RecursiveAssign, value));
        }
    }

    None
}

fn extract_config_from_var(var: &str) -> Option<String> {
    // Match patterns like obj-$(CONFIG_FOO), foo-$(CONFIG_BAR), etc.
    if let Some(start) = var.find("$(CONFIG_") {
        let rest = &var[start + 9..];
        let end = rest.find(')').unwrap_or(rest.len());
        if end > 0 {
            return Some(rest[..end].to_string());
        }
    }
    // Also match $(subst m,y,$(CONFIG_FOO))
    if let Some(start) = var.find("$(subst") {
        let rest = &var[start..];
        if let Some(config_start) = rest.find("CONFIG_") {
            let inner = &rest[config_start + 7..];
            let end = inner
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(inner.len());
            if end > 0 {
                return Some(inner[..end].to_string());
            }
        }
    }
    None
}

fn try_parse_obj_assign(
    var: &str,
    op: AssignOp,
    value: &str,
    span: Span,
) -> Option<ObjAssign> {
    let (base, guard) = parse_var_guard(var)?;

    // Must be obj, lib, subdir, always, extra
    match base {
        "obj" | "lib" | "subdir" | "always" | "extra" => {}
        _ => return None,
    }

    let targets = parse_targets(value);

    Some(ObjAssign {
        var_name: var.to_string(),
        guard,
        targets,
        op,
        span,
    })
}

fn try_parse_composite_assign(
    var: &str,
    op: AssignOp,
    value: &str,
    span: Span,
) -> Option<CompAssign> {
    let (module_name, guard) = parse_var_guard(var)?;

    // Composite module names shouldn't be the standard kbuild variables
    match module_name {
        "obj" | "lib" | "subdir" | "always" | "extra" | "ccflags" | "asflags" | "ldflags"
        | "rustflags" | "subdir-ccflags" | "subdir-asflags" => return None,
        _ => {}
    }

    // Must have .o targets
    let objects: Vec<String> = value
        .split_whitespace()
        .filter(|s| s.ends_with(".o") || s.ends_with('/'))
        .map(|s| s.to_string())
        .collect();

    if objects.is_empty() {
        return None;
    }

    Some(CompAssign {
        module_name: module_name.to_string(),
        guard,
        objects,
        op,
        span,
    })
}

fn parse_var_guard(var: &str) -> Option<(&str, ObjGuard)> {
    // Match: name-y, name-m, name-objs, name-$(CONFIG_FOO), name-$(subst m,y,$(CONFIG_FOO))
    if let Some(pos) = var.rfind('-') {
        let base = &var[..pos];
        let suffix = &var[pos + 1..];

        let guard = match suffix {
            "y" | "objs" => ObjGuard::BuiltIn,
            "m" => ObjGuard::Module,
            s if s.starts_with("$(CONFIG_") => {
                let sym = s
                    .strip_prefix("$(CONFIG_")
                    .and_then(|s| s.strip_suffix(')'))
                    .unwrap_or(s)
                    .to_string();
                ObjGuard::Config(sym)
            }
            s if s.contains("$(subst") && s.contains("CONFIG_") => {
                if let Some(sym) = extract_config_from_var(var) {
                    ObjGuard::SubstConfig(sym)
                } else {
                    return None;
                }
            }
            _ => return None,
        };

        Some((base, guard))
    } else {
        None
    }
}

fn parse_targets(value: &str) -> Vec<ObjTarget> {
    value
        .split_whitespace()
        .map(|s| {
            if s.ends_with('/') {
                ObjTarget::Directory(s.to_string())
            } else {
                ObjTarget::Object(s.to_string())
            }
        })
        .collect()
}

fn is_flag_var(var: &str) -> bool {
    let lower = var.to_lowercase();
    lower.contains("ccflags")
        || lower.contains("asflags")
        || lower.contains("ldflags")
        || lower.contains("rustflags")
        || lower.contains("cppflags")
        || var.starts_with("CFLAGS_")
        || var.starts_with("CFLAGS_REMOVE_")
        || var.starts_with("AFLAGS_")
        || var.starts_with("KASAN_SANITIZE_")
        || var.starts_with("KCOV_INSTRUMENT_")
        || var.starts_with("KCSAN_SANITIZE_")
        || var.starts_with("UBSAN_SANITIZE_")
        || var.starts_with("GCO_PROFILE_")
        || var.starts_with("GCOV_PROFILE_")
}

fn extract_config_refs_from_value(
    value: &str,
    path: &Path,
    lineno: u32,
    refs: &mut Vec<ConfigRef>,
) {
    let mut pos = 0;
    while let Some(idx) = value[pos..].find("CONFIG_") {
        let abs_idx = pos + idx;
        // Ensure CONFIG_ is not part of a larger identifier like KCONFIG_CONFIG
        if abs_idx > 0 {
            let prev = value.as_bytes()[abs_idx - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                pos = abs_idx + 7;
                continue;
            }
        }
        let start = abs_idx + 7;
        let end = value[start..]
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .map(|i| start + i)
            .unwrap_or(value.len());
        if end > start {
            refs.push(ConfigRef {
                symbol: value[start..end].to_string(),
                span: Span::new(path, lineno),
            });
        }
        pos = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_obj_y() {
        let mf = parse_makefile(Path::new("test/Makefile"), "obj-y += foo.o\n");
        assert_eq!(mf.obj_assigns.len(), 1);
        assert_eq!(mf.obj_assigns[0].guard, ObjGuard::BuiltIn);
        assert_eq!(
            mf.obj_assigns[0].targets,
            vec![ObjTarget::Object("foo.o".to_string())]
        );
    }

    #[test]
    fn test_parse_obj_config() {
        let mf = parse_makefile(
            Path::new("test/Makefile"),
            "obj-$(CONFIG_FOO) += foo.o\n",
        );
        assert_eq!(mf.obj_assigns.len(), 1);
        assert_eq!(
            mf.obj_assigns[0].guard,
            ObjGuard::Config("FOO".to_string())
        );
        assert_eq!(mf.config_refs.len(), 1);
        assert_eq!(mf.config_refs[0].symbol, "FOO");
    }

    #[test]
    fn test_parse_directory_target() {
        let mf = parse_makefile(
            Path::new("test/Makefile"),
            "obj-$(CONFIG_NET) += ethernet/\n",
        );
        assert_eq!(mf.obj_assigns.len(), 1);
        assert_eq!(
            mf.obj_assigns[0].targets,
            vec![ObjTarget::Directory("ethernet/".to_string())]
        );
    }

    #[test]
    fn test_parse_composite_module() {
        let mf = parse_makefile(
            Path::new("test/Makefile"),
            "obj-$(CONFIG_EXT4) += ext4.o\next4-y := super.o inode.o dir.o\n",
        );
        assert_eq!(mf.obj_assigns.len(), 1);
        assert_eq!(mf.comp_assigns.len(), 1);
        assert_eq!(mf.comp_assigns[0].module_name, "ext4");
        assert_eq!(mf.comp_assigns[0].objects.len(), 3);
    }

    #[test]
    fn test_parse_conditional() {
        let mf = parse_makefile(
            Path::new("test/Makefile"),
            "ifdef CONFIG_FOO\nobj-y += foo.o\nendif\n",
        );
        assert_eq!(mf.conditionals.len(), 1);
        assert_eq!(
            mf.conditionals[0].config_symbol,
            Some("FOO".to_string())
        );
    }

    #[test]
    fn test_parse_ifeq() {
        let mf = parse_makefile(
            Path::new("test/Makefile"),
            "ifeq ($(CONFIG_BAR),y)\nobj-y += bar.o\nendif\n",
        );
        assert_eq!(mf.conditionals.len(), 1);
        assert_eq!(
            mf.conditionals[0].config_symbol,
            Some("BAR".to_string())
        );
    }

    #[test]
    fn test_parse_multiple_targets() {
        let mf = parse_makefile(
            Path::new("test/Makefile"),
            "obj-y += foo.o bar.o baz.o\n",
        );
        assert_eq!(mf.obj_assigns.len(), 1);
        assert_eq!(mf.obj_assigns[0].targets.len(), 3);
    }

    #[test]
    fn test_parse_flag_assign() {
        let mf = parse_makefile(
            Path::new("test/Makefile"),
            "ccflags-y := -DFOO\nCFLAGS_foo.o := -O2\n",
        );
        assert_eq!(mf.flag_assigns.len(), 2);
    }

    #[test]
    fn test_continuation_lines() {
        let mf = parse_makefile(
            Path::new("test/Makefile"),
            "ext4-y := super.o \\\n  inode.o \\\n  dir.o\n",
        );
        assert_eq!(mf.comp_assigns.len(), 1);
        assert_eq!(mf.comp_assigns[0].objects.len(), 3);
    }

    #[test]
    fn test_comment_skipped() {
        let mf = parse_makefile(
            Path::new("test/Makefile"),
            "# This is a comment\nobj-y += foo.o\n",
        );
        assert_eq!(mf.obj_assigns.len(), 1);
    }

    #[test]
    fn test_subst_pattern() {
        let mf = parse_makefile(
            Path::new("test/Makefile"),
            "obj-$(subst m,y,$(CONFIG_FOO)) += foo.o\n",
        );
        // Should detect CONFIG_FOO reference
        assert!(!mf.config_refs.is_empty());
        assert!(mf.config_refs.iter().any(|r| r.symbol == "FOO"));
    }
}
