// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use crate::diagnostics::Diagnostic;
use std::io::{self, Write};
use std::path::Path;

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\x20' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

pub fn print_diagnostics(
    diagnostics: &[Diagnostic],
    srctree: &Path,
    stats: &OutputStats,
) -> io::Result<()> {
    let stdout = io::stdout();
    let mut w = stdout.lock();

    write!(w, "{{\"kconfiglint_version\":\"{}\",", env!("CARGO_PKG_VERSION"))?;
    write!(w, "\"diagnostics\":[")?;

    for (i, diag) in diagnostics.iter().enumerate() {
        if i > 0 {
            write!(w, ",")?;
        }
        let rel = diag.relative_path(srctree);
        write!(
            w,
            "{{\"check_id\":\"{}\",\"severity\":\"{}\",\"message\":\"{}\",",
            diag.check_id,
            diag.severity.as_str(),
            escape_json(&diag.message),
        )?;
        write!(
            w,
            "\"location\":{{\"file\":\"{}\",\"line\":{}}}",
            escape_json(&rel.display().to_string()),
            diag.span.line,
        )?;

        if !diag.related.is_empty() {
            write!(w, ",\"related\":[")?;
            for (j, rel_loc) in diag.related.iter().enumerate() {
                if j > 0 {
                    write!(w, ",")?;
                }
                let rpath = rel_loc
                    .file
                    .strip_prefix(srctree)
                    .unwrap_or(&rel_loc.file);
                write!(
                    w,
                    "{{\"file\":\"{}\",\"line\":{},\"message\":\"{}\"}}",
                    escape_json(&rpath.display().to_string()),
                    rel_loc.line,
                    escape_json(&rel_loc.message),
                )?;
            }
            write!(w, "]")?;
        }

        if let Some(ref hint) = diag.fix_hint {
            write!(w, ",\"fix_hint\":\"{}\"", escape_json(hint))?;
        }

        write!(w, "}}")?;
    }

    write!(w, "],")?;
    write!(
        w,
        "\"statistics\":{{\"files_parsed\":{},\"kconfig_symbols\":{},",
        stats.files_parsed, stats.kconfig_symbols,
    )?;
    write!(
        w,
        "\"errors\":{},\"warnings\":{},\"infos\":{}}}}}",
        stats.errors, stats.warnings, stats.infos,
    )?;
    writeln!(w)?;
    Ok(())
}

pub struct OutputStats {
    pub files_parsed: usize,
    pub kconfig_symbols: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
}
