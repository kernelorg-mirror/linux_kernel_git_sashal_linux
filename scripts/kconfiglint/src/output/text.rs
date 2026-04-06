// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use crate::diagnostics::{Diagnostic, Severity};
use std::path::Path;

pub fn print_diagnostics(diagnostics: &[Diagnostic], srctree: &Path, use_color: bool) {
    for diag in diagnostics {
        let rel = diag.relative_path(srctree);
        let sev = diag.severity.as_str();

        if use_color {
            let color = match diag.severity {
                Severity::Error => "\x1b[1;31m",
                Severity::Warning => "\x1b[1;33m",
                Severity::Info => "\x1b[1;36m",
            };
            let bold = "\x1b[1m";
            let reset = "\x1b[0m";

            eprintln!(
                "{bold}{}:{}: {color}{}{reset}[{}]{bold}: {}{reset}",
                rel.display(),
                diag.span.line,
                sev,
                diag.check_id,
                diag.message,
            );
        } else {
            eprintln!(
                "{}:{}: {}[{}]: {}",
                rel.display(),
                diag.span.line,
                sev,
                diag.check_id,
                diag.message,
            );
        }

        if let Some(ref snippet) = diag.span.snippet {
            if use_color {
                eprintln!("  \x1b[34m{}\x1b[0m | {}", diag.span.line, snippet);
            } else {
                eprintln!("  {} | {}", diag.span.line, snippet);
            }
        }

        for related in &diag.related {
            let rpath = related
                .file
                .strip_prefix(srctree)
                .unwrap_or(&related.file);
            eprintln!(
                "  note: {} at {}:{}",
                related.message,
                rpath.display(),
                related.line
            );
        }

        if let Some(ref hint) = diag.fix_hint {
            eprintln!("  hint: {hint}");
        }
    }
}
