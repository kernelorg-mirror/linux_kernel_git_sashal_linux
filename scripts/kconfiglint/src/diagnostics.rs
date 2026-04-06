// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct Span {
    pub file: PathBuf,
    pub line: u32,
    pub snippet: Option<String>,
}

impl Span {
    pub fn new(file: &Path, line: u32) -> Self {
        Self {
            file: file.to_path_buf(),
            line,
            snippet: None,
        }
    }

    pub fn with_snippet(mut self, snippet: String) -> Self {
        self.snippet = Some(snippet);
        self
    }
}

#[derive(Debug, Clone)]
pub struct RelatedLocation {
    pub file: PathBuf,
    pub line: u32,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub check_id: &'static str,
    pub severity: Severity,
    pub message: String,
    pub span: Span,
    pub related: Vec<RelatedLocation>,
    pub fix_hint: Option<String>,
}

impl Diagnostic {
    pub fn new(
        check_id: &'static str,
        severity: Severity,
        message: String,
        span: Span,
    ) -> Self {
        Self {
            check_id,
            severity,
            message,
            span,
            related: Vec::new(),
            fix_hint: None,
        }
    }

    pub fn with_related(mut self, file: &Path, line: u32, message: String) -> Self {
        self.related.push(RelatedLocation {
            file: file.to_path_buf(),
            line,
            message,
        });
        self
    }

    pub fn with_hint(mut self, hint: String) -> Self {
        self.fix_hint = Some(hint);
        self
    }

    /// Format the span's file path relative to a base directory.
    pub fn relative_path<'a>(&'a self, base: &Path) -> &'a Path {
        self.span
            .file
            .strip_prefix(base)
            .unwrap_or(&self.span.file)
    }
}
