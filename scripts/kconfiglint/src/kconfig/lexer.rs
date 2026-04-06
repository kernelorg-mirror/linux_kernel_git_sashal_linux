// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

/// Represents a logical line in a Kconfig file (after comment stripping).
#[derive(Debug, Clone)]
pub struct KconfigLine {
    pub line_number: u32,
    pub indent: usize,
    pub content: String,
}

/// Tokenize a Kconfig file into logical lines, stripping comments.
pub fn tokenize(source: &str) -> Vec<KconfigLine> {
    let mut lines = Vec::new();

    for (idx, raw) in source.lines().enumerate() {
        let line_number = (idx + 1) as u32;
        // Strip comments (# not inside quotes)
        let content = strip_comment(raw);
        let trimmed = content.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        let indent = trimmed.len() - trimmed.trim_start().len();
        lines.push(KconfigLine {
            line_number,
            indent,
            content: trimmed.to_string(),
        });
    }

    lines
}

fn strip_comment(line: &str) -> &str {
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut prev_was_escape = false;

    for (i, ch) in line.char_indices() {
        if prev_was_escape {
            prev_was_escape = false;
            continue;
        }
        match ch {
            '\\' => {
                prev_was_escape = true;
            }
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            '#' if !in_single_quote && !in_double_quote => {
                return &line[..i];
            }
            _ => {}
        }
    }

    line
}
