// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

/// Join line continuations and return logical lines with their original line numbers.
pub fn join_continuations(source: &str) -> Vec<(u32, String)> {
    let mut result = Vec::new();
    let mut current_line = String::new();
    let mut start_lineno: u32 = 0;
    let mut in_continuation = false;

    for (idx, raw) in source.lines().enumerate() {
        let lineno = (idx + 1) as u32;

        if !in_continuation {
            start_lineno = lineno;
            current_line.clear();
        }

        if let Some(stripped) = raw.strip_suffix('\\') {
            current_line.push_str(stripped.trim_end());
            current_line.push(' ');
            in_continuation = true;
        } else {
            current_line.push_str(raw);
            in_continuation = false;
            let trimmed = current_line.trim();
            if !trimmed.is_empty() {
                result.push((start_lineno, trimmed.to_string()));
            }
        }
    }

    // Handle trailing continuation
    if in_continuation && !current_line.trim().is_empty() {
        result.push((start_lineno, current_line.trim().to_string()));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_lines() {
        let input = "obj-y += foo.o\nobj-m += bar.o\n";
        let lines = join_continuations(input);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], (1, "obj-y += foo.o".to_string()));
        assert_eq!(lines[1], (2, "obj-m += bar.o".to_string()));
    }

    #[test]
    fn test_continuation() {
        let input = "obj-y += foo.o \\\n  bar.o \\\n  baz.o\n";
        let lines = join_continuations(input);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].0, 1);
        assert!(lines[0].1.contains("foo.o"));
        assert!(lines[0].1.contains("bar.o"));
        assert!(lines[0].1.contains("baz.o"));
    }

    #[test]
    fn test_empty_lines_skipped() {
        let input = "obj-y += foo.o\n\n\nobj-m += bar.o\n";
        let lines = join_continuations(input);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_comment_lines_preserved() {
        let input = "# comment\nobj-y += foo.o\n";
        let lines = join_continuations(input);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].1.starts_with('#'));
    }
}
