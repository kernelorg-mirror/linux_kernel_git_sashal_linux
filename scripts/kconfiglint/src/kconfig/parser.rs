// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use crate::diagnostics::Span;
use crate::kconfig::ast::*;
use crate::kconfig::lexer::{KconfigLine, tokenize};
use std::path::Path;

pub fn parse_kconfig(path: &Path, source: &str) -> KconfigFile {
    let lines = tokenize(source);
    let mut parser = Parser {
        lines: &lines,
        pos: 0,
        path,
        file: KconfigFile {
            path: path.to_path_buf(),
            configs: Vec::new(),
            choices: Vec::new(),
            menus: Vec::new(),
            sources: Vec::new(),
            comments: Vec::new(),
        },
    };
    parser.parse_top_level();
    parser.file
}

struct Parser<'a> {
    lines: &'a [KconfigLine],
    pos: usize,
    path: &'a Path,
    file: KconfigFile,
}

impl<'a> Parser<'a> {
    fn current(&self) -> Option<&'a KconfigLine> {
        self.lines.get(self.pos)
    }

    fn advance(&mut self) {
        self.pos += 1;
    }

    fn span(&self, line: &KconfigLine) -> Span {
        Span::new(self.path, line.line_number).with_snippet(line.content.clone())
    }

    fn parse_top_level(&mut self) {
        self.parse_top_level_with_conditions(&[]);
    }

    fn parse_top_level_with_conditions(&mut self, inherited_conditions: &[Expr]) {
        while let Some(line) = self.current() {
            let keyword = first_word(&line.content);
            match keyword {
                "config" => self.parse_config(false, inherited_conditions),
                "menuconfig" => self.parse_config(true, inherited_conditions),
                "choice" => self.parse_choice_with_conditions(inherited_conditions),
                "menu" => self.parse_menu(),
                "comment" => self.parse_comment_entry(),
                "if" => {
                    // Parse the if condition and propagate to nested configs
                    let rest = rest_after_first_word(&line.content);
                    let mut conditions = inherited_conditions.to_vec();
                    if let Some(expr) = parse_expr(rest) {
                        conditions.push(expr);
                    }
                    self.advance();
                    self.parse_top_level_with_conditions(&conditions);
                }
                "endif" | "endmenu" | "endchoice" => {
                    self.advance();
                    return;
                }
                "source" | "rsource" | "osource" | "orsource" => {
                    self.parse_source(line);
                    self.advance();
                }
                "mainmenu" => {
                    self.advance();
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    fn parse_config(&mut self, is_menuconfig: bool, inherited_conditions: &[Expr]) {
        let line = self.lines[self.pos].clone();
        let name = rest_after_first_word(&line.content).to_string();
        let span = self.span(&line);
        self.advance();

        let mut config = ConfigDef {
            name,
            is_menuconfig,
            sym_type: None,
            prompts: Vec::new(),
            defaults: Vec::new(),
            depends: inherited_conditions.to_vec(),
            selects: Vec::new(),
            implies: Vec::new(),
            ranges: Vec::new(),
            has_help: false,
            help_lines: 0,
            is_transitional: false,
            has_modules: false,
            span,
        };

        self.parse_config_properties(&mut config);
        self.file.configs.push(config);
    }

    fn parse_config_properties(&mut self, config: &mut ConfigDef) {
        while let Some(line) = self.current() {
            let kw = first_word(&line.content);
            match kw {
                "bool" | "boolean" => {
                    config.sym_type = Some(SymType::Bool);
                    let rest = rest_after_first_word(&line.content);
                    if let Some(prompt) = parse_prompt_text(rest) {
                        config.prompts.push(PromptDef {
                            text: prompt.0,
                            condition: prompt.1,
                            span: self.span(line),
                        });
                    }
                    self.advance();
                }
                "tristate" => {
                    config.sym_type = Some(SymType::Tristate);
                    let rest = rest_after_first_word(&line.content);
                    if let Some(prompt) = parse_prompt_text(rest) {
                        config.prompts.push(PromptDef {
                            text: prompt.0,
                            condition: prompt.1,
                            span: self.span(line),
                        });
                    }
                    self.advance();
                }
                "string" => {
                    config.sym_type = Some(SymType::String);
                    let rest = rest_after_first_word(&line.content);
                    if let Some(prompt) = parse_prompt_text(rest) {
                        config.prompts.push(PromptDef {
                            text: prompt.0,
                            condition: prompt.1,
                            span: self.span(line),
                        });
                    }
                    self.advance();
                }
                "int" => {
                    config.sym_type = Some(SymType::Int);
                    let rest = rest_after_first_word(&line.content);
                    if let Some(prompt) = parse_prompt_text(rest) {
                        config.prompts.push(PromptDef {
                            text: prompt.0,
                            condition: prompt.1,
                            span: self.span(line),
                        });
                    }
                    self.advance();
                }
                "hex" => {
                    config.sym_type = Some(SymType::Hex);
                    let rest = rest_after_first_word(&line.content);
                    if let Some(prompt) = parse_prompt_text(rest) {
                        config.prompts.push(PromptDef {
                            text: prompt.0,
                            condition: prompt.1,
                            span: self.span(line),
                        });
                    }
                    self.advance();
                }
                "def_bool" => {
                    config.sym_type = Some(SymType::Bool);
                    let rest = rest_after_first_word(&line.content);
                    if let Some((val, cond)) = parse_default_value(rest) {
                        config.defaults.push(DefaultDef {
                            value: val,
                            condition: cond,
                            span: self.span(line),
                        });
                    }
                    self.advance();
                }
                "def_tristate" => {
                    config.sym_type = Some(SymType::Tristate);
                    let rest = rest_after_first_word(&line.content);
                    if let Some((val, cond)) = parse_default_value(rest) {
                        config.defaults.push(DefaultDef {
                            value: val,
                            condition: cond,
                            span: self.span(line),
                        });
                    }
                    self.advance();
                }
                "prompt" => {
                    let rest = rest_after_first_word(&line.content);
                    if let Some(prompt) = parse_prompt_text(rest) {
                        config.prompts.push(PromptDef {
                            text: prompt.0,
                            condition: prompt.1,
                            span: self.span(line),
                        });
                    }
                    self.advance();
                }
                "default" => {
                    let rest = rest_after_first_word(&line.content);
                    if let Some((val, cond)) = parse_default_value(rest) {
                        config.defaults.push(DefaultDef {
                            value: val,
                            condition: cond,
                            span: self.span(line),
                        });
                    }
                    self.advance();
                }
                "depends" => {
                    // "depends on <expr>"
                    let rest = rest_after_first_word(&line.content);
                    let rest = rest.strip_prefix("on").map(|s| s.trim()).unwrap_or(rest);
                    if let Some(expr) = parse_expr(rest) {
                        config.depends.push(expr);
                    }
                    self.advance();
                }
                "select" => {
                    let rest = rest_after_first_word(&line.content);
                    let (target, cond) = parse_symbol_with_if(rest);
                    config.selects.push(SelectDef {
                        target,
                        condition: cond,
                        span: self.span(line),
                    });
                    self.advance();
                }
                "imply" => {
                    let rest = rest_after_first_word(&line.content);
                    let (target, cond) = parse_symbol_with_if(rest);
                    config.implies.push(ImplyDef {
                        target,
                        condition: cond,
                        span: self.span(line),
                    });
                    self.advance();
                }
                "range" => {
                    let rest = rest_after_first_word(&line.content);
                    let parts: Vec<&str> = rest.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let cond = if parts.len() > 2 && parts[2] == "if" {
                            parse_expr(&parts[3..].join(" "))
                        } else {
                            None
                        };
                        config.ranges.push(RangeDef {
                            low: parts[0].to_string(),
                            high: parts[1].to_string(),
                            condition: cond,
                            span: self.span(line),
                        });
                    }
                    self.advance();
                }
                "help" | "---help---" => {
                    config.has_help = true;
                    self.advance();
                    config.help_lines = self.skip_help_text();
                }
                "transitional" => {
                    config.is_transitional = true;
                    self.advance();
                }
                "modules" => {
                    config.has_modules = true;
                    self.advance();
                }
                // End of config block: any keyword that starts a new entry
                "config" | "menuconfig" | "choice" | "endchoice" | "comment" | "menu"
                | "endmenu" | "if" | "endif" | "source" | "rsource" | "osource"
                | "orsource" | "mainmenu" => {
                    return;
                }
                _ => {
                    // Unknown property — skip
                    self.advance();
                }
            }
        }
    }

    fn skip_help_text(&mut self) -> usize {
        // Help text is determined by indentation: ends at first line with
        // smaller indentation than the first help line.
        let base_indent = match self.current() {
            Some(line) => {
                let trimmed = line.content.trim_start();
                line.content.len() - trimmed.len()
            }
            None => return 0,
        };

        if base_indent == 0 {
            // No indentation found — some Kconfig files have empty help
            return 0;
        }

        let mut count = 0;
        while let Some(line) = self.current() {
            let trimmed = line.content.trim_start();
            let indent = line.content.len() - trimmed.len();
            if indent < base_indent && !trimmed.is_empty() {
                break;
            }
            count += 1;
            self.advance();
        }
        count
    }

    fn parse_choice(&mut self) {
        self.parse_choice_with_conditions(&[]);
    }

    fn parse_choice_with_conditions(&mut self, inherited_conditions: &[Expr]) {
        let line = self.lines[self.pos].clone();
        let span = self.span(&line);
        self.advance();

        let mut choice = ChoiceDef {
            prompts: Vec::new(),
            defaults: Vec::new(),
            depends: Vec::new(),
            has_help: false,
            members: Vec::new(),
            span,
        };

        // Parse choice properties and members until endchoice
        while let Some(line) = self.current() {
            let kw = first_word(&line.content);
            match kw {
                "endchoice" => {
                    self.advance();
                    break;
                }
                "config" => {
                    // Parse as a choice member, inheriting if-block conditions
                    let cline = self.lines[self.pos].clone();
                    let name = rest_after_first_word(&cline.content).to_string();
                    let cspan = self.span(&cline);
                    self.advance();

                    let mut config = ConfigDef {
                        name,
                        is_menuconfig: false,
                        sym_type: None,
                        prompts: Vec::new(),
                        defaults: Vec::new(),
                        depends: inherited_conditions.to_vec(),
                        selects: Vec::new(),
                        implies: Vec::new(),
                        ranges: Vec::new(),
                        has_help: false,
                        help_lines: 0,
                        is_transitional: false,
                        has_modules: false,
                        span: cspan,
                    };
                    self.parse_config_properties(&mut config);
                    // Add to both choices and the global configs list
                    choice.members.push(config.clone());
                    self.file.configs.push(config);
                }
                "prompt" => {
                    let rest = rest_after_first_word(&line.content);
                    if let Some(prompt) = parse_prompt_text(rest) {
                        choice.prompts.push(PromptDef {
                            text: prompt.0,
                            condition: prompt.1,
                            span: self.span(line),
                        });
                    }
                    self.advance();
                }
                "bool" | "boolean" | "tristate" => {
                    let rest = rest_after_first_word(&line.content);
                    if let Some(prompt) = parse_prompt_text(rest) {
                        choice.prompts.push(PromptDef {
                            text: prompt.0,
                            condition: prompt.1,
                            span: self.span(line),
                        });
                    }
                    self.advance();
                }
                "default" => {
                    let rest = rest_after_first_word(&line.content);
                    if let Some((val, cond)) = parse_default_value(rest) {
                        choice.defaults.push(DefaultDef {
                            value: val,
                            condition: cond,
                            span: self.span(line),
                        });
                    }
                    self.advance();
                }
                "depends" => {
                    let rest = rest_after_first_word(&line.content);
                    let rest = rest.strip_prefix("on").map(|s| s.trim()).unwrap_or(rest);
                    if let Some(expr) = parse_expr(rest) {
                        choice.depends.push(expr);
                    }
                    self.advance();
                }
                "help" | "---help---" => {
                    choice.has_help = true;
                    self.advance();
                    self.skip_help_text();
                }
                _ => {
                    self.advance();
                }
            }
        }

        self.file.choices.push(choice);
    }

    fn parse_menu(&mut self) {
        let line = self.lines[self.pos].clone();
        let prompt = rest_after_first_word(&line.content)
            .trim_matches('"')
            .to_string();
        let span = self.span(&line);
        self.advance();

        let mut menu = MenuDef {
            prompt,
            depends: Vec::new(),
            visible_if: None,
            span,
        };

        // Parse menu properties before entries
        while let Some(line) = self.current() {
            let kw = first_word(&line.content);
            match kw {
                "depends" => {
                    let rest = rest_after_first_word(&line.content);
                    let rest = rest.strip_prefix("on").map(|s| s.trim()).unwrap_or(rest);
                    if let Some(expr) = parse_expr(rest) {
                        menu.depends.push(expr);
                    }
                    self.advance();
                }
                "visible" => {
                    let rest = rest_after_first_word(&line.content);
                    let rest = rest.strip_prefix("if").map(|s| s.trim()).unwrap_or(rest);
                    menu.visible_if = parse_expr(rest);
                    self.advance();
                }
                _ => break,
            }
        }

        self.file.menus.push(menu);
        // Parse contents
        self.parse_top_level();
    }

    fn parse_comment_entry(&mut self) {
        let line = self.lines[self.pos].clone();
        let text = rest_after_first_word(&line.content)
            .trim_matches('"')
            .to_string();
        let span = self.span(&line);
        self.advance();

        let mut comment = CommentDef {
            text,
            depends: Vec::new(),
            span,
        };

        while let Some(line) = self.current() {
            let kw = first_word(&line.content);
            if kw == "depends" {
                let rest = rest_after_first_word(&line.content);
                let rest = rest.strip_prefix("on").map(|s| s.trim()).unwrap_or(rest);
                if let Some(expr) = parse_expr(rest) {
                    comment.depends.push(expr);
                }
                self.advance();
            } else {
                break;
            }
        }

        self.file.comments.push(comment);
    }

    fn parse_source(&mut self, line: &KconfigLine) {
        let rest = rest_after_first_word(&line.content);
        let path = rest.trim_matches('"').trim_matches('\'').to_string();
        self.file.sources.push(SourceDirective {
            path,
            span: self.span(line),
        });
    }
}

// --- Expression parsing ---

fn parse_expr(input: &str) -> Option<Expr> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    let mut parser = ExprParser::new(input);
    parser.parse_or()
}

struct ExprParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> ExprParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn remaining(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len()
            && self.input.as_bytes()[self.pos].is_ascii_whitespace()
        {
            self.pos += 1;
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn parse_or(&mut self) -> Option<Expr> {
        let mut left = self.parse_and()?;
        loop {
            self.skip_whitespace();
            if self.remaining().starts_with("||") {
                self.pos += 2;
                let right = self.parse_and()?;
                left = Expr::Or(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Some(left)
    }

    fn parse_and(&mut self) -> Option<Expr> {
        let mut left = self.parse_comparison()?;
        loop {
            self.skip_whitespace();
            if self.remaining().starts_with("&&") {
                self.pos += 2;
                let right = self.parse_comparison()?;
                left = Expr::And(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Some(left)
    }

    fn parse_comparison(&mut self) -> Option<Expr> {
        let left = self.parse_unary()?;
        self.skip_whitespace();

        let rem = self.remaining();
        if rem.starts_with("!=") {
            self.pos += 2;
            let right = self.parse_unary()?;
            Some(Expr::Neq(Box::new(left), Box::new(right)))
        } else if rem.starts_with("<=") {
            self.pos += 2;
            let right = self.parse_unary()?;
            Some(Expr::Leq(Box::new(left), Box::new(right)))
        } else if rem.starts_with(">=") {
            self.pos += 2;
            let right = self.parse_unary()?;
            Some(Expr::Geq(Box::new(left), Box::new(right)))
        } else if rem.starts_with('=') {
            self.pos += 1;
            let right = self.parse_unary()?;
            Some(Expr::Eq(Box::new(left), Box::new(right)))
        } else if rem.starts_with('<') {
            self.pos += 1;
            let right = self.parse_unary()?;
            Some(Expr::Lt(Box::new(left), Box::new(right)))
        } else if rem.starts_with('>') {
            self.pos += 1;
            let right = self.parse_unary()?;
            Some(Expr::Gt(Box::new(left), Box::new(right)))
        } else {
            Some(left)
        }
    }

    fn parse_unary(&mut self) -> Option<Expr> {
        self.skip_whitespace();
        if self.remaining().starts_with('!') {
            self.pos += 1;
            let expr = self.parse_primary()?;
            Some(Expr::Not(Box::new(expr)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Option<Expr> {
        self.skip_whitespace();

        match self.peek_char()? {
            '(' => {
                self.pos += 1;
                let expr = self.parse_or()?;
                self.skip_whitespace();
                if self.peek_char() == Some(')') {
                    self.pos += 1;
                }
                Some(expr)
            }
            '"' | '\'' => {
                let quote = self.peek_char().unwrap();
                self.pos += 1;
                let start = self.pos;
                while self.pos < self.input.len() {
                    let ch = self.input.as_bytes()[self.pos];
                    if ch == quote as u8 {
                        let val = self.input[start..self.pos].to_string();
                        self.pos += 1;
                        return Some(Expr::Const(val));
                    }
                    if ch == b'\\' {
                        self.pos += 1;
                    }
                    self.pos += 1;
                }
                Some(Expr::Const(self.input[start..].to_string()))
            }
            '$' => {
                // Macro expression — treat as opaque symbol
                let start = self.pos;
                self.skip_macro();
                let text = self.input[start..self.pos].to_string();
                Some(Expr::Symbol(text))
            }
            _ => {
                // Symbol name
                let start = self.pos;
                while self.pos < self.input.len() {
                    let ch = self.input.as_bytes()[self.pos];
                    if ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-' {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                if self.pos == start {
                    return None;
                }
                let name = self.input[start..self.pos].to_string();
                Some(Expr::Symbol(name))
            }
        }
    }

    fn skip_macro(&mut self) {
        // Skip $(...)
        if self.remaining().starts_with("$(") {
            self.pos += 2;
            let mut depth = 1;
            while self.pos < self.input.len() && depth > 0 {
                match self.input.as_bytes()[self.pos] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                self.pos += 1;
            }
        } else {
            self.pos += 1;
        }
    }
}

// --- Helper functions ---

fn first_word(s: &str) -> &str {
    s.trim().split_whitespace().next().unwrap_or("")
}

fn rest_after_first_word(s: &str) -> &str {
    let trimmed = s.trim();
    match trimmed.find(|c: char| c.is_whitespace()) {
        Some(i) => trimmed[i..].trim(),
        None => "",
    }
}

fn parse_prompt_text(s: &str) -> Option<(String, Option<Expr>)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    if s.starts_with('"') {
        // Find matching close quote
        let mut end = 1;
        while end < s.len() {
            if s.as_bytes()[end] == b'\\' {
                end += 2;
                continue;
            }
            if s.as_bytes()[end] == b'"' {
                let text = s[1..end].to_string();
                let rest = s[end + 1..].trim();
                let cond = if let Some(rest) = rest.strip_prefix("if") {
                    parse_expr(rest.trim())
                } else {
                    None
                };
                return Some((text, cond));
            }
            end += 1;
        }
        // Unterminated quote
        Some((s[1..].to_string(), None))
    } else {
        // Unquoted — the whole thing is the prompt (unusual)
        let (text, cond) = split_at_if(s);
        Some((text.to_string(), cond))
    }
}

fn parse_default_value(s: &str) -> Option<(Expr, Option<Expr>)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Split at " if " boundary to separate value from condition
    if let Some(if_pos) = find_if_boundary(s) {
        let val_str = s[..if_pos].trim();
        let cond_str = s[if_pos + 3..].trim();
        let val = parse_expr(val_str)?;
        let cond = parse_expr(cond_str);
        Some((val, cond))
    } else {
        let val = parse_expr(s)?;
        Some((val, None))
    }
}

fn parse_symbol_with_if(s: &str) -> (String, Option<Expr>) {
    let s = s.trim();
    let parts: Vec<&str> = s.splitn(2, " if ").collect();
    let symbol = parts[0].trim().to_string();
    let cond = if parts.len() > 1 {
        parse_expr(parts[1].trim())
    } else {
        None
    };
    (symbol, cond)
}

fn split_at_if(s: &str) -> (&str, Option<Expr>) {
    if let Some(pos) = find_if_boundary(s) {
        let cond = parse_expr(s[pos + 3..].trim());
        (s[..pos].trim(), cond)
    } else {
        (s, None)
    }
}

fn find_if_boundary(s: &str) -> Option<usize> {
    // Find " if " that's not inside quotes
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut in_quote = false;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            in_quote = !in_quote;
        } else if !in_quote && i + 3 < bytes.len() {
            if (i == 0 || bytes[i - 1].is_ascii_whitespace())
                && bytes[i] == b'i'
                && bytes[i + 1] == b'f'
                && bytes[i + 2].is_ascii_whitespace()
            {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}
