// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use crate::diagnostics::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymType {
    Bool,
    Tristate,
    String,
    Int,
    Hex,
}

impl SymType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SymType::Bool => "bool",
            SymType::Tristate => "tristate",
            SymType::String => "string",
            SymType::Int => "int",
            SymType::Hex => "hex",
        }
    }
}

#[derive(Debug, Clone)]
pub enum Expr {
    Symbol(String),
    Const(String),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Eq(Box<Expr>, Box<Expr>),
    Neq(Box<Expr>, Box<Expr>),
    Lt(Box<Expr>, Box<Expr>),
    Gt(Box<Expr>, Box<Expr>),
    Leq(Box<Expr>, Box<Expr>),
    Geq(Box<Expr>, Box<Expr>),
}

impl Expr {
    /// Check if this dependency expression can be satisfied given a set of
    /// known-true symbols. Used by K006 to properly handle OR expressions:
    /// `A || B` is satisfied if either A or B is in the satisfied set.
    pub fn is_satisfiable(&self, satisfied: &std::collections::HashSet<String>) -> bool {
        match self {
            Expr::Symbol(s) => satisfied.contains(s),
            Expr::Const(_) => true,
            Expr::Or(a, b) => a.is_satisfiable(satisfied) || b.is_satisfiable(satisfied),
            Expr::And(a, b) => a.is_satisfiable(satisfied) && b.is_satisfiable(satisfied),
            // Negation, comparisons — conservatively assume satisfied
            // (we can't prove these false without full evaluation)
            _ => true,
        }
    }

    /// Collect all symbol names referenced in this expression.
    pub fn collect_symbols(&self, out: &mut Vec<String>) {
        match self {
            Expr::Symbol(s) => out.push(s.clone()),
            Expr::Const(_) => {}
            Expr::Not(e) => e.collect_symbols(out),
            Expr::And(a, b)
            | Expr::Or(a, b)
            | Expr::Eq(a, b)
            | Expr::Neq(a, b)
            | Expr::Lt(a, b)
            | Expr::Gt(a, b)
            | Expr::Leq(a, b)
            | Expr::Geq(a, b) => {
                a.collect_symbols(out);
                b.collect_symbols(out);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PromptDef {
    pub text: String,
    pub condition: Option<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct DefaultDef {
    pub value: Expr,
    pub condition: Option<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SelectDef {
    pub target: String,
    pub condition: Option<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ImplyDef {
    pub target: String,
    pub condition: Option<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct RangeDef {
    pub low: String,
    pub high: String,
    pub condition: Option<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ConfigDef {
    pub name: String,
    pub is_menuconfig: bool,
    pub sym_type: Option<SymType>,
    pub prompts: Vec<PromptDef>,
    pub defaults: Vec<DefaultDef>,
    pub depends: Vec<Expr>,
    pub selects: Vec<SelectDef>,
    pub implies: Vec<ImplyDef>,
    pub ranges: Vec<RangeDef>,
    pub has_help: bool,
    pub help_lines: usize,
    pub is_transitional: bool,
    pub has_modules: bool,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ChoiceDef {
    pub prompts: Vec<PromptDef>,
    pub defaults: Vec<DefaultDef>,
    pub depends: Vec<Expr>,
    pub has_help: bool,
    pub members: Vec<ConfigDef>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct MenuDef {
    pub prompt: String,
    pub depends: Vec<Expr>,
    pub visible_if: Option<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SourceDirective {
    pub path: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct CommentDef {
    pub text: String,
    pub depends: Vec<Expr>,
    pub span: Span,
}

#[derive(Debug)]
pub struct KconfigFile {
    pub path: std::path::PathBuf,
    pub configs: Vec<ConfigDef>,
    pub choices: Vec<ChoiceDef>,
    pub menus: Vec<MenuDef>,
    pub sources: Vec<SourceDirective>,
    pub comments: Vec<CommentDef>,
}
