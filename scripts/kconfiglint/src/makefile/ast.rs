// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use crate::diagnostics::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignOp {
    /// `:=` (simple)
    SimpleAssign,
    /// `=` (recursive)
    RecursiveAssign,
    /// `+=` (append)
    Append,
    /// `?=` (conditional)
    Conditional,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjGuard {
    /// `obj-y`
    BuiltIn,
    /// `obj-m`
    Module,
    /// `obj-$(CONFIG_FOO)` — stores "FOO"
    Config(String),
    /// `obj-$(subst m,y,$(CONFIG_FOO))` — stores "FOO"
    SubstConfig(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjTarget {
    /// `foo.o`
    Object(String),
    /// `bar/` (trailing slash)
    Directory(String),
}

#[derive(Debug, Clone)]
pub struct ObjAssign {
    pub var_name: String,
    pub guard: ObjGuard,
    pub targets: Vec<ObjTarget>,
    pub op: AssignOp,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct CompAssign {
    pub module_name: String,
    pub guard: ObjGuard,
    pub objects: Vec<String>,
    pub op: AssignOp,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct FlagAssign {
    pub var_name: String,
    pub value: String,
    pub op: AssignOp,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ConfigRef {
    pub symbol: String,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalKind {
    Ifdef,
    Ifndef,
    Ifeq,
    Ifneq,
}

#[derive(Debug, Clone)]
pub struct ConditionalBlock {
    pub kind: ConditionalKind,
    pub config_symbol: Option<String>,
    pub span: Span,
}

#[derive(Debug)]
pub struct KbuildMakefile {
    pub path: std::path::PathBuf,
    pub obj_assigns: Vec<ObjAssign>,
    pub comp_assigns: Vec<CompAssign>,
    pub flag_assigns: Vec<FlagAssign>,
    pub config_refs: Vec<ConfigRef>,
    pub conditionals: Vec<ConditionalBlock>,
}
