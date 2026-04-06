// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

pub mod ast;
pub mod checks;
pub mod lexer;
pub mod parser;

use ast::KconfigFile;
use std::collections::HashMap;
use std::path::PathBuf;

/// Index of all Kconfig symbols across the entire tree.
#[derive(Debug, Default)]
pub struct KconfigIndex {
    /// symbol name → list of definitions (a symbol can be defined multiple times)
    pub symbols: HashMap<String, Vec<SymbolInfo>>,
    /// All parsed Kconfig files
    pub files: Vec<KconfigFile>,
    /// Set of files reached via the source chain
    pub sourced_files: std::collections::HashSet<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub file: PathBuf,
    pub line: u32,
    pub sym_type: Option<ast::SymType>,
    pub has_prompt: bool,
    pub is_tristate: bool,
    pub depends_symbols: Vec<String>,
    pub select_targets: Vec<String>,
    pub imply_targets: Vec<String>,
}

impl KconfigIndex {
    pub fn add_file(&mut self, kfile: KconfigFile) {
        for config in &kfile.configs {
            let mut dep_syms = Vec::new();
            for dep in &config.depends {
                dep.collect_symbols(&mut dep_syms);
            }

            let info = SymbolInfo {
                file: kfile.path.clone(),
                line: config.span.line,
                sym_type: config.sym_type,
                has_prompt: !config.prompts.is_empty(),
                is_tristate: config.sym_type == Some(ast::SymType::Tristate),
                depends_symbols: dep_syms,
                select_targets: config.selects.iter().map(|s| s.target.clone()).collect(),
                imply_targets: config.implies.iter().map(|s| s.target.clone()).collect(),
            };

            self.symbols
                .entry(config.name.clone())
                .or_default()
                .push(info);
        }
        self.files.push(kfile);
    }

    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }
}
