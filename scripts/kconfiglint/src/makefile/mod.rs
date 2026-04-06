// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

pub mod ast;
pub mod checks;
pub mod lexer;
pub mod parser;

use ast::KbuildMakefile;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// Index of all Makefile data across the entire tree.
#[derive(Debug, Default)]
pub struct MakefileIndex {
    /// All parsed Makefile/Kbuild files
    pub files: Vec<KbuildMakefile>,
    /// CONFIG_ symbols referenced in Makefiles → file locations
    pub config_refs: HashMap<String, Vec<(PathBuf, u32)>>,
    /// obj targets per directory (directory path → set of .o targets)
    pub obj_targets: HashMap<PathBuf, HashSet<String>>,
    /// Composite module names per directory
    pub composite_modules: HashMap<PathBuf, HashSet<String>>,
}

impl MakefileIndex {
    pub fn add_file(&mut self, mf: KbuildMakefile) {
        let dir = mf.path.parent().unwrap_or_else(|| std::path::Path::new(".")).to_path_buf();

        for cref in &mf.config_refs {
            self.config_refs
                .entry(cref.symbol.clone())
                .or_default()
                .push((mf.path.clone(), cref.span.line));
        }

        for obj in &mf.obj_assigns {
            for target in &obj.targets {
                match target {
                    ast::ObjTarget::Object(name) => {
                        self.obj_targets
                            .entry(dir.clone())
                            .or_default()
                            .insert(name.clone());
                    }
                    ast::ObjTarget::Directory(_) => {}
                }
            }
        }

        for comp in &mf.comp_assigns {
            self.composite_modules
                .entry(dir.clone())
                .or_default()
                .insert(comp.module_name.clone());
        }

        self.files.push(mf);
    }
}
