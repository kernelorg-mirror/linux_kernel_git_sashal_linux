// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use crate::kconfig::KconfigIndex;
use crate::makefile::MakefileIndex;
use std::collections::HashSet;
use std::path::Path;

/// Merged view of all Kconfig symbols and Makefile CONFIG_ references.
pub struct SymbolIndex<'a> {
    pub kconfig: &'a KconfigIndex,
    pub makefile: &'a MakefileIndex,
    /// CONFIG_ symbols referenced in C/H/S/rs source files.
    pub source_refs: HashSet<String>,
}

impl<'a> SymbolIndex<'a> {
    pub fn new(kconfig: &'a KconfigIndex, makefile: &'a MakefileIndex) -> Self {
        Self {
            kconfig,
            makefile,
            source_refs: HashSet::new(),
        }
    }

    pub fn with_source_refs(mut self, refs: HashSet<String>) -> Self {
        self.source_refs = refs;
        self
    }

    /// All CONFIG_ symbol names defined in Kconfig.
    pub fn kconfig_defined_symbols(&self) -> HashSet<&str> {
        self.kconfig.symbols.keys().map(|s| s.as_str()).collect()
    }

    /// All CONFIG_ symbol names referenced in Makefiles.
    pub fn makefile_referenced_symbols(&self) -> HashSet<&str> {
        self.makefile.config_refs.keys().map(|s| s.as_str()).collect()
    }

    /// All symbol names referenced in any Kconfig expression (depends, select, imply, default).
    pub fn kconfig_referenced_symbols(&self) -> HashSet<String> {
        let mut refs = HashSet::new();
        for infos in self.kconfig.symbols.values() {
            for info in infos {
                for s in &info.depends_symbols {
                    refs.insert(s.clone());
                }
                for s in &info.select_targets {
                    refs.insert(s.clone());
                }
                for s in &info.imply_targets {
                    refs.insert(s.clone());
                }
            }
        }
        // Also scan defaults for symbol refs
        for kfile in &self.kconfig.files {
            for config in &kfile.configs {
                for def in &config.defaults {
                    let mut syms = Vec::new();
                    def.value.collect_symbols(&mut syms);
                    if let Some(ref cond) = def.condition {
                        cond.collect_symbols(&mut syms);
                    }
                    refs.extend(syms);
                }
            }
            // Scan choice defaults too (e.g. "default LTO_NONE" in a choice block)
            for choice in &kfile.choices {
                for def in &choice.defaults {
                    let mut syms = Vec::new();
                    def.value.collect_symbols(&mut syms);
                    if let Some(ref cond) = def.condition {
                        cond.collect_symbols(&mut syms);
                    }
                    refs.extend(syms);
                }
                // Choice members are inherently referenced by being in a choice
                for member in &choice.members {
                    refs.insert(member.name.clone());
                }
            }
        }
        refs
    }

    /// Compute edit distance for "did you mean?" suggestions.
    pub fn suggest_similar<'b>(&self, symbol: &str, defined: &HashSet<&'b str>) -> Option<&'b str> {
        let mut best: Option<(&str, usize)> = None;
        let max_dist = match symbol.len() {
            0..=3 => 1,
            4..=7 => 2,
            _ => 3,
        };

        for &candidate in defined {
            let dist = edit_distance(symbol, candidate);
            if dist <= max_dist {
                if best.is_none() || dist < best.unwrap().1 {
                    best = Some((candidate, dist));
                }
            }
        }

        best.map(|(s, _)| s)
    }
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let m = a.len();
    let n = b.len();

    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }

    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];

    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edit_distance() {
        assert_eq!(edit_distance("FOO", "FOO"), 0);
        assert_eq!(edit_distance("FOO", "BAR"), 3);
        assert_eq!(edit_distance("FOO", "FOB"), 1);
        assert_eq!(edit_distance("FOOBAR", "FOOBAZ"), 1);
        assert_eq!(edit_distance("", "FOO"), 3);
        assert_eq!(edit_distance("FOO", ""), 3);
    }

    #[test]
    fn test_suggest_similar() {
        let kconfig = KconfigIndex::default();
        let makefile = MakefileIndex::default();
        let idx = SymbolIndex::new(&kconfig, &makefile);

        let defined: HashSet<&str> = ["FOO_BAR", "FOO_BAZ", "SOMETHING_ELSE"]
            .iter()
            .copied()
            .collect();

        // FOO_BAT has distance 1 from both FOO_BAR and FOO_BAZ,
        // so either is a valid suggestion
        let suggestion = idx.suggest_similar("FOO_BAT", &defined);
        assert!(
            suggestion == Some("FOO_BAR") || suggestion == Some("FOO_BAZ"),
            "expected FOO_BAR or FOO_BAZ, got {suggestion:?}",
        );
        assert_eq!(idx.suggest_similar("COMPLETELY_DIFFERENT", &defined), None);
    }
}
