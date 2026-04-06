// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use crate::diagnostics::Severity;
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckDomain {
    All,
    KconfigOnly,
    MakefileOnly,
    CrossOnly,
}

#[derive(Debug)]
pub struct Config {
    pub srctree: PathBuf,
    pub paths: Vec<PathBuf>,
    pub domain: CheckDomain,
    pub enabled_checks: Option<HashSet<String>>,
    pub disabled_checks: HashSet<String>,
    pub min_severity: Severity,
    pub format: OutputFormat,
    pub jobs: usize,
    pub verbose: bool,
    pub color: ColorMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

impl Config {
    pub fn is_check_enabled(&self, check_id: &str) -> bool {
        if self.disabled_checks.contains(check_id) {
            return false;
        }
        if let Some(ref enabled) = self.enabled_checks {
            return enabled.contains(check_id);
        }
        true
    }

    pub fn should_run_kconfig(&self) -> bool {
        matches!(self.domain, CheckDomain::All | CheckDomain::KconfigOnly)
    }

    pub fn should_run_makefile(&self) -> bool {
        matches!(self.domain, CheckDomain::All | CheckDomain::MakefileOnly)
    }

    pub fn should_run_cross(&self) -> bool {
        matches!(self.domain, CheckDomain::All | CheckDomain::CrossOnly)
    }
}

fn print_usage() {
    eprintln!(
        "Usage: kconfiglint [OPTIONS] [PATHS...]

Lint Linux kernel Kconfig files and Makefiles.

ARGUMENTS:
  [PATHS...]                 Files/directories to check (default: full tree)

OPTIONS:
  -k, --kconfig-only         Only Kconfig checks (K-series)
  -m, --makefile-only         Only Makefile checks (M-series)
  -x, --cross-only            Only cross-domain checks (X-series)
  -c, --check <IDs>           Enable only these check IDs (comma-separated)
  -d, --disable <IDs>         Disable these check IDs (comma-separated)
  -s, --severity <LEVEL>      Minimum severity: error, warning, info (default: warning)
  -f, --format <FMT>          Output format: text, json (default: text)
  --srctree <PATH>            Kernel source tree root (default: auto-detect)
  -j, --jobs <N>              Parallel threads (default: nproc)
  -q, --quiet                 Only output errors
  -v, --verbose               Show progress and statistics
  --color <WHEN>              Color mode: auto, always, never (default: auto)
  -h, --help                  Print this help
  --version                   Print version"
    );
}

pub fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut srctree: Option<PathBuf> = None;
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut domain = CheckDomain::All;
    let mut enabled_checks: Option<HashSet<String>> = None;
    let mut disabled_checks: HashSet<String> = HashSet::new();
    let mut min_severity = Severity::Warning;
    let mut format = OutputFormat::Text;
    let mut jobs = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let mut verbose = false;
    let mut color = ColorMode::Auto;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "--version" => {
                eprintln!("kconfiglint {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-k" | "--kconfig-only" => domain = CheckDomain::KconfigOnly,
            "-m" | "--makefile-only" => domain = CheckDomain::MakefileOnly,
            "-x" | "--cross-only" => domain = CheckDomain::CrossOnly,
            "-q" | "--quiet" => min_severity = Severity::Error,
            "-v" | "--verbose" => verbose = true,
            "-c" | "--check" => {
                i += 1;
                let val = args.get(i).ok_or("--check requires an argument")?;
                let set: HashSet<String> =
                    val.split(',').map(|s| s.trim().to_uppercase()).collect();
                enabled_checks = Some(set);
            }
            "-d" | "--disable" => {
                i += 1;
                let val = args.get(i).ok_or("--disable requires an argument")?;
                for id in val.split(',') {
                    disabled_checks.insert(id.trim().to_uppercase());
                }
            }
            "-s" | "--severity" => {
                i += 1;
                let val = args.get(i).ok_or("--severity requires an argument")?;
                min_severity = match val.as_str() {
                    "error" => Severity::Error,
                    "warning" => Severity::Warning,
                    "info" => Severity::Info,
                    _ => return Err(format!("unknown severity: {val}")),
                };
            }
            "-f" | "--format" => {
                i += 1;
                let val = args.get(i).ok_or("--format requires an argument")?;
                format = match val.as_str() {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    _ => return Err(format!("unknown format: {val}")),
                };
            }
            "--srctree" => {
                i += 1;
                let val = args.get(i).ok_or("--srctree requires an argument")?;
                srctree = Some(PathBuf::from(val));
            }
            "-j" | "--jobs" => {
                i += 1;
                let val = args.get(i).ok_or("--jobs requires an argument")?;
                jobs = val
                    .parse()
                    .map_err(|_| format!("invalid job count: {val}"))?;
            }
            "--color" => {
                i += 1;
                let val = args.get(i).ok_or("--color requires an argument")?;
                color = match val.as_str() {
                    "auto" => ColorMode::Auto,
                    "always" => ColorMode::Always,
                    "never" => ColorMode::Never,
                    _ => return Err(format!("unknown color mode: {val}")),
                };
            }
            arg if arg.starts_with('-') => {
                return Err(format!("unknown option: {arg}"));
            }
            arg => {
                paths.push(PathBuf::from(arg));
            }
        }
        i += 1;
    }

    let srctree = match srctree {
        Some(s) => s,
        None => detect_srctree()?,
    };

    Ok(Config {
        srctree,
        paths,
        domain,
        enabled_checks,
        disabled_checks,
        min_severity,
        format,
        jobs,
        verbose,
        color,
    })
}

fn detect_srctree() -> Result<PathBuf, String> {
    let mut dir = std::env::current_dir().map_err(|e| format!("cannot get cwd: {e}"))?;
    loop {
        if dir.join("Kconfig").is_file() && dir.join("Makefile").is_file() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(
                "cannot detect kernel source tree root (no Kconfig + Makefile found). \
                 Use --srctree to specify it."
                    .to_string(),
            );
        }
    }
}
