// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

// AST fields are intentionally kept for completeness even if not
// yet used by all checks.
#![allow(dead_code)]

pub mod config;
pub mod cross;
pub mod diagnostics;
pub mod kconfig;
pub mod makefile;
pub mod output;
pub mod walk;
