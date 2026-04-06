#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
#
# Wrapper script for kconfiglint. Builds the tool if needed, then runs it.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KLINT_BIN="${SCRIPT_DIR}/target/release/kconfiglint"

if [ ! -x "$KLINT_BIN" ]; then
    echo "Building kconfiglint..." >&2
    cargo build --manifest-path="${SCRIPT_DIR}/Cargo.toml" --release --quiet || exit 2
fi

exec "$KLINT_BIN" "$@"
