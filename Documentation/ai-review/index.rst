.. SPDX-License-Identifier: GPL-2.0

.. _ai_review_prompts:

==========================
AI Review Prompt Reference
==========================

AI review prompts provide subsystem-specific knowledge for automated
kernel patch review.  They encode invariants, API contracts, common bug
patterns, and review protocols developed by kernel maintainers.

These prompts are consumed by AI tools performing patch regression
analysis.  They are distributed throughout the kernel tree in
``ai-review/`` subdirectories alongside the code they cover.

Core Framework
==============

The core review framework lives in ``ai-review/`` at the tree root.
Start with ``review-core.md`` for patch review or ``debugging.md``
for crash analysis.

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - File
     - Purpose
   * - ``ai-review/review-core.md``
     - Main review protocol and task orchestration
   * - ``ai-review/technical-patterns.md``
     - Kernel-wide technical patterns and best practices
   * - ``ai-review/subsystem-index.md``
     - Trigger table: maps file paths and symbols to subsystem guides
   * - ``ai-review/callstack.md``
     - Call chain analysis methodology
   * - ``ai-review/false-positive-guide.md``
     - False positive elimination checklist
   * - ``ai-review/debugging.md``
     - Crash and warning debugging protocol
   * - ``ai-review/inline-template.md``
     - LKML-appropriate review output template
   * - ``ai-review/fixes-tag.md``
     - Fixes: tag format verification
   * - ``ai-review/missing-fixes-tag.md``
     - Detection of missing Fixes: tags
   * - ``ai-review/pointer-guards.md``
     - NULL pointer guard analysis
   * - ``ai-review/lore-thread.md``
     - lore.kernel.org thread analysis

Subsystem Guides
================

Each subsystem's review guide lives alongside its source code in an
``ai-review/`` subdirectory.  The master trigger table at
``ai-review/subsystem-index.md`` maps file paths, function names, and
symbols to the appropriate guide.

.. list-table::
   :header-rows: 1
   :widths: 25 30 45

   * - Subsystem
     - Guide Path
     - Key Triggers
   * - Memory Management
     - ``mm/ai-review/``
     - pte\_\*, folio\_\*, alloc\_pages, vma\_\*, shrink\_\*
   * - Networking
     - ``net/ai-review/``
     - net/, drivers/net/, skb\_\*
   * - Filesystems
     - ``fs/ai-review/``, ``fs/btrfs/ai-review/``, etc.
     - inode, dentry, vfs\_\*, fs/\*.c
   * - BPF
     - ``kernel/bpf/ai-review/``
     - kernel/bpf/, bpf, verifier
   * - Core Kernel
     - ``kernel/ai-review/``, ``kernel/\*/ai-review/``
     - spin\_lock\*, schedule, rcu\*, timer\_\*
   * - Block/Storage
     - ``block/ai-review/``, ``io_uring/ai-review/``
     - block layer, io\_uring/
   * - Drivers
     - ``drivers/\*/ai-review/``
     - drivers/gpu/drm/, drivers/pci/, etc.
   * - Architecture
     - ``arch/\*/ai-review/``
     - arch/mips/
   * - Tools
     - ``tools/\*/ai-review/``
     - tools/perf/, tools/objtool/

Agent Orchestration
===================

Multi-agent review workflows are defined in ``ai-review/agent/``.
These prompts enable specialized agents to handle different aspects
of a patch review in parallel.

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - File
     - Purpose
   * - ``ai-review/agent/overview.md``
     - Holistic diff analysis
   * - ``ai-review/agent/review.md``
     - Per-change regression analysis
   * - ``ai-review/agent/side-effect.md``
     - Cross-function side effect tracing
   * - ``ai-review/agent/context.md``
     - Context gathering orchestration
   * - ``ai-review/agent/debug.md``
     - Crash debugging orchestration
   * - ``ai-review/agent/orc.md``
     - Multi-agent review orchestrator

Contributing
============

To add a review guide for a new subsystem:

1. Copy ``ai-review/subsystem-template.md`` as a starting point
2. Place the guide at ``<subsystem-dir>/ai-review/<name>.md``
3. Add an entry to ``ai-review/subsystem-index.md`` with trigger patterns
