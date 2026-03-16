# Subsystem Guide Index

Load subsystem guides based on what the code touches. Each guide contains
subsystem-specific invariants, API contracts, and common bug patterns.
Each subsystem guide may reference additional pattern files to load
conditionally.

Subsystem guides live alongside the code they cover, in `ai-review/`
subdirectories within each subsystem's source tree.

The triggers column below includes both path names, function calls, and symbols
regexes

## Subsystem Guides

| Subsystem | Triggers | File |
|-----------|----------|------|
| Networking | net/, drivers/net/, skb_, sockets | net/ai-review/networking.md |
| MM Page Tables | `pte_*`, `pmd_*`, `pud_*`, `set_pte`, `ptep_*`, `tlb_*`, `page_vma_mapped_walk`, `walk_page_range`, `zap_pte_range`, mm/memory.c, mm/mprotect.c, mm/pagewalk.c | mm/ai-review/mm-pagetable.md |
| MM Folio/Page Cache | `folio_*`, `page_folio`, `compound_head`, `filemap_*`, `xa_*`, `xas_*`, `page_cache_*`, mm/filemap.c, mm/swap.c, mm/truncate.c | mm/ai-review/mm-folio.md |
| MM Large Folios/THP/Hugetlb | `huge_memory`, `hugetlb`, `split_huge_*`, `folio_test_large`, `hstate`, PMD sharing, mm/huge_memory.c, mm/hugetlb.c, mm/memory-failure.c | mm/ai-review/mm-largepage.md |
| MM VMA Operations | `vma_*`, `mmap_*`, `vm_area_struct`, `vm_flags`, `anon_vma`, `maple_tree`, mm/vma.c, mm/mmap.c, mm/mmap_lock.c | mm/ai-review/mm-vma.md |
| MM Allocation | `alloc_pages`, `__GFP_*`, `kmalloc`, `kmem_cache_*`, `slub`, `vmalloc`, `zone_watermark`, `mempool`, `memblock`, mm/page_alloc.c, mm/slub.c, mm/vmalloc.c | mm/ai-review/mm-alloc.md |
| MM Reclaim/Swap/Migration | `vmscan`, `shrink_*`, `lru_*`, `swap_*`, `shmem_*`, `mem_cgroup_*`, `writeback`, `migrate_*`, mm/vmscan.c, mm/swap_state.c, mm/migrate.c, mm/memcontrol.c | mm/ai-review/mm-reclaim.md |
| VFS | inode, dentry, vfs_, fs/*.c | fs/ai-review/vfs.md |
| Locking | spin_lock*, mutex_*, rwsem*, seqlock*, *seqcount* | kernel/locking/ai-review/locking.md |
| Scheduler | kernel/sched/, sched_, schedule, *wakeup* | kernel/sched/ai-review/scheduler.md |
| Timers | timer_list, timer_setup, mod_timer, del_timer, hrtimer, delayed_work | kernel/time/ai-review/timers.md |
| BPF | kernel/bpf/, bpf, verifier | kernel/bpf/ai-review/bpf.md |
| RCU | rcu*, call_rcu, synchronize_rcu, kfree_rcu, kvfree_call_rcu | kernel/rcu/ai-review/rcu.md |
| Encryption | crypto, fscrypt_ | fs/crypto/ai-review/fscrypt.md |
| Tracing | trace_, tracepoints | kernel/trace/ai-review/tracing.md |
| Workqueue | kernel/workqueue.c, work_struct | kernel/ai-review/workqueue.md |
| Syscalls | `SYSCALL_DEFINE`, `copy_from_user`, `copy_to_user`, `get_user`, `put_user`, any change to syscall parameter validation | kernel/ai-review/syscall.md |
| btrfs | fs/btrfs/ | fs/btrfs/ai-review/btrfs.md |
| DAX | dax operations | drivers/dax/ai-review/dax.md |
| Block/NVMe | block layer, nvme | block/ai-review/block.md |
| DRM/GPU | drivers/gpu/drm/, drm_atomic_, drm_crtc_, hwseq, hw_sequencer | drivers/gpu/drm/ai-review/drm.md |
| NFSD | fs/nfsd/*, fs/lockd/* | fs/nfsd/ai-review/nfsd.md |
| SunRPC | net/sunrpc/* | net/sunrpc/ai-review/sunrpc.md |
| io_uring | io_uring/, io_uring_, io_ring_, io_sq_, io_cq_, io_wq_, IORING_ | io_uring/ai-review/io_uring.md |
| Cleanup API | `__free`, `guard(`, `scoped_guard`, `DEFINE_FREE`, `DEFINE_GUARD`, `no_free_ptr`, `return_ptr` | kernel/ai-review/cleanup.md |
| RCU lifecycle | `call_rcu(`, `kfree_rcu(`, `synchronize_rcu(`, `rhashtable_*` + `call_rcu`, `hlist_del_rcu` + `call_rcu`, `list_del_rcu` + `call_rcu` | kernel/rcu/ai-review/rcu.md |
| Power Domains | drivers/pmdomain/, pm_genpd_, of_genpd_, exynos_pd_ | drivers/pmdomain/ai-review/pmdomain.md |
| PM Runtime | include/linux/pm_runtime.h, pm_runtime_, __pm_runtime_, rpm_idle, rpm_suspend, rpm_resume | drivers/pmdomain/ai-review/pm.md |
| Sysfs | fs/sysfs/, sysfs_create_group, sysfs_update_group, attribute_group, is_visible | fs/sysfs/ai-review/sysfs.md |
| CXL | drivers/cxl/, cxl_, hmat_get_extended_linear_cache_size | drivers/cxl/ai-review/cxl.md |
| Bluetooth | net/bluetooth/, hci_, HCI_LE_ADV, adv_instances, cur_adv_instance | net/bluetooth/ai-review/bluetooth.md |
| TTY/Serial | drivers/tty/, uart_add_one_port, uart_ops, serial_core | drivers/tty/ai-review/tty.md |
| PCI | drivers/pci/, pci_epc_, pci_epf_, pci_ep_ | drivers/pci/ai-review/pci.md |
| SMB/ksmbd | fs/smb/server/, ksmbd_, smb_direct_ | fs/smb/server/ai-review/smb-ksmbd.md |
| Open Firmware (DT) | drivers/of/, of_node, of_find_, of_get_, of_parse_, for_each_child_of_node, for_each_available_child_of_node, of_node_put, of_node_get | drivers/of/ai-review/of.md |
| Perf Tools | tools/perf/, openat, fdopendir, closedir | tools/perf/ai-review/perf.md |
| MIPS | arch/mips/, tlb_probe, tlb_read, tlb_write_indexed, write_c0_entryhi, read_c0_index, TLBP, TLBR, TLBWI | arch/mips/ai-review/mips.md |
| Wireless/mac80211 | drivers/net/wireless/, net/mac80211/, BSS_CHANGED_, vif_cfg_changed, link_info_changed, bss_info_changed | net/ai-review/wireless.md |
| Selftests | tools/testing/selftests/, TEST_PROGS, TEST_FILES, TEST_GEN_FILES | tools/testing/selftests/ai-review/selftests.md |
| DT Bindings | Documentation/devicetree/bindings/, *.yaml in devicetree | drivers/of/ai-review/dt-bindings.md |
| USB Storage | drivers/usb/storage/, unusual_devs.h, UNUSUAL_DEV, USB_SC_, USB_PR_ | drivers/usb/storage/ai-review/usb-storage.md |
| ATA/libata | drivers/ata/, ata_dev_, ata_port_, ata_read_log_, ATA_QUIRK_ | drivers/ata/ai-review/ata.md |
| I/O Accessors | writesl, readsl, writesw, readsw, writesb, readsb, __raw_writel, __raw_readl, FIFO | kernel/ai-review/io-accessors.md |
| Kconfig | Kconfig, `config `, `select `, `depends on `, `tristate `, `bool ` | scripts/kconfig/ai-review/kconfig.md |
| Objtool | tools/objtool/, INSN_BUG, INSN_TRAP, decode.c | tools/objtool/ai-review/objtool.md |
| KHO (Kexec Handover) | lib/test_kho.c, kho_, kho_is_enabled, kho_retrieve_subtree, kho_preserve_folio, kho_add_subtree, register_kho_notifier | kernel/ai-review/kho.md |

## Optional Patterns

Load only when explicitly requested in the prompt:

- **Subjective Review** (ai-review/subjective-review.md): Subjective general assessment
