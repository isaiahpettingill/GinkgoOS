# Memory architecture

GinkgoOS uses 4 KiB pages, 64-bit addresses and counters, and x86-64 four-level page tables. It does not swap or overcommit physical memory.

## CPU address widths

Boot reads CPUID leaf `0x80000008`. The physical width is validated in the range 12–52 bits and limits which Limine memory-map frames can enter the allocator. The reported linear width is retained for diagnostics. If the leaf is absent, boot uses a 36-bit physical default and a 48-bit linear default.

The active page-table implementation is deliberately four-level. Its virtual-address contract is 48 bits even when CPUID reports 57-bit linear addresses and LA57 support. Valid user addresses are in the canonical lower half below `0x0000_8000_0000_0000`; kernel addresses start at `0xffff_8000_0000_0000`. The noncanonical hole is never accepted.

## Physical memory

The frame allocator admits every page-aligned Limine `USABLE` range that fits the CPUID physical width. Zero-length entries are ignored. Overlap between a usable entry and any other memory-map entry is a boot error. Firmware, bootloader, kernel image, framebuffer, ACPI, MMIO, and other non-usable Limine entries never become eligible. Frames already used by the active page-table tree are also reserved before ordinary allocation.

Ownership is exact. A frame is fresh, live, reclaimed-free, or permanently reserved. Batch reclaim preflights the complete set and rejects duplicate, never-issued, already-free, or reserved frames without partial mutation.

Ordinary allocation is high-first when RAM exists above 4 GiB. It consumes frames at or above `0x1_0000_0000` before falling back below 4 GiB. This preserves low memory for devices with 32-bit DMA limits. Reclaimed frames are eligible under the same bounds.

DMA32 callers use explicit bounded allocation below 4 GiB. The allocator tracks DMA-low allocation, live-frame, and failure counts. Current drivers use bounded low frames or reject addresses they cannot issue to hardware; there is no IOMMU support and no general bounce-buffer service yet. Ordinary memory is not constrained to DMA32.

Every newly allocated private, stack, page-table, and shared-memory frame is zeroed before use or userspace exposure. Recycled frames therefore cannot disclose bytes from a previous owner.

## Virtual address layout

The active layout is:

| Range | Use |
| --- | --- |
| `0x0000_0000_0000_0000..0x0000_0000_0000_1000` | Unmapped null page |
| Caller-selected `ET_EXEC` ranges | Fixed image VMAs, validated below the user ceiling |
| Biases `0x0000_0000_2000_0000..0x0000_0000_6000_0000` | 512 possible 2 MiB-aligned static `ET_DYN` image biases |
| From `0x0000_0001_0000_0000` | Automatic anonymous, shared, and file mappings; the first cursor receives up to 16,383 pages of independent random displacement and then advances by first-fit placement |
| Below the randomized stack guard | Remaining user mapping/heap space, subject to process quotas and collision checks |
| Up to 8 MiB below stack top | Reserved downward-growing stack |
| One page below the stack | Permanent guard VMA |
| Stack top at or below `0x0000_7fff_ffff_f000` | Initial 64 KiB commit; top moves down by 0–1023 independently selected 2 MiB slots |
| `0x0000_8000_0000_0000..0xffff_7fff_ffff_ffff` | Noncanonical hole |
| From `0xffff_8000_0000_0000` | Supervisor-only kernel half and Limine-selected HHDM mappings |
| `0xffff_b000_0000_0000..0xffff_b010_0000_0000` | Growable page-backed kernel heap, up to 64 GiB of virtual space |
| From `0xffff_ffff_8000_0000` | Linked kernel image and its 32 MiB bootstrap heap |

The HHDM base is supplied by Limine, so it is not a fixed address in this contract. User address spaces clone only the kernel higher-half topology and force those root entries supervisor-only.

The userspace Talc runtime obtains heap space from anonymous reserve/commit/unmap calls. It has no fixed static 2 MiB heap. Virtual reservations are bounded by process policy but consume no frames until commit.

## Semantic VMAs

Each process owns a sorted, bounded semantic VMA table. Adjacent private entries merge only when their kind, backing identity, commitment state, protection, and backing offsets allow it. Shared VMAs never merge, so each query result stays within one mapping and one shared kernel-object identity.

- **Image**: eagerly committed ELF `PT_LOAD` pages. The ELF source is not an ongoing mapping authority.
- **Anonymous**: a private reservation identity with committed or uncommitted subranges. The identity is process-local and lasts until that reservation is fully unmapped. Committed pages are zero-filled.
- **Stack**: the full stack maximum is reserved. The initial top pages are committed and eligible faults grow the commit downward transactionally.
- **Guard**: reserved and inaccessible. A guard fault terminates the process with a page fault.
- **Shared**: a frame-backed shared kernel-object alias. It is fully committed while mapped and retains an owning lease. Its identity is stable across duplicated or transferred handles and mapping leases in the same capability graph object. The internal VMA also records the source object offset, although the v1 query ABI exposes only the identity-scoped virtual bounds. Creating two IPC objects over the same `SharedMemoryStorage` produces two object identities even though their bytes may alias.
- **File**: an eager private snapshot tied to a retained generation-protected file identity. Its `backing_identity` is a process-local backing-record ID, not the filesystem node or a system-wide ID. Committed and decommitted subranges keep their source offset.

`MapProtection` bit 0 is read, bit 1 is write, and bit 2 is execute. Unknown bits are rejected. Private image, anonymous, stack, and file mappings enforce W^X. Shared mappings require read and may add write; executable shared mappings are not supported.

## Lifecycle syscalls

Syscalls use the x86-64 convention: number in `RAX`; arguments in `RDI`, `RSI`, `RDX`, `R10`, `R8`, and `R9`; signed `Status` in `RAX`.

| Number | Call | Register arguments |
| ---: | --- | --- |
| 8 | `SharedMemoryCreate` | size, output |
| 9 | `SharedMemoryGetSize` | handle, output |
| 10 | `SharedMemoryMap` | handle, `SharedMemoryMapArgs*`, output |
| 11 | `SharedMemoryUnmap` | address, original logical length |
| 39 | `AnonymousMap` | length, protection, output |
| 40 | `AnonymousUnmap` | address, length |
| 41 | `AnonymousProtect` | address, length, protection |
| 42 | `AnonymousReserve` | length, protection, output |
| 43 | `AnonymousCommit` | address, length |
| 44 | `AnonymousDecommit` | address, length |
| 45 | `MemoryGetInfo` | output, size, version |
| 46 | `VirtualMapFile` | file handle, `VirtualMapFileArgs*`, output |
| 47 | `VirtualCommit` | address, length |
| 48 | `VirtualDecommit` | address, length |
| 49 | `VirtualProtect` | address, length, protection |
| 50 | `VirtualUnmap` | address, length |
| 52 | `VirtualQuery` | address, output, version, size |

Lengths must be nonzero for map/reserve/commit/decommit/protect/unmap operations and are rounded up to whole pages. Addresses and file/shared offsets that name page boundaries must be 4 KiB aligned. Fixed placement validates the complete rounded range. Range arithmetic, canonicality, ownership, overlap, quota, VMA growth, and page-table metadata are checked before publication.

Planning and metadata allocation happen before visible VMA changes. Multi-page operations either publish the complete semantic change or leave the old mapping in place. Frame or PTE rollback failure is an internal invariant violation: the process is quarantined and retained ownership is not released. Kernel-heap rollback failure is fail-stop because continuing could alias physical ownership.

File mappings are private snapshots, not coherent file aliases. Initial commit reads the selected file bytes eagerly and zero-fills the page tail. Decommit releases private frames but retains file identity and offset. Recommit rereads the original generation. Closing the source handle is harmless; unlink invalidates that retained generation, and a new file at the same path is not the old backing.

## Commitment and OOM policy

GinkgoOS has no swap and makes no promise-style overcommit commitment.

- Reserve consumes virtual range and VMA quota only.
- Commit eagerly allocates and zeroes physical frames, or eagerly reads private file snapshot bytes.
- The kernel does not choose a global victim or reclaim another live process to satisfy a request.
- A syscall that cannot meet quota returns `ResourceLimit`; physical or kernel metadata exhaustion returns `OutOfMemory`.
- OOM during an eligible stack-growth fault is charged to and terminates the faulting process with `ProcessFault::OutOfMemory`.
- Kernel invariants remain live after ordinary process-scoped OOM. Corrupt rollback state fails stop or quarantines the owning process rather than freeing uncertain ownership.

## RAM-derived process policy

Default process limits are derived from currently available validated RAM with checked floors and ceilings. Private pages, created shared backing, mapped shared bytes, reserved virtual bytes, VMA count, executable image pages, executable source bytes, channel traffic, and CPU quantum are separate limits.

A child never gains a larger memory policy than its parent. Legacy creation receives the lower of the current RAM-derived defaults and the caller's limits. Versioned `ProcessCreate2` may request lower values, but every field is checked against that inherited ceiling. This transitive cap applies even when a process chain repeatedly creates children. Capabilities still decide which operations are authorized; quotas only bound authorized use.

## Accounting ABI

`MemoryGetInfo` accepts exact supported `(version, size)` pairs. Version 1 is 288 bytes. Version 2 is 400 bytes and keeps the complete v1 layout as its prefix. Callers must not infer fields from another size.

The v1 prefix reports physical eligibility and availability, allocation and DMA failures, kernel heap commitment/headroom/failures, caller limits, reserved bytes, aggregate committed private pages, resident owned frames, shared charges, quota failures, and OOM failures.

Version 2 appends:

- current semantic VMA count;
- caller-owned page-table frames, including the P4 root;
- committed image, stack, anonymous, and private file-backed pages;
- shared-frame arena owned, idle/free, returned, reclaimed, and reclaim-failure counts;
- current system-wide live shared-object count, logical bytes, and page-rounded backing bytes.

`resident_owned_frames` includes mapped and retired private frames plus page-table frames. It excludes non-owning shared aliases. `shared_memory_bytes` is page-rounded backing charged to objects created by the caller. `mapped_shared_bytes` is the page-rounded alias charge. Arena owned frames remain owned until an allocator safe point reclaims idle frames.

`VirtualQuery` is syscall 52 and accepts only version 1 with an exact 80-byte output. The queried address must be a canonical, non-null lower-half user address. A valid gap returns `NotFound`. The record contains start/end, stable kind, protection bits, committed/reserved bytes and pages, opaque backing identity, and file offset. The returned bounds never cross a shared mapping or shared kernel-object identity. Shared identities are stable capability-graph object IDs; anonymous reservation and file backing-record identities are process-local. Separately created shared objects have distinct IDs even if they use the same underlying storage. All identities are integer tokens, never kernel pointers or physical addresses. Existing `SharedMemoryGetSize` remains the source for a shared object's logical byte length.

Both ABIs are append-only. Existing syscall numbers, enum values, field offsets, and v1 prefix meaning are covered by layout tests.

## Kernel heap and failure invariants

Early allocation uses a linked 32 MiB bootstrap Talc arena. It remains mapped forever because early objects may still refer to it. Normal allocation adds a 16 MiB page-backed region at `0xffff_b000_0000_0000` and grows it in bounded, page-rounded steps toward `0xffff_b010_0000_0000`.

Scheduler maintenance asks for adaptive free heap headroom derived from RAM and clamped from 8 MiB to 256 MiB. Growth leaves at least 64 physical frames outside the heap and conservatively budgets two frames per added heap page. Low-memory growth can defer and retry after frames return. Mapping is installed before Talc receives the range. A failed map rolls back exact frames; an incomplete rollback fails stop. Talc rejecting or partially consuming a successfully mapped extension also fails stop because allocator and page-table ownership would disagree.

## Shared-frame leases

A shared-memory object owns a list of distinct physical frames. Handles, transferred aliases, windows, and process mappings hold reference-counted ownership. Mapping records retain a lease after the source handle closes. Unmap drops that lease only after all PTE aliases are unreachable. Process retirement first switches back to the kernel CR3 and removes aliases, then releases mappings and object references.

When the last storage owner drops, its frames move to the shared-frame arena without allocation. The scheduler's safe point returns idle arena frames to the general allocator. Failed reclaim keeps exact arena ownership and increments a retry-visible failure counter; a later round retries. No frame is freed while an object, address space, DMA operation, or CPU may still reference it.

## CR3 and TLB rules

The scheduler is single-core. A process address space is active only while its userspace or syscall copy path runs. Retirement switches to the kernel CR3 before reclaiming the process root, lower page tables, and data frames. Local page-table edits use the current CPU's invalidation path.

SMP must not reuse these rules unchanged. Before any frame reachable by another CPU's TLB can be reclaimed or reused, the kernel will need remote shootdown acknowledgements and CPU/address-space lifetime tracking. Until that exists, GinkgoOS does not claim SMP-safe revocation.

## Test targets and markers

`make memory-policy-smoke` boots three fresh QEMU cases: 256 MiB (`low`), 512 MiB (`normal`), and 5 GiB (`high`). The harness checks RAM accounting, high-first allocation above 4 GiB in the high case, DMA32 preservation, HHDM access, shared and anonymous map/unmap/reclaim identity, stack growth, guard and protection faults, process-scoped OOM, witness progress, and exact retirement. Each boot must emit exactly one `ginkgo-memory-policy-smoke: <case> PASS`; the host ends with `memory-policy-smoke: matrix PASS`.

`make frame-reclaim-smoke` boots with 256 MiB and runs 512 alternating clean-exit and faulting process cycles with shared-memory leases. It requires stable live frame/shared backing counts and frame reuse after warmup. Success is the single marker `frame-reclaim stress passed cycles=512 ...`.

Host tests cover CPUID widths, canonical ranges, allocator overflow and ownership, VMA split/merge, reserve/commit/decommit/protect/unmap, guard growth, quota and rollback behavior, stable syscall/enum/layout values, malformed `VirtualQuery`, and each public VMA kind.
