# Asynchronous storage and filesystem execution

GinkgoOS uses one bounded asynchronous block queue for virtio-blk and AHCI. RedoxFS still uses its synchronous `Disk` interface, but that interface runs on a dedicated stackful filesystem fiber. A storage wait yields that fiber to the kernel task scheduler, so the requesting thread can remain blocked while input, audio, rendering, and unrelated threads continue.

## Runtime layers

The production path is:

```text
filesystem request
  -> fixed-capacity filesystem executor
  -> RedoxFS transaction
  -> 4 KiB write-back cache
  -> partition/volume adapter
  -> fiber-aware storage adapter
  -> bounded asynchronous block queue
  -> virtio-blk or AHCI
```

Boot discovery and initial mounting use bounded synchronous driver calls. After the IDT and local APIC are ready, the filesystem executor enables MSI-X for virtio-blk or MSI for AHCI and permanently switches the storage adapter to runtime mode. Runtime block calls are rejected outside the filesystem fiber.

The filesystem executor owns RedoxFS and runs one filesystem job at a time. This keeps RedoxFS transaction state and filesystem locking serialized. A job may yield many times while hardware owns a block request, but a second filesystem job does not enter RedoxFS until the first finishes. The hardware drivers and generic block queue support multiple in-flight commands; the raw QEMU storage tests exercise that depth. Normal RedoxFS traffic is currently serialized at the executor boundary.

## Block requests and bounds

Each request contains a generation-tagged ID, device and epoch, operation, LBA, checked byte range, priority, absolute monotonic deadline, ordering epoch, and owned DMA description. The queue is allocated at boot and does not grow on submission, dispatch, completion, cancellation, timeout, reset, removal, or shutdown.

The production storage adapter reserves eight DMA32 bounce pages and eight parent request slots. RedoxFS transfers are split into 4 KiB requests. Bounce ownership moves through available, leased, submitted, and quarantined states. A page returns to the pool only after the exact request completion or after reset/removal proves that DMA stopped. Stale and duplicate completions cannot release or complete a replacement request.

The queue supports latency, normal, and background priorities. Filesystem reads and ordinary operations use latency priority. Checkpoint and shutdown work uses normal priority. Periodic dirty writeback uses background priority. Weighted service, background aging, and a forced background-progress interval prevent starvation. Because the filesystem executor is serialized, this policy mainly applies to block work already admitted by one active filesystem job.

## Virtio-blk

The virtio driver supports transitional PCI devices through one split virtqueue. Runtime setup negotiates supported features, configures MSI-X, reserves fixed descriptor blocks per request slot, and maps used-ring heads back to exact dispatch tokens. Descriptor chains support multiple scatter/gather segments and out-of-order used completions.

The interrupt handler only records pending work. Deferred driver polling validates used-index movement, descriptor ownership, used lengths, status bytes, and device state before publishing completion. A watchdog poll preserves progress if an interrupt is lost.

A reset writes device status zero and waits until the device reports zero before queue ownership is released. Reset is terminal for the current driver instance; the storage adapter offlines the queue device after DMA-stop proof rather than accepting work that cannot run.

## AHCI

The AHCI driver claims one active SATA port. It parses both HBA and disk capabilities, enabling NCQ only when the HBA advertises `CAP.SNCQ` and IDENTIFY reports NCQ support. Negotiated depth is bounded by the controller slots, disk queue depth, and the fixed 32-slot driver limit. Without NCQ, the driver uses one non-NCQ command at a time.

Each active slot owns one command table and one exact dispatch token. PRDT construction validates address width, byte counts, segment count, and command-table bounds. One command can use up to 32 PRDT entries. Runtime reads and writes use queued FPDMA commands when NCQ is enabled. Flush uses an exclusive non-NCQ command after active commands drain.

MSI is enabled only after CPU interrupt setup. Per-vector masking is handled explicitly: vector zero is unmasked before MSI is enabled. The interrupt handler records pending work; deferred code reads and clears port status, matches completed `PxCI`/`PxSACT` bits to active slots, and publishes completions. A watchdog handles missed interrupts.

Reset stops command issue and FIS receive engines, then waits for `PxCMD.CR` and `PxCMD.FR` to clear. Slots remain quarantined if that proof fails. A proved reset is terminal for the current driver instance and offlines the queue device.

## Cache and durability

The fixed-capacity write-back cache stores complete 4 KiB blocks. Reads use dirty cache data first. Writes become acknowledged after the bytes enter the cache and receive a monotonic write sequence. Clean entries may be evicted; dirty entries stay owned until writeback succeeds.

A sync operation creates a durability ticket for the latest acknowledged sequence. Writeback sends dirty blocks in sequence order and issues the backing-device flush only after all blocks covered by the ticket have been written. The ticket becomes durable only after that flush succeeds. Writes submitted after a ticket do not cross its barrier.

Devices that do not advertise flush support skip the hardware flush command. This preserves operation on such hardware but cannot promise persistence through volatile device caches. Drivers reject an unsupported flush during ordinary execution, and shutdown does not manufacture a flush request for a device that declared no flush support.

A write or flush failure is sticky and makes the cache read-only. The periodic writeback task retries one failed backing operation after its normal delay. Write acceptance resumes only after that retry succeeds. Repeated failures stay visible and continue to reject writes.

## Shutdown and failure rules

Orderly shutdown follows these steps:

1. Stop new process launches and request admission.
2. Terminate remaining applications after their grace period.
3. Create and drain a RedoxFS durability checkpoint.
4. Quiesce the write-back cache.
5. Drain dirty data and the device shutdown flush in order.
6. Commit the firmware power transition.

A cancellation before irreversible storage shutdown resumes the filesystem executor, writeback, launch admission, and request admission. Once storage shutdown completes, the driver cannot be restarted in place. If firmware power-off or reboot then fails or times out, GinkgoOS remains quiesced and shows a terminal error instead of returning to a desktop backed by an offline device.

Timeout, cancellation, or driver error starts reset. Queue requests are failed only after the driver proves DMA stopped. The queue device is then removed, so later submissions fail immediately instead of entering a reset loop. If DMA-stop proof fails, buffers remain quarantined.

## Diagnostics

The generic queue records submissions, dispatches, completions, bytes, queue and in-flight high-water marks, queue/service latency, priority dispatches, starvation promotions, timeouts, cancellations, I/O errors, unsupported operations, stale and duplicate completions, resets, removals, shutdown flushes, and shutdown flush failures.

Driver snapshots add interrupt and watchdog counts, negotiated depth, in-flight slots, transferred bytes, errors, resets, DMA-stop proofs, and quarantine state. AHCI also reports NCQ, MSI, and PRDT high-water state. Virtio reports MSI-X and descriptor/used-ring state. The storage snapshot includes bounce-pool ownership and timeout settings. Writeback snapshots include resident and dirty counts, sequence and ticket state, cache hits/misses, evictions, backing reads/writes/flushes, retries, backpressure, and failures.

These snapshots are currently available to kernel jobs and QEMU smoke paths. A stable public storage-diagnostics syscall is not yet defined.

## Validation

Host tests cover queue ordering, weighted priority and aging, split requests, barriers, command-slot ownership, scatter/gather validation, bounce ownership, cancellation, timeout, stale and duplicate completion, reset/removal, shutdown, cache eviction, dirty writeback, durability tickets, retry, fiber switching, and filesystem executor bounds.

`make virtio-blk-smoke` boots a disposable GPT disk through virtio-blk, requires MSI-X, submits concurrent requests, transfers more than 4 KiB, verifies readback, and rejects errors or leaked queue state.

`make ahci-ncq-smoke` boots the same style of disk through AHCI, requires NCQ and MSI, uses multiple command slots and 32-entry PRDT transfers, verifies readback, and rejects errors, quarantined slots, or leaked queue state.

`make scheduler-smoke` runs rendering, audio, input, CPU hogs, and background RedoxFS writes together. `make power-smoke` checks orderly persistence, canceled shutdown, power-off, and reboot behavior on disposable images.
