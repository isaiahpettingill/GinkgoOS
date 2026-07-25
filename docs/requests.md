# Asynchronous request and completion framework

GinkgoOS uses one bounded request framework for operations that may finish immediately, block one thread, or return a waitable completion capability. The framework owns request identity, queueing, deadlines, cancellation races, lifecycle drain, and diagnostics. Services and drivers own operation-specific execution.

## Syscall ABI

The append-only request syscalls are:

| Number | Call | Purpose |
| ---: | --- | --- |
| 66 | `RequestSubmit` | Submit one copied and validated request. |
| 67 | `RequestCancel` | Request cancellation through a request capability with `MANAGE`. |
| 68 | `RequestGetInfo` | Read the stable request snapshot through `INSPECT`. |
| 69 | `RequestSubmitBatch` | Submit up to 16 requests atomically. |
| 70 | `RequestGetDiagnostics` | Read aggregate queue, latency, result, and pressure counters. |

Every argument and output structure starts with a version and size where later extension is expected. New fields are appended so existing prefixes keep their offsets. Unknown versions, sizes, flags, enum values, reserved fields, or invalid pointer ranges are rejected before a request is published.

`RequestSubmitArgs` contains the target capability, operation, completion mode, flags, buffer descriptor array, operation-specific scalar, absolute monotonic deadline, and opaque `user_data`. The kernel copies the complete argument and descriptor arrays before the syscall can block. `user_data` is returned without interpretation.

Production userspace can submit `Nop`, filesystem read/write/sync, and audio write operations when the target and its rights match. Filesystem open, truncate, and namespace operations are reserved for kernel adapters until their public request contracts are complete. `Synthetic` exists only in request-smoke kernels for completion and fault tests.

## Completion modes

`InlineOnly` accepts only work that can finish during submission. It returns no request handle. An operation that would need queued service returns `ShouldWait` without publishing a request.

`Block` publishes a request and blocks only the calling thread. The kernel retains a hidden request handle in the blocked continuation. Completion, timeout, cancellation, or owner termination directly notifies that thread. Completion copies outputs, unpins pages, closes the hidden handle, and resumes the syscall exactly once.

`Handle` returns a request capability. The object is level-triggered with `SIGNALED` after terminal publication and integrates with `wait_many`. Closing, duplicating, or transferring the capability does not cancel the operation. Cancellation requires `MANAGE`; inspection requires `INSPECT`; waiting requires `WAIT`.

## Identity, ownership, and ordering

Internal request IDs contain a slot and nonzero generation. Stale IDs cannot inspect, cancel, acknowledge, or complete a replacement request. A request records its owner process and thread, target identity, optional device identity, operation, deadline, timestamps, result, and resource charges.

Each target has a bounded FIFO. Dispatch rotates fairly between nonempty targets. Ordered requests retain target submission order. Chunked services requeue at the back of the target queue, allowing other targets and later fair turns to run. Concurrency is allowed only across targets or after a service explicitly transfers resource ownership to a device.

The runtime and all worker-path queues reserve their backing storage at boot. Submission preparation may allocate bounded copied metadata before publication. Completion, deadline, cancellation, reset, removal, termination, action dispatch, and resource release do not grow runtime collections.

## Logical state and resource state

The public logical states are:

```text
Pending -> Active -> Completing -> Completed
Pending/Active -> CancelPending -> Canceled
Pending/Active/CancelPending -> TimedOut
Pending/Active/CancelPending -> Failed
Pending/Active/CancelPending -> OwnerTerminated
```

Only one terminal state is published. Late or duplicate completion records cannot replace it. A completion timestamp, result status, transferred byte count, and result flags are frozen with that publication.

Resource ownership is tracked separately:

```text
KernelOwned -> DeviceOwned -> DrainPending -> ReleasePending -> Released
```

A logical timeout or cancellation may be visible before a device has stopped DMA. In that case the completion object is signaled, but pins and leases remain in `DrainPending`. A late completion, cancellation acknowledgement, reset, removal with bus mastering stopped, or explicit drain acknowledgement proves that device access ended. Only then does the runtime emit one release action. Release acknowledgement retires the slot and advances its generation.

This split prevents double publication, double wake, double unpin, stale DMA access, and stale completion reuse.

## Deadline and cancellation precedence

Deadlines are absolute monotonic nanoseconds. `DEADLINE_INFINITE` means no deadline. Completion records already queued for worker processing are handled before deadlines at the same worker timestamp, so a completion at the inclusive boundary wins when it was observed first.

Explicit cancellation records intent. Pending kernel-owned work can acknowledge cancellation immediately. Active device-owned work enters `CancelPending` and emits one bounded cancellation action. Completion may win before the device acknowledges cancellation; that result remains final and the lost cancellation race is counted. If cancellation wins, `CANCEL_ACKNOWLEDGED` is set. A deadline winner sets `DEADLINE_EXPIRED`.

Thread exit marks that thread's live requests `OwnerTerminated`. Process exit does the same for every thread in the process. Process retirement waits until every request resource is released. External process termination uses a dedicated boot-preallocated observer queue, so a blocked process is selected directly rather than waiting for a blocked-process scan.

Orderly shutdown calls `begin_shutdown`: new submissions receive backpressure, queued requests are canceled, active requests are asked to stop or drain, and power synchronization waits for `is_system_drained`. Canceling or failing the power transition reopens admission, but canceled requests are never resurrected. Device reset and removal use the same terminal and resource-drain rules.

## Buffer ownership

A request uses one of three explicit buffer policies.

### Copied buffers

`Copy` retains bounded kernel-owned bytes. Read buffers are copied from userspace before publication. Write buffers are copied back only through the owning process address space during completion. The broker stores the userspace address only as an integer and never dereferences it directly.

### Pinned buffers

`Pinned` validates every mapped page, access direction, range, and permission, then increments central page pin counts transactionally. Unmap, decommit, and incompatible protection changes return `ShouldWait` while any page is pinned. Failed preparation rolls back every earlier pin. Completion or terminal drain unpins each page once.

### Shared-memory buffers

`SharedMemory` takes a checked range lease with the required source rights. Closing or transferring the source handle cannot invalidate the request lease. The lease is released only after logical completion and any device drain.

A service must never hold an ordinary unpinned userspace pointer across a scheduler turn.

## Default limits and backpressure

| Resource | Per request | Per owner | System |
| --- | ---: | ---: | ---: |
| Live requests | — | 64 | 1,024 |
| Requests for one target | — | — | 32 |
| Atomic batch | 16 | — | — |
| Copied bytes | 16 KiB | 256 KiB | 4 MiB |
| Pinned pages | 64 | 256 | 4,096 |
| Shared-memory bytes | 1 MiB | 4 MiB | 32 MiB |
| Deferred completions | — | — | 1,024 |

Batch preflight checks the complete aggregate charge. Any invalid member or exceeded limit rejects the whole batch, leaves output handles invalid, and transfers no prepared resource. Queue pressure returns `ResourceLimit`; shutdown admission returns `ShouldWait`. No pressure path panics or allocates an unbounded queue.

One worker turn handles at most 32 deferred completions and 32 expired deadlines. Interrupt handlers may acknowledge hardware, copy one bounded completion record, and wake the worker. They must not copy user buffers, release process resources, or run large service continuations.

## Diagnostics

`RequestGetDiagnostics` reports current and peak queue depth, current and peak active requests, terminal publications, total and maximum queue/service latency, deadline misses, cancellation requests, transferred bytes, failed requests, rejected submissions, and dropped completion records. Counters saturate.

Internal tests also inspect live resources, copied bytes, pinned pages, shared bytes, deferred records, stale and duplicate completions, cancellation acknowledgements and lost races, lifecycle terminations, resets, removals, shutdowns, batch rollback, worker-budget exhaustion, release actions, and release acknowledgements.

## Validation

Host model tests cover every ordered terminal race, stale generation reuse, completion-at-deadline precedence, cancellation acknowledgement, late completion drain, reset/removal, owner thread and process exit, shutdown, exact resource release, queue fairness, chunk requeue, atomic batch rollback, all resource limits, deferred-worker budgets, fixed collection capacities, completion capabilities, copied/pinned/shared buffers, page mutation rejection while pinned, and ABI layouts.

`make request-smoke` boots QEMU and checks immediate, blocking, and handle completion modes; level-triggered wait completion; copied, pinned, and shared buffers; cancellation; deadline expiry followed by late and duplicate completion records; injected device reset and removal; 64 concurrent active requests and owner-limit rejection; atomic mixed batches; owner-thread termination; exact drain; and diagnostics. The harness rejects kernel faults, duplicate markers, leaked queue/active state, fewer than 64 peak active requests, missing timeout/cancellation/rejection activity, any failure count other than the two injected device failures, or dropped completions.
