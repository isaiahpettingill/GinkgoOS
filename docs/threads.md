# Thread architecture

GinkgoOS schedules threads. A process is the protection, authority, and resource container for one or more generation-tagged threads.

## Current milestone

Every successful process launch creates a main `Thread`. The process owns that thread through a process-local generation table. The userspace scheduler selects a `ThreadRef` containing both `ProcessId` and `ThreadId`; it no longer selects a bare process as the execution identity.

This milestone deliberately enforces one live thread per process. `ThreadCreate` therefore returns `Status::ResourceLimit` while the main thread exists. The fixed ABI already carries entry, argument, stack-size, and TLS fields so later multi-thread support does not need to change syscall layouts or numbers.

The limit keeps existing applications unchanged while removing the old ownership assumption that CPU and blocking state belongs directly to `Process`.

## Ownership

A process owns:

- its address space and semantic virtual-memory areas;
- capability table and startup authority;
- application identity and process control;
- memory, traffic, and aggregate CPU accounting;
- shared mappings and retained file backing;
- a generation-checked thread table;
- final process status and teardown.

A thread owns:

- the complete `UserContext`, including integer and x87/SSE/AVX state;
- user entry point and stack layout;
- runnable, blocked, and terminal scheduler state;
- blocked syscall continuation and deadline;
- preemption and CPU-time accounting;
- a process-local generation-tagged `ThreadId`.

The existing x86-64 entry path switches away from the user stack before Rust runs and uses protected supervisor entry stacks. Dedicated dynamically allocated kernel stacks are required before the one-live-thread limit can be lifted.

## Identity and scheduling

`ThreadId` uses the same 64-bit slot-and-generation shape as `ProcessId`. Generation zero and raw zero are invalid. Scheduler references always contain both IDs:

```text
ThreadRef {
    process_id: ProcessId,
    thread_id: ThreadId,
}
```

Both generations must resolve before dispatch. A stale process ID cannot name a replacement process, and a stale thread ID cannot name a reused thread slot in the same process.

The permanent process-runner kernel task still performs bounded maintenance. Its round-robin selector now returns `ThreadRef`. It activates the owner process address space, enters that thread's `UserContext`, charges time and preemption to the thread and process, polls that thread's blocked operation, and retires the process only after its last thread is terminal.

## State and termination policy

The current one-thread transitions are:

```text
Ready -> Blocked -> Ready
Ready -> Exited
Ready/Blocked -> Faulted
Ready/Blocked -> Terminated
```

Blocked syscall ownership moves with the thread. Exit, fault, and external termination discard the continuation before final status is published.

`ProcessExit` remains process-wide for compatibility. `ThreadExit` exits only the caller in the ABI; with one live thread, it is also the last-thread exit and finalizes the process with the supplied code.

Fatal userspace faults terminate the complete process. This conservative rule prevents sibling execution after an invariant may have been damaged. Recoverable stack-growth page faults resume the faulting thread. When multiple live threads are enabled, stack VMAs must carry thread ownership so one thread cannot grow another thread's stack.

External process termination cancels every thread. Thread termination targets one process-local generation ID. In the current one-thread milestone, terminating the main thread terminates the process.

## ABI

Syscall numbers are append-only:

| Number | Call | Current behavior |
| ---: | --- | --- |
| 53 | `ThreadCreate` | Returns `ResourceLimit` under the one-live-thread policy. |
| 54 | `ThreadExit` | Exits the caller; this is currently the last-thread exit. |
| 55 | `ThreadYield` | Yields the caller. Syscall 0 remains a compatible alias. |
| 56 | `ThreadSleepUntil` | Past/current deadlines complete immediately; a future blocking deadline returns `ResourceLimit` until delegated wake authority lands. |
| 57 | `ThreadWake` | Validates a process-local generation ID; waking the only live, non-sleeping thread is an idempotent success. |
| 58 | `ThreadTerminate` | Terminates the selected local thread. |
| 59 | `ThreadGetInfo` | Returns versioned state, identity, fault, CPU-time, and preemption data. |
| 60 | `ThreadJoin` | Self-join is rejected; no other live thread can exist under the current policy. |
| 61 | `ThreadDetach` | Validates and releases join interest; currently no extra retained join state exists. |
| 62 | `ThreadGetCurrent` | Returns the calling thread's process-local generation ID. |

`ThreadCreateArgs` reserves stable fields for a kernel-selected guarded stack and future TLS base. `ThreadInfo` uses raw state and fault integers so a future kernel cannot place an unknown Rust enum discriminant into an older binary.

## Capability and address-space rules

All threads in a process will share one capability table and address space. Thread creation cannot grant rights or create cross-process authority. The current single-core scheduler serializes access. Lifting the one-live-thread limit requires synchronized capability-table and process-resource access without changing handle rights.

A thread ID is diagnostic and scheduler-facing, not a capability. Calls accepting a thread ID are limited to the calling process. Cross-process thread control must use an explicit capability object if added later.

## Resource policy

The active limit is one live thread per process. Before increasing it, policy must separately bound:

- live and retained terminal thread records;
- reserved and committed user-stack pages;
- protected kernel-stack bytes;
- TLS bytes;
- scheduler and wait metadata.

Creation must reserve all metadata before publishing an ID. Failure must leave no stack mapping, scheduler entry, accounting charge, or visible identity.

## SMP assumptions

Scheduling and teardown are single-core. The kernel restores the kernel CR3 before process retirement. Future SMP support must add:

- an atomic active-thread marker per CPU;
- remote TLB shootdown before address-space or stack reuse;
- safe switching of per-thread kernel entry stacks;
- migration-safe FPU and TLS restore;
- cancellation that waits until no CPU or queued wake references a thread;
- locking or ownership transfer for shared process resources.

A thread slot cannot be reused until every scheduler, wake, join, and CPU reference is unreachable. Generation wrap permanently retires a slot.

## Validation

Host tests cover:

- process and thread identity validation;
- thread-reference scheduler selection;
- blocking continuation ownership and cancellation;
- preemption and CPU-time saturation;
- terminal process status publication;
- stack growth and guard behavior;
- syscall number and fixed-layout ABI stability.

Existing process, preemption, memory-policy, process-capability, and frame-reclaim QEMU probes continue to exercise automatically created main threads. Multi-thread churn, FPU isolation between sibling threads, per-thread guarded-stack faults, and process-termination races are required before lifting the one-live-thread limit.
