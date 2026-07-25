# Thread architecture

GinkgoOS schedules threads. A process is the protection, authority, address-space, capability, quota, and teardown container for one or more generation-tagged threads.

## Ownership

A process owns its address space, VMAs, capability table, shared mappings, file backing, process control, aggregate accounting, thread table, and final status. A thread owns:

- a complete `UserContext`, including integer, x87/SSE/AVX, and FS-base TLS state;
- a guarded user stack with thread-owned stack VMAs;
- dedicated 64 KiB supervisor RSP0 and syscall-entry stacks;
- runnable, blocked, sleeping, and terminal state;
- its blocked syscall continuation, deadline, wake permit, and join state;
- scheduling class, budget, CPU time, wait/latency counters, and preemption count;
- a process-local generation-tagged `ThreadId`.

The kernel limits each process to 64 retained live or joinable thread records. Creation reserves the thread slot, VM metadata, initial user pages, and protected entry stacks before publishing the ID. Failed creation removes mappings and accounting before returning.

## Identity and scheduling

`ThreadId` and `ProcessId` are 64-bit slot-and-generation values. Generation zero is invalid. Scheduler keys contain both IDs:

```text
ThreadRef { process_id, thread_id }
```

Both generations must resolve before dispatch. Reaped slots increment their generation, so stale IDs cannot name replacements.

The scheduler dispatches only ready threads. Blocked continuations register with their waitable objects and the deadline heap, then return to the scheduler only after a targeted object, dependency, cancellation, or deadline notification. The kernel does not scan every blocked process. A selected thread installs its own supervisor RSP0 and syscall stack, address space, FS base, and extended CPU state. The CPU fallback stacks are restored before Rust scheduler code resumes, and the kernel CR3 is restored before reaping stacks or retiring a process.

## Lifecycle

```text
Ready -> Blocked -> Ready
Ready -> Exited
Ready/Blocked -> Terminated
Ready/Blocked -> process-wide Faulted
```

`ThreadExit` exits only the caller. It also marks that thread's outstanding asynchronous requests owner-terminated and delays thread-slot reuse until their copied buffers, page pins, shared-memory leases, and device ownership have drained. `ProcessExit` does the same for every sibling and publishes one process exit status. The last live thread finalizes the process only after process-wide request drain. Fatal userspace faults terminate the complete process; recoverable user-stack growth faults affect only the faulting thread.

A join claims one target. One caller may join a target, and timeout or caller cancellation releases the claim. Successful join copies terminal information before reaping; copy failure leaves the target joinable. Detach rejects an active join claim and causes terminal cleanup after the kernel CR3 and fallback entry stacks are restored. Process-wide exit clears every blocked continuation and join claim.

Wake uses a one-bit permit. Waking a sleeping thread completes its sleep immediately. Waking before sleep stores one permit, preventing the usual wake-before-block race. External process termination has a separate boot-preallocated observer queue. A terminate capability notifies the owning process ID directly, so a process blocked on an unrelated object is stopped without polling all blocked processes.

## ABI

Thread syscall numbers are append-only:

| Number | Call |
| ---: | --- |
| 53 | `ThreadCreate` |
| 54 | `ThreadExit` |
| 55 | `ThreadYield` |
| 56 | `ThreadSleepUntil` |
| 57 | `ThreadWake` |
| 58 | `ThreadTerminate` |
| 59 | `ThreadGetInfo` |
| 60 | `ThreadJoin` |
| 61 | `ThreadDetach` |
| 62 | `ThreadGetCurrent` |
| 63 | `ThreadSetSchedulingClass` |
| 64 | `ThreadGetSchedulingInfo` |

All thread IDs accepted by these calls are local to the calling process. Cross-process thread control requires a future capability object.

Threads share their process address space and capability table. Thread creation grants no rights. The TLS base must be zero or a canonical user address. GinkgoOS clears `CR4.FSGSBASE`; userspace cannot change FS base outside the saved kernel context.

## Stacks and faults

Each user stack has an unmapped guard page, reserved growth range, and initially committed zero-filled pages. Stack VMAs carry their owner `ThreadId`; a fault can grow only the current thread's stack and only within the stack-growth slop and resource limits.

Each thread also has separate supervisor-only RSP0 and syscall stacks. Their tops are 64-byte aligned because syscall context capture uses `XSAVE64`. User memory cannot map or write these stacks. Double-fault, NMI, and machine-check IST stacks remain per-CPU fail-stop stacks.

## SMP assumptions

The implementation is single-core but keeps process and thread identity separate. Future SMP work must add CPU ownership, migration-safe FS/FPU state, remote TLB shootdown, scheduler locking or per-CPU queues, and a grace period before stack or thread-slot reuse. A thread slot cannot be reused while any CPU, wake, join, donation, or scheduler reference can still reach it.

## Validation

Host tests cover multi-thread creation, independent contexts/stacks/TLS, generation reuse, round-robin identity, sleep/wake permits, join cancellation, main-thread reaping, last-thread exit, VM rollback, fault policy, and ABI layouts. `make thread-smoke` boots QEMU and creates two sibling threads, checks FS-base isolation across syscalls and preemption, exercises sleep/wake and yielding under different scheduling classes, joins both threads, and requires `ginkgo-thread-smoke: PASS`.
