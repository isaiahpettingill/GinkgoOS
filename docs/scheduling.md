# Thread scheduling policy

GinkgoOS uses a bounded, single-core, priority-aware thread scheduler. Threads are scheduler entities; processes retain aggregate resource accounting and authority.

## Classes and admission

Classes, from strongest to weakest, are:

1. `Critical` for bounded kernel completion work.
2. `Audio` for admitted system audio and bounded real-time service work.
3. `Interactive` for focused desktop and game work.
4. `Normal` for ordinary applications and services.
5. `Background` for installation, indexing, compilation, writeback, and maintenance.

Ordinary userspace may select only `Normal` or `Background`. System policy may assign `Audio` or `Interactive`. Only kernel policy may assign `Critical`. A userspace class request cannot raise a thread above its authority.

## Default policy

| Class | Quantum | Budget | Period | Starvation bound | Wake target |
| --- | ---: | ---: | ---: | ---: | ---: |
| Critical | 0.25 ms | 1 ms | 5 ms | 1 ms | 0.25 ms |
| Audio | 1 ms | 3 ms | 10 ms | 4 ms | 1 ms |
| Interactive | 2 ms | 16 ms | 16 ms | 8 ms | 2 ms |
| Normal | 4 ms | 8 ms | 20 ms | 20 ms | 5 ms |
| Background | 5 ms | 5 ms | 25 ms | 50 ms | 20 ms |

Every class is budgeted. Exhausted threads are throttled until their next period, so even admitted real-time work cannot permanently monopolize the CPU. Actual elapsed time is charged, including timer overrun. FIFO queues provide fairness within a class. If a class head exceeds its starvation bound, the oldest weaker class can bypass stronger work.

Runnable jobs with service deadlines use earliest-deadline-first order before class aging. A sleep deadline is a release time, not an execution deadline: after wake, the job receives a service deadline one class period after release. Object and dependency completions receive the class wake-latency target. The deadline remains active across short syscall turns until the job blocks or explicitly yields. This prevents an expired release timestamp from letting one periodic thread delay a later audio job.

## Storage and overload

Scheduler storage is reserved once at boot for the process-table limit multiplied by 64 threads per process. Thread records, all five run queues, and donation records do not grow during scheduling. Admission fails instead of allocating after boot. Ready threads never run through the blocked-maintenance fallback, so a failed admission cannot bypass budgets.

Under CPU overload, critical and audio work keep short dispatch targets but remain budgeted; interactive work receives the next preference; normal and background work retain bounded progress through aging. Deadline and wake-target misses are counted instead of granting unbounded execution. Filesystem request service and writeback are rate-limited as background work rather than being stopped whenever a periodic deadline is near.

Waits register generation-tagged entries with each waitable object and an indexed deadline heap. Object notifications enqueue only registered waiters. The bounded wait task completes those continuations and wakes only their scheduler entities; it does not scan every blocked process. Deadline wakes use a bounded immediate process handoff so returning from the blocked syscall does not add a full kernel round.

## Donation

The policy model supports one active bounded dependency chain per donor. A chain may contain at most eight recipients and last at most 50 ms. Donation raises only effective class; it does not change base authority. A token covers the whole chain. Normal completion, timeout, cancellation, donor exit, and disconnect remove the token and recompute every recipient's effective class. Cycles, excessive depth/duration, duplicate donor chains, and exhausted bounded storage are rejected before mutation.

Synchronous kernel operations must supply an owner chain before using donation. Asynchronous channels do not imply a single owner and therefore do not donate by themselves.

## Accounting

`ThreadGetSchedulingInfo` reports:

- base and effective class;
- current budget and state;
- CPU time and runnable wait time;
- total, maximum, and sampled wake latency;
- wake-target misses and context switches;
- deadline misses;
- throttle count and throttled time.

Counters saturate. Deadlines are absolute monotonic nanoseconds. Readiness is checked before timeout when both occur together. Scheduler snapshots for every thread in a process are refreshed after policy changes so sibling diagnostic queries do not report stale effective classes.

## Validation

Deterministic model tests cover class order, FIFO rotation, budgets, replenishment, throttling, starvation aging, EDF order, repeated deadline turns, deadline accounting, direct wake accounting, privileged admission, bounded storage, nested donation, timeout, disconnect, and generation reuse.

`make scheduler-smoke` runs a strict QEMU overload workload with a 60 Hz render thread, a 10 ms audio period, input events, two normal CPU hogs, and 1 MiB of background filesystem writes plus sync. It requires 180 frames with no misses, at least 300 audio periods with no deadline misses or underruns, input latency at most 20 ms, full background progress, CPU-hog progress, and admission and nested-donation checks. The harness does not relax these limits when QEMU is under load.

## SMP preparation

Keys contain process and thread generations and do not encode a CPU. Running threads are absent from run queues, which permits later per-CPU dispatch. SMP still needs queue locking or ownership, affinity, migration accounting, remote wakeups, and TLB/FPU handoff.
