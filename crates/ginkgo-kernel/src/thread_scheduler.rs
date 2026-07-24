//! Deterministic, priority-aware thread scheduling policy.
//!
//! This module owns no clocks, interrupt state, or architecture context. Callers
//! provide monotonic nanosecond timestamps and perform the context switch described
//! by [`Dispatch`]. That keeps policy testable on a host and leaves mechanism in the
//! kernel scheduler.
//!
//! Classes are strictly ordered, but every class is budgeted. FIFO queues provide
//! fairness within a class, while an oldest-first aging check lets lower classes
//! make bounded progress. Privileged base classes require the matching [`Authority`].
//! Priority donations may temporarily cross that authority boundary, but both their
//! chain depth and lifetime are bounded.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt::Debug;

pub const CLASS_COUNT: usize = 5;
pub const DEFAULT_MAX_DONATION_DEPTH: usize = 8;
pub const DEFAULT_MAX_DONATION_NS: u64 = 50_000_000;

/// A standalone generation-tagged identity suitable for scheduler integration.
///
/// The scheduler treats keys as opaque. A slot may be reused only with a new,
/// nonzero generation, making stale keys compare unequal to their replacement.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpaqueThreadKey {
    slot: u64,
    generation: u64,
}

impl OpaqueThreadKey {
    pub const fn new(slot: u64, generation: u64) -> Option<Self> {
        if generation == 0 {
            None
        } else {
            Some(Self { slot, generation })
        }
    }

    pub const fn slot(self) -> u64 {
        self.slot
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Key bound used by [`ThreadScheduler`]. Existing generation-safe kernel IDs can
/// be used directly without depending on this module's [`OpaqueThreadKey`].
pub trait SchedulerKey: Copy + Debug + Ord {}

impl<T: Copy + Debug + Ord> SchedulerKey for T {}

/// Lower numeric ranks have stronger dispatch preference.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SchedulingClass {
    Critical = 0,
    Audio = 1,
    Interactive = 2,
    Normal = 3,
    Background = 4,
}

impl SchedulingClass {
    pub const ALL: [Self; CLASS_COUNT] = [
        Self::Critical,
        Self::Audio,
        Self::Interactive,
        Self::Normal,
        Self::Background,
    ];

    const AGING_ORDER: [Self; CLASS_COUNT] = [
        Self::Background,
        Self::Normal,
        Self::Interactive,
        Self::Audio,
        Self::Critical,
    ];

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn higher(self, other: Self) -> Self {
        if (self as u8) < (other as u8) {
            self
        } else {
            other
        }
    }
}

/// Authority to assign a thread's base class. Donation is separately bounded and
/// may raise a recipient above the class it could select for itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authority {
    User,
    System,
    Kernel,
}

impl Authority {
    pub const fn allows(self, class: SchedulingClass) -> bool {
        match self {
            Self::User => matches!(class, SchedulingClass::Normal | SchedulingClass::Background),
            Self::System => !matches!(class, SchedulingClass::Critical),
            Self::Kernel => true,
        }
    }
}

/// Per-thread limits while a class is effective.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassPolicy {
    /// Maximum uninterrupted dispatch length.
    pub quantum_ns: u64,
    /// CPU time available to one thread during one period.
    pub budget_ns: u64,
    /// Budget replenishment period.
    pub period_ns: u64,
    /// Runnable wait after which this class may bypass stronger classes.
    pub starvation_ns: u64,
    /// Diagnostic target used when accounting wake latency.
    pub wake_latency_target_ns: u64,
}

impl ClassPolicy {
    pub const fn is_valid(self) -> bool {
        self.quantum_ns != 0
            && self.budget_ns != 0
            && self.period_ns != 0
            && self.starvation_ns != 0
            && self.wake_latency_target_ns != 0
            && self.quantum_ns <= self.budget_ns
            && self.budget_ns <= self.period_ns
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerConfig {
    pub classes: [ClassPolicy; CLASS_COUNT],
    pub max_donation_depth: usize,
    pub max_donation_ns: u64,
}

impl SchedulerConfig {
    pub const fn default_policy() -> Self {
        Self {
            classes: [
                ClassPolicy {
                    quantum_ns: 250_000,
                    budget_ns: 1_000_000,
                    period_ns: 5_000_000,
                    starvation_ns: 1_000_000,
                    wake_latency_target_ns: 250_000,
                },
                ClassPolicy {
                    quantum_ns: 1_000_000,
                    budget_ns: 3_000_000,
                    period_ns: 10_000_000,
                    starvation_ns: 4_000_000,
                    wake_latency_target_ns: 1_000_000,
                },
                ClassPolicy {
                    quantum_ns: 2_000_000,
                    budget_ns: 6_000_000,
                    period_ns: 16_000_000,
                    starvation_ns: 8_000_000,
                    wake_latency_target_ns: 2_000_000,
                },
                ClassPolicy {
                    quantum_ns: 4_000_000,
                    budget_ns: 8_000_000,
                    period_ns: 20_000_000,
                    starvation_ns: 20_000_000,
                    wake_latency_target_ns: 5_000_000,
                },
                ClassPolicy {
                    quantum_ns: 5_000_000,
                    budget_ns: 5_000_000,
                    period_ns: 25_000_000,
                    starvation_ns: 50_000_000,
                    wake_latency_target_ns: 20_000_000,
                },
            ],
            max_donation_depth: DEFAULT_MAX_DONATION_DEPTH,
            max_donation_ns: DEFAULT_MAX_DONATION_NS,
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.classes.iter().any(|policy| !policy.is_valid()) {
            return Err(ConfigError::InvalidClassPolicy);
        }
        if self.max_donation_depth == 0 {
            return Err(ConfigError::ZeroDonationDepth);
        }
        if self.max_donation_depth > DEFAULT_MAX_DONATION_DEPTH {
            return Err(ConfigError::DonationDepthTooLarge);
        }
        if self.max_donation_ns == 0 {
            return Err(ConfigError::ZeroDonationDuration);
        }
        Ok(())
    }
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self::default_policy()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    InvalidClassPolicy,
    ZeroDonationDepth,
    DonationDepthTooLarge,
    ZeroDonationDuration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadState {
    Runnable,
    Running,
    Blocked,
    Throttled,
}

/// Saturating lifetime counters. All time values are nanoseconds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ThreadMetrics {
    pub cpu_time_ns: u64,
    pub runnable_wait_ns: u64,
    pub wake_latency_ns: u64,
    pub maximum_wake_latency_ns: u64,
    pub wake_latency_samples: u64,
    pub wake_latency_target_misses: u64,
    pub context_switches: u64,
    pub deadline_misses: u64,
    pub throttling_events: u64,
    pub throttled_time_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadSnapshot {
    pub base_class: SchedulingClass,
    pub effective_class: SchedulingClass,
    pub authority: Authority,
    pub state: ThreadState,
    pub budget_remaining_ns: u64,
    pub next_replenishment_ns: u64,
    pub deadline_ns: Option<u64>,
    pub metrics: ThreadMetrics,
}

/// Work selected by [`ThreadScheduler::next_dispatch`]. The caller should run at
/// most `quantum_ns`, then report actual elapsed CPU time with [`ThreadScheduler::finish_dispatch`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dispatch<K> {
    pub key: K,
    pub class: SchedulingClass,
    pub quantum_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunDisposition {
    /// Requeue after a yield or preemption.
    Runnable,
    /// Keep the thread blocked until an explicit wake.
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DonationToken(u64);

impl DonationToken {
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerError {
    DuplicateKey,
    CapacityReached,
    UnknownKey,
    UnauthorizedClass(SchedulingClass),
    InvalidState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DonationError {
    UnknownKey,
    EmptyChain,
    CapacityReached,
    DonorAlreadyDonating,
    ChainTooDeep,
    Cycle,
    Expired,
    DurationTooLong,
    TokenExhausted,
}

#[derive(Clone, Copy, Debug)]
struct DonationChain<K> {
    token: DonationToken,
    root: K,
    class: SchedulingClass,
    expires_at_ns: u64,
    recipients: [K; DEFAULT_MAX_DONATION_DEPTH],
    recipient_count: usize,
}

impl<K> DonationChain<K> {
    fn recipients(&self) -> &[K] {
        &self.recipients[..self.recipient_count]
    }
}

#[derive(Debug)]
struct Thread {
    base_class: SchedulingClass,
    effective_class: SchedulingClass,
    authority: Authority,
    state: ThreadState,
    budget_remaining_ns: u64,
    period_started_ns: u64,
    runnable_since_ns: Option<u64>,
    pending_wake_ns: Option<u64>,
    throttled_since_ns: Option<u64>,
    deadline_ns: Option<u64>,
    metrics: ThreadMetrics,
}

/// Alloc-backed scheduler policy for one or more future dispatching CPUs.
///
/// Running threads are not stored in a run queue, so a caller may have more than
/// one outstanding [`Dispatch`] when SMP support is added. Mutating methods expect
/// monotonic timestamps; saturating arithmetic makes accidental clock regressions
/// harmless to accounting.
pub struct ThreadScheduler<K: SchedulerKey = OpaqueThreadKey> {
    config: SchedulerConfig,
    capacity: usize,
    threads: Vec<(K, Thread)>,
    queues: [VecDeque<K>; CLASS_COUNT],
    donations: Vec<DonationChain<K>>,
    next_donation_token: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerInitError {
    InvalidConfig(ConfigError),
    InvalidCapacity,
    OutOfMemory,
}

impl<K: SchedulerKey> ThreadScheduler<K> {
    pub fn try_new(config: SchedulerConfig, capacity: usize) -> Result<Self, SchedulerInitError> {
        config
            .validate()
            .map_err(SchedulerInitError::InvalidConfig)?;
        if capacity == 0 {
            return Err(SchedulerInitError::InvalidCapacity);
        }
        let mut threads = Vec::new();
        threads
            .try_reserve_exact(capacity)
            .map_err(|_| SchedulerInitError::OutOfMemory)?;
        let mut queues = core::array::from_fn(|_| VecDeque::new());
        for queue in &mut queues {
            queue
                .try_reserve_exact(capacity)
                .map_err(|_| SchedulerInitError::OutOfMemory)?;
        }
        let mut donations = Vec::new();
        donations
            .try_reserve_exact(capacity)
            .map_err(|_| SchedulerInitError::OutOfMemory)?;
        Ok(Self {
            config,
            capacity,
            threads,
            queues,
            donations,
            next_donation_token: 1,
        })
    }

    pub fn try_with_default_policy(capacity: usize) -> Result<Self, SchedulerInitError> {
        Self::try_new(SchedulerConfig::default(), capacity)
    }

    fn thread_index(&self, key: K) -> Result<usize, usize> {
        self.threads
            .binary_search_by_key(&key, |(candidate, _)| *candidate)
    }

    fn thread(&self, key: K) -> Option<&Thread> {
        self.thread_index(key)
            .ok()
            .map(|index| &self.threads[index].1)
    }

    fn thread_mut(&mut self, key: K) -> Option<&mut Thread> {
        self.thread_index(key)
            .ok()
            .map(|index| &mut self.threads[index].1)
    }

    pub const fn config(&self) -> &SchedulerConfig {
        &self.config
    }

    pub fn len(&self) -> usize {
        self.threads.len()
    }

    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }

    pub fn add_thread(
        &mut self,
        key: K,
        base_class: SchedulingClass,
        authority: Authority,
        now_ns: u64,
    ) -> Result<(), SchedulerError> {
        let insertion = match self.thread_index(key) {
            Ok(_) => return Err(SchedulerError::DuplicateKey),
            Err(insertion) => insertion,
        };
        if self.threads.len() == self.capacity {
            return Err(SchedulerError::CapacityReached);
        }
        if !authority.allows(base_class) {
            return Err(SchedulerError::UnauthorizedClass(base_class));
        }
        let policy = self.policy(base_class);
        self.threads.insert(
            insertion,
            (
                key,
                Thread {
                    base_class,
                    effective_class: base_class,
                    authority,
                    state: ThreadState::Runnable,
                    budget_remaining_ns: policy.budget_ns,
                    period_started_ns: now_ns,
                    runnable_since_ns: Some(now_ns),
                    pending_wake_ns: None,
                    throttled_since_ns: None,
                    deadline_ns: None,
                    metrics: ThreadMetrics::default(),
                },
            ),
        );
        self.queues[base_class.index()].push_back(key);
        Ok(())
    }

    /// Removes a thread and every donation rooted at it, as required on exit or disconnect.
    pub fn remove_thread(&mut self, key: K, now_ns: u64) -> Result<ThreadMetrics, SchedulerError> {
        let index = self
            .thread_index(key)
            .map_err(|_| SchedulerError::UnknownKey)?;
        self.cancel_donations_from(key, now_ns);
        self.remove_from_all_queues(key);
        Ok(self.threads.remove(index).1.metrics)
    }

    pub fn snapshot(&self, key: K) -> Option<ThreadSnapshot> {
        let thread = self.thread(key)?;
        let policy = self.policy(thread.effective_class);
        Some(ThreadSnapshot {
            base_class: thread.base_class,
            effective_class: thread.effective_class,
            authority: thread.authority,
            state: thread.state,
            budget_remaining_ns: thread.budget_remaining_ns,
            next_replenishment_ns: thread.period_started_ns.saturating_add(policy.period_ns),
            deadline_ns: thread.deadline_ns,
            metrics: thread.metrics,
        })
    }

    pub fn set_base_class(
        &mut self,
        key: K,
        class: SchedulingClass,
        now_ns: u64,
    ) -> Result<(), SchedulerError> {
        self.maintain_thread(key, now_ns)?;
        let effective = self.effective_class_for(key, class);
        let (old_class, new_class, state) = {
            let thread = self.thread_mut(key).ok_or(SchedulerError::UnknownKey)?;
            if !thread.authority.allows(class) {
                return Err(SchedulerError::UnauthorizedClass(class));
            }
            let old_class = thread.effective_class;
            thread.base_class = class;
            thread.effective_class = effective;
            (old_class, thread.effective_class, thread.state)
        };
        self.move_queue_if_needed(key, old_class, new_class, state);
        self.cap_budget_for_class(key);
        Ok(())
    }

    pub fn set_deadline(&mut self, key: K, deadline_ns: u64) -> Result<(), SchedulerError> {
        self.thread_mut(key)
            .ok_or(SchedulerError::UnknownKey)?
            .deadline_ns = Some(deadline_ns);
        Ok(())
    }

    pub fn clear_deadline(&mut self, key: K) -> Result<(), SchedulerError> {
        self.thread_mut(key)
            .ok_or(SchedulerError::UnknownKey)?
            .deadline_ns = None;
        Ok(())
    }

    pub fn record_deadline_miss(&mut self, key: K) -> Result<(), SchedulerError> {
        let thread = self.thread_mut(key).ok_or(SchedulerError::UnknownKey)?;
        thread.metrics.deadline_misses = thread.metrics.deadline_misses.saturating_add(1);
        Ok(())
    }

    /// Blocks a queued or currently running thread. Blocking a queued thread removes it directly;
    /// no scheduler-wide blocked-thread scan is needed for its later wake.
    pub fn block(&mut self, key: K) -> Result<(), SchedulerError> {
        let state = self.thread(key).ok_or(SchedulerError::UnknownKey)?.state;
        if !matches!(state, ThreadState::Runnable | ThreadState::Running) {
            return Err(SchedulerError::InvalidState);
        }
        self.remove_from_all_queues(key);
        let thread = self.thread_mut(key).expect("thread was checked");
        thread.state = ThreadState::Blocked;
        thread.runnable_since_ns = None;
        Ok(())
    }

    /// Directly wakes one blocked thread and starts wake-latency accounting.
    pub fn wake(&mut self, key: K, now_ns: u64) -> Result<(), SchedulerError> {
        self.maintain_thread(key, now_ns)?;
        let (class, runnable) = {
            let thread = self.thread_mut(key).ok_or(SchedulerError::UnknownKey)?;
            if thread.state != ThreadState::Blocked {
                return Err(SchedulerError::InvalidState);
            }
            thread.pending_wake_ns = Some(now_ns);
            thread.runnable_since_ns = Some(now_ns);
            if thread.budget_remaining_ns == 0 {
                thread.state = ThreadState::Throttled;
                thread.throttled_since_ns.get_or_insert(now_ns);
                (thread.effective_class, false)
            } else {
                thread.state = ThreadState::Runnable;
                (thread.effective_class, true)
            }
        };
        if runnable {
            self.queues[class.index()].push_back(key);
        }
        Ok(())
    }

    /// Runs expiry and replenishment maintenance, then selects one thread.
    ///
    /// Normally the strongest nonempty class wins. If one or more class heads have
    /// exceeded their starvation bound, the weakest aged class wins. This is
    /// deterministic and preserves FIFO order inside every class.
    pub fn next_dispatch(&mut self, now_ns: u64) -> Option<Dispatch<K>> {
        self.maintain(now_ns);
        let class = self.select_class(now_ns)?;
        let key = self.queues[class.index()].pop_front()?;
        let policy = self.policy(class);
        let thread = self.thread_mut(key).expect("run queue key must be live");
        debug_assert_eq!(thread.state, ThreadState::Runnable);
        debug_assert_eq!(thread.effective_class, class);

        if let Some(since) = thread.runnable_since_ns.take() {
            thread.metrics.runnable_wait_ns = thread
                .metrics
                .runnable_wait_ns
                .saturating_add(now_ns.saturating_sub(since));
        }
        if let Some(woke_at) = thread.pending_wake_ns.take() {
            let latency = now_ns.saturating_sub(woke_at);
            thread.metrics.wake_latency_ns = thread.metrics.wake_latency_ns.saturating_add(latency);
            thread.metrics.maximum_wake_latency_ns =
                thread.metrics.maximum_wake_latency_ns.max(latency);
            thread.metrics.wake_latency_samples =
                thread.metrics.wake_latency_samples.saturating_add(1);
            if latency > policy.wake_latency_target_ns {
                thread.metrics.wake_latency_target_misses =
                    thread.metrics.wake_latency_target_misses.saturating_add(1);
            }
        }
        if thread.deadline_ns.is_some_and(|deadline| now_ns > deadline) {
            thread.metrics.deadline_misses = thread.metrics.deadline_misses.saturating_add(1);
            thread.deadline_ns = None;
        }
        thread.state = ThreadState::Running;
        thread.metrics.context_switches = thread.metrics.context_switches.saturating_add(1);

        Some(Dispatch {
            key,
            class,
            quantum_ns: policy.quantum_ns.min(thread.budget_remaining_ns),
        })
    }

    /// Charges actual CPU time and completes a dispatch. Runtime is charged even if
    /// it exceeds the granted quantum, so a late timer cannot bypass throttling.
    pub fn finish_dispatch(
        &mut self,
        key: K,
        elapsed_ns: u64,
        now_ns: u64,
        disposition: RunDisposition,
    ) -> Result<(), SchedulerError> {
        let (class, state) = {
            let thread = self.thread_mut(key).ok_or(SchedulerError::UnknownKey)?;
            if thread.state != ThreadState::Running {
                return Err(SchedulerError::InvalidState);
            }
            thread.metrics.cpu_time_ns = thread.metrics.cpu_time_ns.saturating_add(elapsed_ns);
            thread.budget_remaining_ns = thread.budget_remaining_ns.saturating_sub(elapsed_ns);

            match disposition {
                RunDisposition::Blocked => {
                    thread.state = ThreadState::Blocked;
                    thread.runnable_since_ns = None;
                }
                RunDisposition::Runnable if thread.budget_remaining_ns == 0 => {
                    thread.state = ThreadState::Throttled;
                    thread.runnable_since_ns = Some(now_ns);
                    thread.throttled_since_ns = Some(now_ns);
                    thread.metrics.throttling_events =
                        thread.metrics.throttling_events.saturating_add(1);
                }
                RunDisposition::Runnable => {
                    thread.state = ThreadState::Runnable;
                    thread.runnable_since_ns = Some(now_ns);
                }
            }
            (thread.effective_class, thread.state)
        };
        if state == ThreadState::Runnable {
            self.queues[class.index()].push_back(key);
        }
        Ok(())
    }

    /// Donates the donor's effective class through each recipient in `chain`.
    ///
    /// `chain[0]` is the object owner directly blocking `donor`; later entries are
    /// nested owners. One token covers the whole chain, so cancellation, timeout,
    /// disconnect, and normal reply all unwind every applied boost together.
    pub fn donate_chain(
        &mut self,
        donor: K,
        chain: &[K],
        expires_at_ns: u64,
        now_ns: u64,
    ) -> Result<DonationToken, DonationError> {
        if chain.is_empty() {
            return Err(DonationError::EmptyChain);
        }
        if chain.len() > self.config.max_donation_depth {
            return Err(DonationError::ChainTooDeep);
        }
        if expires_at_ns <= now_ns {
            return Err(DonationError::Expired);
        }
        if expires_at_ns.saturating_sub(now_ns) > self.config.max_donation_ns {
            return Err(DonationError::DurationTooLong);
        }
        if self.donations.iter().any(|donation| donation.root == donor) {
            return Err(DonationError::DonorAlreadyDonating);
        }
        if self.donations.len() == self.capacity {
            return Err(DonationError::CapacityReached);
        }
        let donated_class = self
            .thread(donor)
            .ok_or(DonationError::UnknownKey)?
            .effective_class;
        for (index, key) in chain.iter().enumerate() {
            if *key == donor || chain[..index].contains(key) {
                return Err(DonationError::Cycle);
            }
            if self.thread(*key).is_none() {
                return Err(DonationError::UnknownKey);
            }
        }
        let token = DonationToken(self.next_donation_token);
        let next_token = self
            .next_donation_token
            .checked_add(1)
            .ok_or(DonationError::TokenExhausted)?;
        let mut recipients = [chain[0]; DEFAULT_MAX_DONATION_DEPTH];
        recipients[..chain.len()].copy_from_slice(chain);
        self.donations.push(DonationChain {
            token,
            root: donor,
            class: donated_class,
            expires_at_ns,
            recipients,
            recipient_count: chain.len(),
        });
        self.next_donation_token = next_token;
        for key in chain.iter().copied() {
            self.recompute_effective_class(key, now_ns);
        }
        Ok(token)
    }

    /// Cancels or normally unwinds a complete donation chain.
    pub fn cancel_donation(&mut self, token: DonationToken, now_ns: u64) -> bool {
        let Some(index) = self
            .donations
            .iter()
            .position(|donation| donation.token == token)
        else {
            return false;
        };
        let removed = self.donations.swap_remove(index);
        for key in removed.recipients().iter().copied() {
            self.recompute_effective_class(key, now_ns);
        }
        true
    }

    /// Unwinds all chains rooted at a disconnected, cancelled, or exiting donor.
    pub fn cancel_donations_from(&mut self, donor: K, now_ns: u64) -> usize {
        let Some(token) = self
            .donations
            .iter()
            .find(|donation| donation.root == donor)
            .map(|donation| donation.token)
        else {
            return 0;
        };
        usize::from(self.cancel_donation(token, now_ns))
    }

    /// Expires donations and replenishes all elapsed budgets.
    pub fn maintain(&mut self, now_ns: u64) {
        self.donations
            .retain(|donation| donation.expires_at_ns > now_ns);
        for index in 0..self.threads.len() {
            let key = self.threads[index].0;
            let _ = self.maintain_thread(key, now_ns);
        }
    }

    fn maintain_thread(&mut self, key: K, now_ns: u64) -> Result<(), SchedulerError> {
        let base_class = self
            .thread(key)
            .ok_or(SchedulerError::UnknownKey)?
            .base_class;
        let effective_class = self.effective_class_for(key, base_class);
        let policy = self.config.classes[effective_class.index()];
        let (old_class, new_class, old_state, new_state) = {
            let thread = self.thread_mut(key).ok_or(SchedulerError::UnknownKey)?;
            let old_class = thread.effective_class;
            let old_state = thread.state;
            thread.effective_class = effective_class;
            let period_end = thread.period_started_ns.saturating_add(policy.period_ns);
            if now_ns >= period_end {
                let elapsed = now_ns.saturating_sub(thread.period_started_ns);
                let periods = elapsed / policy.period_ns;
                thread.period_started_ns = thread
                    .period_started_ns
                    .saturating_add(periods.saturating_mul(policy.period_ns));
                thread.budget_remaining_ns = policy.budget_ns;
                if thread.state == ThreadState::Throttled {
                    if let Some(since) = thread.throttled_since_ns.take() {
                        thread.metrics.throttled_time_ns = thread
                            .metrics
                            .throttled_time_ns
                            .saturating_add(now_ns.saturating_sub(since));
                    }
                    thread.state = ThreadState::Runnable;
                    thread.runnable_since_ns.get_or_insert(now_ns);
                }
            } else {
                thread.budget_remaining_ns = thread.budget_remaining_ns.min(policy.budget_ns);
            }
            (old_class, thread.effective_class, old_state, thread.state)
        };

        if old_state == ThreadState::Runnable && old_class != new_class {
            self.remove_from_queue(old_class, key);
            if new_state == ThreadState::Runnable {
                self.queues[new_class.index()].push_back(key);
            }
        } else if old_state == ThreadState::Throttled && new_state == ThreadState::Runnable {
            self.queues[new_class.index()].push_back(key);
        }
        Ok(())
    }

    fn select_class(&self, now_ns: u64) -> Option<SchedulingClass> {
        for class in SchedulingClass::AGING_ORDER {
            let Some(key) = self.queues[class.index()].front() else {
                continue;
            };
            let thread = self.thread(*key).expect("run queue key must be live");
            let waited = now_ns.saturating_sub(thread.runnable_since_ns.unwrap_or(now_ns));
            if waited >= self.policy(class).starvation_ns {
                return Some(class);
            }
        }
        SchedulingClass::ALL
            .into_iter()
            .find(|class| !self.queues[class.index()].is_empty())
    }

    fn policy(&self, class: SchedulingClass) -> ClassPolicy {
        self.config.classes[class.index()]
    }

    fn cap_budget_for_class(&mut self, key: K) {
        let class = self
            .thread(key)
            .expect("thread key must be live")
            .effective_class;
        let budget = self.policy(class).budget_ns;
        let thread = self.thread_mut(key).expect("thread key must be live");
        thread.budget_remaining_ns = thread.budget_remaining_ns.min(budget);
    }

    fn effective_class_for(&self, key: K, base_class: SchedulingClass) -> SchedulingClass {
        self.donations
            .iter()
            .filter(|donation| donation.recipients().contains(&key))
            .fold(base_class, |class, donation| class.higher(donation.class))
    }

    fn recompute_effective_class(&mut self, key: K, now_ns: u64) {
        let Some(thread) = self.thread(key) else {
            return;
        };
        let old_class = thread.effective_class;
        let state = thread.state;
        let new_class = self.effective_class_for(key, thread.base_class);
        self.thread_mut(key)
            .expect("thread disappeared during class recomputation")
            .effective_class = new_class;
        self.move_queue_if_needed(key, old_class, new_class, state);
        self.cap_budget_for_class(key);
        let _ = self.maintain_thread(key, now_ns);
    }

    fn move_queue_if_needed(
        &mut self,
        key: K,
        old_class: SchedulingClass,
        new_class: SchedulingClass,
        state: ThreadState,
    ) {
        if state == ThreadState::Runnable && old_class != new_class {
            self.remove_from_queue(old_class, key);
            self.queues[new_class.index()].push_back(key);
        }
    }

    fn remove_from_queue(&mut self, class: SchedulingClass, key: K) {
        self.queues[class.index()].retain(|queued| *queued != key);
    }

    fn remove_from_all_queues(&mut self, key: K) {
        for queue in &mut self.queues {
            queue.retain(|queued| *queued != key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(slot: u64) -> OpaqueThreadKey {
        OpaqueThreadKey::new(slot, 1).unwrap()
    }

    fn add(
        scheduler: &mut ThreadScheduler,
        slot: u64,
        class: SchedulingClass,
        authority: Authority,
        now_ns: u64,
    ) {
        scheduler
            .add_thread(key(slot), class, authority, now_ns)
            .unwrap();
    }

    #[test]
    fn class_order_and_fifo_quantum_rotation_are_deterministic() {
        let mut scheduler = ThreadScheduler::try_with_default_policy(64).unwrap();
        add(
            &mut scheduler,
            1,
            SchedulingClass::Normal,
            Authority::User,
            0,
        );
        add(
            &mut scheduler,
            2,
            SchedulingClass::Interactive,
            Authority::System,
            0,
        );
        add(
            &mut scheduler,
            3,
            SchedulingClass::Interactive,
            Authority::System,
            0,
        );

        let first = scheduler.next_dispatch(0).unwrap();
        assert_eq!(first.key, key(2));
        assert_eq!(first.class, SchedulingClass::Interactive);
        assert_eq!(first.quantum_ns, 2_000_000);
        scheduler
            .finish_dispatch(
                first.key,
                first.quantum_ns,
                2_000_000,
                RunDisposition::Runnable,
            )
            .unwrap();

        let second = scheduler.next_dispatch(2_000_000).unwrap();
        assert_eq!(second.key, key(3));
        scheduler
            .finish_dispatch(second.key, 1, 2_000_001, RunDisposition::Runnable)
            .unwrap();
        assert_eq!(scheduler.next_dispatch(2_000_001).unwrap().key, key(2));
    }

    #[test]
    fn aging_gives_background_work_bounded_progress() {
        let mut scheduler = ThreadScheduler::try_with_default_policy(64).unwrap();
        add(
            &mut scheduler,
            1,
            SchedulingClass::Critical,
            Authority::Kernel,
            0,
        );
        add(
            &mut scheduler,
            2,
            SchedulingClass::Background,
            Authority::User,
            0,
        );

        assert_eq!(scheduler.next_dispatch(49_999_999).unwrap().key, key(1));
        scheduler
            .finish_dispatch(key(1), 1, 50_000_000, RunDisposition::Runnable)
            .unwrap();
        assert_eq!(scheduler.next_dispatch(50_000_000).unwrap().key, key(2));
    }

    #[test]
    fn exhausted_budget_throttles_then_replenishes() {
        let mut scheduler = ThreadScheduler::try_with_default_policy(64).unwrap();
        add(
            &mut scheduler,
            1,
            SchedulingClass::Audio,
            Authority::System,
            0,
        );

        for end in [1_000_000, 2_000_000, 3_000_000] {
            let dispatch = scheduler.next_dispatch(end - 1_000_000).unwrap();
            assert_eq!(dispatch.quantum_ns, 1_000_000);
            scheduler
                .finish_dispatch(dispatch.key, 1_000_000, end, RunDisposition::Runnable)
                .unwrap();
        }
        let throttled = scheduler.snapshot(key(1)).unwrap();
        assert_eq!(throttled.state, ThreadState::Throttled);
        assert_eq!(throttled.budget_remaining_ns, 0);
        assert!(scheduler.next_dispatch(9_999_999).is_none());

        let replenished = scheduler.next_dispatch(10_000_000).unwrap();
        assert_eq!(replenished.key, key(1));
        assert_eq!(replenished.quantum_ns, 1_000_000);
        let metrics = scheduler.snapshot(key(1)).unwrap().metrics;
        assert_eq!(metrics.throttling_events, 1);
        assert_eq!(metrics.throttled_time_ns, 7_000_000);
    }

    #[test]
    fn wake_wait_deadline_and_switch_metrics_are_accounted() {
        let mut scheduler = ThreadScheduler::try_with_default_policy(64).unwrap();
        add(
            &mut scheduler,
            1,
            SchedulingClass::Interactive,
            Authority::System,
            100,
        );
        scheduler.block(key(1)).unwrap();
        scheduler.wake(key(1), 1_000).unwrap();
        scheduler.set_deadline(key(1), 1_500).unwrap();

        let dispatch = scheduler.next_dispatch(3_100_000).unwrap();
        assert_eq!(dispatch.key, key(1));
        let metrics = scheduler.snapshot(key(1)).unwrap().metrics;
        assert_eq!(metrics.runnable_wait_ns, 3_099_000);
        assert_eq!(metrics.wake_latency_ns, 3_099_000);
        assert_eq!(metrics.maximum_wake_latency_ns, 3_099_000);
        assert_eq!(metrics.wake_latency_samples, 1);
        assert_eq!(metrics.wake_latency_target_misses, 1);
        assert_eq!(metrics.context_switches, 1);
        assert_eq!(metrics.deadline_misses, 1);
    }

    #[test]
    fn bounded_donation_chain_boosts_and_cancels_every_recipient() {
        let mut config = SchedulerConfig::default();
        config.max_donation_depth = 2;
        let mut scheduler = ThreadScheduler::try_new(config, 64).unwrap();
        add(
            &mut scheduler,
            1,
            SchedulingClass::Audio,
            Authority::System,
            0,
        );
        add(
            &mut scheduler,
            2,
            SchedulingClass::Normal,
            Authority::User,
            0,
        );
        add(
            &mut scheduler,
            3,
            SchedulingClass::Background,
            Authority::User,
            0,
        );
        add(
            &mut scheduler,
            4,
            SchedulingClass::Interactive,
            Authority::System,
            0,
        );

        let token = scheduler
            .donate_chain(key(1), &[key(2), key(3)], 10_000, 0)
            .unwrap();
        assert_eq!(
            scheduler.snapshot(key(2)).unwrap().effective_class,
            SchedulingClass::Audio
        );
        assert_eq!(
            scheduler.snapshot(key(3)).unwrap().effective_class,
            SchedulingClass::Audio
        );
        assert_eq!(scheduler.next_dispatch(0).unwrap().key, key(1));
        scheduler.block(key(1)).unwrap();
        assert_eq!(scheduler.next_dispatch(0).unwrap().key, key(2));

        assert!(scheduler.cancel_donation(token, 1));
        assert_eq!(
            scheduler.snapshot(key(2)).unwrap().effective_class,
            SchedulingClass::Normal
        );
        assert_eq!(
            scheduler.snapshot(key(3)).unwrap().effective_class,
            SchedulingClass::Background
        );
        assert_eq!(
            scheduler.donate_chain(key(4), &[key(1), key(2), key(3)], 10_000, 0),
            Err(DonationError::ChainTooDeep)
        );
    }

    #[test]
    fn donation_expires_and_disconnect_unwinds_nested_boosts() {
        let mut scheduler = ThreadScheduler::try_with_default_policy(64).unwrap();
        add(
            &mut scheduler,
            1,
            SchedulingClass::Interactive,
            Authority::System,
            0,
        );
        add(
            &mut scheduler,
            2,
            SchedulingClass::Normal,
            Authority::User,
            0,
        );
        add(
            &mut scheduler,
            3,
            SchedulingClass::Background,
            Authority::User,
            0,
        );
        let token = scheduler
            .donate_chain(key(1), &[key(2), key(3)], 100, 0)
            .unwrap();

        scheduler.maintain(100);
        assert_eq!(
            scheduler.snapshot(key(2)).unwrap().effective_class,
            SchedulingClass::Normal
        );
        assert!(!scheduler.cancel_donation(token, 100));

        scheduler
            .donate_chain(key(1), &[key(2), key(3)], 1_000, 100)
            .unwrap();
        assert_eq!(scheduler.cancel_donations_from(key(1), 200), 1);
        assert_eq!(
            scheduler.snapshot(key(3)).unwrap().effective_class,
            SchedulingClass::Background
        );
    }

    #[test]
    fn bounded_storage_rejects_excess_threads_without_changing_live_state() {
        let mut scheduler = ThreadScheduler::try_with_default_policy(2).unwrap();
        add(
            &mut scheduler,
            1,
            SchedulingClass::Normal,
            Authority::User,
            0,
        );
        add(
            &mut scheduler,
            2,
            SchedulingClass::Background,
            Authority::User,
            0,
        );
        let capacities: (usize, [usize; CLASS_COUNT], usize) = (
            scheduler.threads.capacity(),
            core::array::from_fn(|index| scheduler.queues[index].capacity()),
            scheduler.donations.capacity(),
        );
        assert_eq!(
            scheduler.add_thread(key(3), SchedulingClass::Normal, Authority::User, 0),
            Err(SchedulerError::CapacityReached)
        );
        scheduler.block(key(1)).unwrap();
        scheduler.wake(key(1), 10).unwrap();
        let dispatch = scheduler.next_dispatch(10).unwrap();
        scheduler
            .finish_dispatch(dispatch.key, 1, 11, RunDisposition::Runnable)
            .unwrap();
        assert_eq!(scheduler.len(), 2);
        assert_eq!(
            capacities,
            (
                scheduler.threads.capacity(),
                core::array::from_fn(|index| scheduler.queues[index].capacity()),
                scheduler.donations.capacity(),
            )
        );
    }

    #[test]
    fn admission_and_generation_tags_reject_implicit_promotion_and_stale_identity() {
        let mut scheduler = ThreadScheduler::try_with_default_policy(64).unwrap();
        assert_eq!(
            scheduler.add_thread(key(1), SchedulingClass::Audio, Authority::User, 0),
            Err(SchedulerError::UnauthorizedClass(SchedulingClass::Audio))
        );

        let old = OpaqueThreadKey::new(7, 1).unwrap();
        let replacement = OpaqueThreadKey::new(7, 2).unwrap();
        scheduler
            .add_thread(old, SchedulingClass::Normal, Authority::User, 0)
            .unwrap();
        scheduler.remove_thread(old, 0).unwrap();
        scheduler
            .add_thread(replacement, SchedulingClass::Normal, Authority::User, 0)
            .unwrap();
        assert!(scheduler.snapshot(old).is_none());
        assert!(scheduler.snapshot(replacement).is_some());
    }
}
