//! Boot-preallocated wait registration and dispatch.
//!
//! IPC objects only receive an opaque [`WaitToken`] and a shared [`SignalObserver`].
//! This runtime keeps the scheduler key and wait metadata in kernel-owned slots, so
//! IPC never needs to know process or scheduler types.
//!
//! The current implementation has one kernel-owned dispatcher. Observer notification
//! is protected by a spinlock and is ready for calls from multiple CPUs, while
//! registration, cancellation, and wake dispatch remain owned by that dispatcher.

extern crate alloc;

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::fmt::Debug;

use ginkgo_ipc::{SignalObserver, WaitToken};
use spinning_top::Spinlock;

const TOKEN_INDEX_BITS: u32 = 32;
const TOKEN_INDEX_MASK: u64 = u32::MAX as u64;

/// The operation represented by a wait registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitKind {
    WaitMany,
    Sleep,
    Join,
    Request,
    ProcessTermination,
}

/// The event that completed a wait registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WakeCause {
    Object,
    Dependency,
    Deadline,
}

/// A completed wait returned to the kernel scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitWake<K> {
    pub token: WaitToken,
    pub key: K,
    pub kind: WaitKind,
    pub cause: WakeCause,
    pub deadline_ns: Option<u64>,
}

/// Construction or registration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitRuntimeError {
    InvalidCapacity,
    CapacityTooLarge,
    CapacityReached,
    OutOfMemory,
}

/// Point-in-time and saturating lifetime wait diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WaitRuntimeDiagnostics {
    pub active: usize,
    pub peak_active: usize,
    pub object_notifications: u64,
    pub dependency_notifications: u64,
    pub coalesced_notifications: u64,
    pub stale_notifications: u64,
    pub deadline_wakes: u64,
    pub cancellations: u64,
    pub queue_peak: usize,
}

#[derive(Clone, Copy, Debug)]
struct DecodedToken {
    index: usize,
    generation: u32,
}

fn decode_token(token: WaitToken, capacity: usize) -> Option<DecodedToken> {
    let raw = token.raw();
    let encoded_index = (raw & TOKEN_INDEX_MASK) as u32;
    let generation = (raw >> TOKEN_INDEX_BITS) as u32;
    if encoded_index == 0 || generation == 0 {
        return None;
    }
    let index = (encoded_index - 1) as usize;
    if index >= capacity {
        return None;
    }
    Some(DecodedToken { index, generation })
}

fn encode_token(index: usize, generation: u32) -> WaitToken {
    let encoded_index = (index as u64) + 1;
    let raw = (u64::from(generation) << TOKEN_INDEX_BITS) | encoded_index;
    WaitToken::from_raw(raw).expect("wait token layout is always nonzero")
}

fn advanced_generation(generation: u32) -> (u32, bool) {
    match generation.checked_add(1) {
        Some(next) => (next, false),
        None => (generation, true),
    }
}

#[derive(Debug)]
struct WaitSlot<K> {
    generation: u32,
    retired: bool,
    key: Option<K>,
    kind: WaitKind,
    deadline_ns: Option<u64>,
    heap_index: Option<usize>,
}

impl<K> WaitSlot<K> {
    const fn vacant() -> Self {
        Self {
            generation: 1,
            retired: false,
            key: None,
            kind: WaitKind::WaitMany,
            deadline_ns: None,
            heap_index: None,
        }
    }

    fn is_active(&self) -> bool {
        self.key.is_some()
    }
}

#[derive(Clone, Copy, Debug)]
struct ObserverSlot {
    generation: u32,
    retired: bool,
    active: bool,
    queued: bool,
}

impl ObserverSlot {
    const fn vacant() -> Self {
        Self {
            generation: 1,
            retired: false,
            active: false,
            queued: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ReadyRecord {
    token: WaitToken,
    cause: WakeCause,
}

struct ObserverState {
    slots: Vec<ObserverSlot>,
    ready: VecDeque<ReadyRecord>,
    diagnostics: WaitRuntimeDiagnostics,
}

impl ObserverState {
    fn notify(&mut self, token: WaitToken, cause: WakeCause) -> bool {
        let Some(decoded) = decode_token(token, self.slots.len()) else {
            self.diagnostics.stale_notifications =
                self.diagnostics.stale_notifications.saturating_add(1);
            return false;
        };
        let slot = &mut self.slots[decoded.index];
        if !slot.active || slot.retired || slot.generation != decoded.generation {
            self.diagnostics.stale_notifications =
                self.diagnostics.stale_notifications.saturating_add(1);
            return false;
        }

        match cause {
            WakeCause::Object => {
                self.diagnostics.object_notifications =
                    self.diagnostics.object_notifications.saturating_add(1);
            }
            WakeCause::Dependency => {
                self.diagnostics.dependency_notifications =
                    self.diagnostics.dependency_notifications.saturating_add(1);
            }
            WakeCause::Deadline => unreachable!("deadlines do not enter the ready queue"),
        }

        if slot.queued {
            self.diagnostics.coalesced_notifications =
                self.diagnostics.coalesced_notifications.saturating_add(1);
            return true;
        }

        slot.queued = true;
        debug_assert!(self.ready.len() < self.slots.len());
        self.ready.push_back(ReadyRecord { token, cause });
        self.diagnostics.queue_peak = self.diagnostics.queue_peak.max(self.ready.len());
        true
    }

    fn remove_ready(&mut self, token: WaitToken, index: usize) {
        if self.slots[index].queued {
            if let Some(position) = self.ready.iter().position(|record| record.token == token) {
                self.ready.remove(position);
            }
            self.slots[index].queued = false;
        }
    }

    fn activate(&mut self, index: usize, generation: u32) {
        let slot = &mut self.slots[index];
        debug_assert!(!slot.active);
        debug_assert!(!slot.retired);
        debug_assert_eq!(slot.generation, generation);
        debug_assert!(!slot.queued);
        slot.active = true;
        self.diagnostics.active += 1;
        self.diagnostics.peak_active = self.diagnostics.peak_active.max(self.diagnostics.active);
    }

    fn deactivate(&mut self, index: usize, generation: u32, retired: bool) {
        let slot = &mut self.slots[index];
        debug_assert!(slot.active);
        slot.active = false;
        slot.queued = false;
        slot.generation = generation;
        slot.retired = retired;
        self.diagnostics.active -= 1;
    }
}

struct SharedObserver {
    state: Spinlock<ObserverState>,
}

impl SignalObserver for SharedObserver {
    fn notify(&self, token: WaitToken) {
        self.state.lock().notify(token, WakeCause::Object);
    }
}

#[derive(Clone, Copy, Debug)]
struct DeadlineEntry {
    deadline_ns: u64,
    token: WaitToken,
}

impl DeadlineEntry {
    fn ordering_key(self) -> (u64, u64) {
        (self.deadline_ns, self.token.raw())
    }
}

/// Fixed-capacity mapping from opaque IPC wait tokens to scheduler keys.
///
/// Slot arrays, the ready queue, and the indexed deadline heap reserve their full
/// capacity in [`WaitRuntime::try_new`]. Once construction succeeds, registration,
/// notification, dependency notification, cancellation, wake dispatch, and heap
/// maintenance do not allocate.
pub struct WaitRuntime<K: Copy + Debug + Ord> {
    capacity: usize,
    slots: Vec<WaitSlot<K>>,
    deadlines: Vec<DeadlineEntry>,
    observer: Arc<SharedObserver>,
}

impl<K: Copy + Debug + Ord> WaitRuntime<K> {
    /// Allocates all storage required for up to `capacity` simultaneous waits.
    pub fn try_new(capacity: usize) -> Result<Self, WaitRuntimeError> {
        if capacity == 0 {
            return Err(WaitRuntimeError::InvalidCapacity);
        }
        if capacity > u32::MAX as usize {
            return Err(WaitRuntimeError::CapacityTooLarge);
        }

        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| WaitRuntimeError::OutOfMemory)?;
        for _ in 0..capacity {
            slots.push(WaitSlot::vacant());
        }

        let mut deadlines = Vec::new();
        deadlines
            .try_reserve_exact(capacity)
            .map_err(|_| WaitRuntimeError::OutOfMemory)?;

        let mut observer_slots = Vec::new();
        observer_slots
            .try_reserve_exact(capacity)
            .map_err(|_| WaitRuntimeError::OutOfMemory)?;
        for _ in 0..capacity {
            observer_slots.push(ObserverSlot::vacant());
        }

        let mut ready = VecDeque::new();
        ready
            .try_reserve_exact(capacity)
            .map_err(|_| WaitRuntimeError::OutOfMemory)?;
        let observer = Arc::try_new(SharedObserver {
            state: Spinlock::new(ObserverState {
                slots: observer_slots,
                ready,
                diagnostics: WaitRuntimeDiagnostics::default(),
            }),
        })
        .map_err(|_| WaitRuntimeError::OutOfMemory)?;

        Ok(Self {
            capacity,
            slots,
            deadlines,
            observer,
        })
    }

    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the shared object-signal sink passed to IPC registrations.
    ///
    /// Cloning an [`Arc`] does not allocate.
    pub fn observer(&self) -> Arc<dyn SignalObserver> {
        self.observer.clone()
    }

    /// Returns a consistent diagnostics snapshot.
    pub fn diagnostics(&self) -> WaitRuntimeDiagnostics {
        self.observer.state.lock().diagnostics
    }

    /// Registers one scheduler key and returns its opaque IPC token.
    pub fn register(
        &mut self,
        key: K,
        kind: WaitKind,
        deadline_ns: Option<u64>,
    ) -> Result<WaitToken, WaitRuntimeError> {
        let index = self
            .slots
            .iter()
            .position(|slot| !slot.is_active() && !slot.retired)
            .ok_or(WaitRuntimeError::CapacityReached)?;
        let generation = self.slots[index].generation;
        let token = encode_token(index, generation);

        self.slots[index].key = Some(key);
        self.slots[index].kind = kind;
        self.slots[index].deadline_ns = deadline_ns;
        self.slots[index].heap_index = None;
        if let Some(deadline_ns) = deadline_ns {
            self.push_deadline(DeadlineEntry { deadline_ns, token });
        }
        self.observer.state.lock().activate(index, generation);
        Ok(token)
    }

    /// Queues a dependency wake through the same bounded, coalescing path as IPC.
    ///
    /// Returns `false` if `token` is stale or invalid.
    pub fn notify_dependency(&self, token: WaitToken) -> bool {
        self.observer
            .state
            .lock()
            .notify(token, WakeCause::Dependency)
    }

    /// Returns the active token for `key`, if that scheduler key is blocked.
    pub fn token_for_key(&self, key: K) -> Option<WaitToken> {
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            (slot.key == Some(key)).then(|| encode_token(index, slot.generation))
        })
    }

    /// Cancels the active registration owned by `key`.
    pub fn cancel_key(&mut self, key: K) -> bool {
        self.token_for_key(key)
            .is_some_and(|token| self.cancel(token))
    }

    /// Cancels an active registration and invalidates its token.
    pub fn cancel(&mut self, token: WaitToken) -> bool {
        let Some(decoded) = decode_token(token, self.capacity) else {
            return false;
        };
        let slot = &self.slots[decoded.index];
        if !slot.is_active() || slot.generation != decoded.generation {
            return false;
        }
        let (next_generation, retired) = advanced_generation(decoded.generation);

        let observer = Arc::clone(&self.observer);
        let mut state = observer.state.lock();
        state.remove_ready(token, decoded.index);
        state.deactivate(decoded.index, next_generation, retired);
        state.diagnostics.cancellations = state.diagnostics.cancellations.saturating_add(1);
        drop(state);

        self.remove_slot_deadline(decoded.index);
        self.release_slot(decoded.index, next_generation, retired);
        true
    }

    /// Returns the next ready notification, or an inclusive deadline expiration.
    ///
    /// Ready records are always checked while holding the observer lock before the
    /// deadline heap, so object and dependency readiness win at an equal timestamp.
    pub fn next_wake(&mut self, now_ns: u64) -> Option<WaitWake<K>> {
        loop {
            let observer = Arc::clone(&self.observer);
            let mut state = observer.state.lock();

            while let Some(record) = state.ready.pop_front() {
                let Some(decoded) = decode_token(record.token, self.capacity) else {
                    continue;
                };
                let observer_slot = state.slots[decoded.index];
                if !observer_slot.active
                    || !observer_slot.queued
                    || observer_slot.generation != decoded.generation
                {
                    continue;
                }
                let slot = &self.slots[decoded.index];
                let Some(key) = slot.key else {
                    state.slots[decoded.index].queued = false;
                    continue;
                };
                if slot.generation != decoded.generation {
                    state.slots[decoded.index].queued = false;
                    continue;
                }

                let kind = slot.kind;
                let deadline_ns = slot.deadline_ns;
                let (next_generation, retired) = advanced_generation(decoded.generation);
                state.deactivate(decoded.index, next_generation, retired);
                drop(state);

                self.remove_slot_deadline(decoded.index);
                self.release_slot(decoded.index, next_generation, retired);
                return Some(WaitWake {
                    token: record.token,
                    key,
                    kind,
                    cause: record.cause,
                    deadline_ns,
                });
            }

            let Some(entry) = self.deadlines.first().copied() else {
                return None;
            };
            if entry.deadline_ns > now_ns {
                return None;
            }
            let Some(decoded) = decode_token(entry.token, self.capacity) else {
                drop(state);
                self.remove_deadline_at(0);
                continue;
            };
            let slot = &self.slots[decoded.index];
            let Some(key) = slot.key else {
                drop(state);
                self.remove_deadline_at(0);
                continue;
            };
            if slot.generation != decoded.generation {
                drop(state);
                self.remove_deadline_at(0);
                continue;
            }

            let kind = slot.kind;
            let deadline_ns = slot.deadline_ns;
            let (next_generation, retired) = advanced_generation(decoded.generation);
            state.deactivate(decoded.index, next_generation, retired);
            state.diagnostics.deadline_wakes = state.diagnostics.deadline_wakes.saturating_add(1);
            drop(state);

            self.remove_deadline_at(0);
            self.release_slot(decoded.index, next_generation, retired);
            return Some(WaitWake {
                token: entry.token,
                key,
                kind,
                cause: WakeCause::Deadline,
                deadline_ns,
            });
        }
    }

    /// Returns the earliest registered deadline.
    pub fn next_deadline_ns(&self) -> Option<u64> {
        self.deadlines.first().map(|entry| entry.deadline_ns)
    }

    fn release_slot(&mut self, index: usize, generation: u32, retired: bool) {
        let slot = &mut self.slots[index];
        slot.key = None;
        slot.deadline_ns = None;
        slot.heap_index = None;
        slot.generation = generation;
        slot.retired = retired;
    }

    fn push_deadline(&mut self, entry: DeadlineEntry) {
        debug_assert!(self.deadlines.len() < self.capacity);
        let index = self.deadlines.len();
        self.deadlines.push(entry);
        self.set_heap_index(index);
        self.sift_deadline_up(index);
    }

    fn remove_slot_deadline(&mut self, slot_index: usize) {
        if let Some(heap_index) = self.slots[slot_index].heap_index {
            self.remove_deadline_at(heap_index);
        }
    }

    fn remove_deadline_at(&mut self, index: usize) -> DeadlineEntry {
        let removed = self.deadlines.swap_remove(index);
        if let Some(decoded) = decode_token(removed.token, self.capacity) {
            if self.slots[decoded.index].generation == decoded.generation {
                self.slots[decoded.index].heap_index = None;
            }
        }

        if index < self.deadlines.len() {
            self.set_heap_index(index);
            if index > 0
                && self.deadlines[index].ordering_key()
                    < self.deadlines[(index - 1) / 2].ordering_key()
            {
                self.sift_deadline_up(index);
            } else {
                self.sift_deadline_down(index);
            }
        }
        removed
    }

    fn sift_deadline_up(&mut self, mut index: usize) {
        while index > 0 {
            let parent = (index - 1) / 2;
            if self.deadlines[parent].ordering_key() <= self.deadlines[index].ordering_key() {
                break;
            }
            self.swap_deadlines(parent, index);
            index = parent;
        }
    }

    fn sift_deadline_down(&mut self, mut index: usize) {
        loop {
            let left = index * 2 + 1;
            if left >= self.deadlines.len() {
                break;
            }
            let right = left + 1;
            let smallest = if right < self.deadlines.len()
                && self.deadlines[right].ordering_key() < self.deadlines[left].ordering_key()
            {
                right
            } else {
                left
            };
            if self.deadlines[index].ordering_key() <= self.deadlines[smallest].ordering_key() {
                break;
            }
            self.swap_deadlines(index, smallest);
            index = smallest;
        }
    }

    fn swap_deadlines(&mut self, left: usize, right: usize) {
        self.deadlines.swap(left, right);
        self.set_heap_index(left);
        self.set_heap_index(right);
    }

    fn set_heap_index(&mut self, heap_index: usize) {
        let token = self.deadlines[heap_index].token;
        let decoded = decode_token(token, self.capacity).expect("runtime-generated deadline token");
        self.slots[decoded.index].heap_index = Some(heap_index);
    }

    #[cfg(test)]
    fn set_generation_for_test(&mut self, index: usize, generation: u32) {
        assert_ne!(generation, 0);
        assert!(!self.slots[index].is_active());
        self.slots[index].generation = generation;
        self.slots[index].retired = false;
        let mut state = self.observer.state.lock();
        assert!(!state.slots[index].active);
        state.slots[index].generation = generation;
        state.slots[index].retired = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime(capacity: usize) -> WaitRuntime<u32> {
        WaitRuntime::try_new(capacity).unwrap()
    }

    #[test]
    fn stale_generation_is_rejected() {
        let mut runtime = runtime(1);
        let observer = runtime.observer();
        let stale = runtime.register(10, WaitKind::WaitMany, None).unwrap();
        assert!(runtime.cancel(stale));

        let current = runtime.register(11, WaitKind::Join, None).unwrap();
        observer.notify(stale);
        assert_eq!(runtime.next_wake(0), None);
        assert_eq!(runtime.diagnostics().stale_notifications, 1);

        observer.notify(current);
        assert_eq!(runtime.next_wake(0).unwrap().key, 11);
    }

    #[test]
    fn slot_reuse_increments_generation() {
        let mut runtime = runtime(1);
        let first = runtime.register(1, WaitKind::WaitMany, None).unwrap();
        assert!(runtime.cancel(first));
        let second = runtime.register(2, WaitKind::WaitMany, None).unwrap();

        assert_eq!(
            first.raw() & TOKEN_INDEX_MASK,
            second.raw() & TOKEN_INDEX_MASK
        );
        assert_eq!(second.raw() >> TOKEN_INDEX_BITS, 2);
        assert_ne!(first, second);
    }

    #[test]
    fn cancellation_removes_queued_and_heap_entries() {
        let mut runtime = runtime(1);
        let observer = runtime.observer();
        let token = runtime.register(7, WaitKind::Sleep, Some(50)).unwrap();
        observer.notify(token);

        assert!(runtime.cancel(token));
        assert_eq!(runtime.next_deadline_ns(), None);
        assert_eq!(runtime.next_wake(100), None);
        assert_eq!(runtime.diagnostics().active, 0);
    }

    #[test]
    fn repeated_notify_cancel_and_reuse_preserves_queue_capacity() {
        let mut runtime = runtime(1);
        let observer = runtime.observer();

        for key in 0..100 {
            let token = runtime.register(key, WaitKind::WaitMany, None).unwrap();
            observer.notify(token);
            assert!(runtime.cancel(token));
        }

        let token = runtime.register(200, WaitKind::WaitMany, None).unwrap();
        observer.notify(token);
        assert_eq!(runtime.next_wake(0).unwrap().key, 200);
        assert_eq!(runtime.diagnostics().queue_peak, 1);
    }

    #[test]
    fn notifications_are_coalesced() {
        let mut runtime = runtime(1);
        let observer = runtime.observer();
        let token = runtime.register(3, WaitKind::Join, None).unwrap();

        observer.notify(token);
        observer.notify(token);
        observer.notify(token);

        let wake = runtime.next_wake(0).unwrap();
        assert_eq!(wake.cause, WakeCause::Object);
        assert_eq!(runtime.next_wake(0), None);
        let diagnostics = runtime.diagnostics();
        assert_eq!(diagnostics.object_notifications, 3);
        assert_eq!(diagnostics.coalesced_notifications, 2);
    }

    #[test]
    fn equal_deadlines_are_ordered_by_token() {
        let mut runtime = runtime(3);
        let first = runtime.register(30, WaitKind::Sleep, Some(10)).unwrap();
        let second = runtime.register(10, WaitKind::Sleep, Some(10)).unwrap();
        let third = runtime.register(20, WaitKind::Sleep, Some(10)).unwrap();

        let mut expected = [(first.raw(), 30), (second.raw(), 10), (third.raw(), 20)];
        expected.sort_unstable_by_key(|entry| entry.0);
        for (_, key) in expected {
            let wake = runtime.next_wake(10).unwrap();
            assert_eq!(wake.key, key);
            assert_eq!(wake.cause, WakeCause::Deadline);
        }
    }

    #[test]
    fn readiness_wins_before_an_equal_deadline() {
        let mut runtime = runtime(2);
        let deadline = runtime.register(1, WaitKind::Sleep, Some(10)).unwrap();
        let ready = runtime.register(2, WaitKind::WaitMany, Some(10)).unwrap();
        runtime.observer().notify(ready);

        let wake = runtime.next_wake(10).unwrap();
        assert_eq!(wake.token, ready);
        assert_eq!(wake.cause, WakeCause::Object);
        assert_eq!(runtime.next_wake(10).unwrap().token, deadline);
    }

    #[test]
    fn dependency_wakes_use_the_ready_path() {
        let mut runtime = runtime(1);
        let token = runtime.register(9, WaitKind::Join, Some(20)).unwrap();

        assert!(runtime.notify_dependency(token));
        let wake = runtime.next_wake(20).unwrap();
        assert_eq!(wake.cause, WakeCause::Dependency);
        assert_eq!(wake.deadline_ns, Some(20));
        assert_eq!(runtime.next_deadline_ns(), None);
    }

    #[test]
    fn generation_wrap_retires_the_slot() {
        let mut runtime = runtime(1);
        runtime.set_generation_for_test(0, u32::MAX);
        let token = runtime.register(1, WaitKind::WaitMany, None).unwrap();
        assert_eq!(token.raw() >> TOKEN_INDEX_BITS, u64::from(u32::MAX));

        assert!(runtime.cancel(token));
        assert_eq!(
            runtime.register(2, WaitKind::WaitMany, None),
            Err(WaitRuntimeError::CapacityReached)
        );
        assert!(!runtime.cancel(token));
    }

    #[test]
    fn cancellation_by_key_removes_the_active_registration() {
        let mut runtime = runtime(1);
        let token = runtime.register(7, WaitKind::Join, Some(50)).unwrap();
        assert_eq!(runtime.token_for_key(7), Some(token));
        assert!(runtime.cancel_key(7));
        assert_eq!(runtime.token_for_key(7), None);
        assert!(!runtime.cancel_key(7));
        assert_eq!(runtime.next_deadline_ns(), None);
    }

    #[test]
    fn capacity_is_exact() {
        let mut runtime = runtime(2);
        let first = runtime.register(1, WaitKind::WaitMany, None).unwrap();
        runtime.register(2, WaitKind::Join, None).unwrap();
        assert_eq!(
            runtime.register(3, WaitKind::Sleep, None),
            Err(WaitRuntimeError::CapacityReached)
        );

        assert!(runtime.cancel(first));
        assert!(runtime.register(3, WaitKind::Sleep, None).is_ok());
    }

    #[test]
    fn diagnostics_track_lifecycle_and_notifications() {
        let mut runtime = runtime(2);
        let observer = runtime.observer();
        let first = runtime.register(1, WaitKind::WaitMany, None).unwrap();
        observer.notify(first);
        observer.notify(first);
        assert!(runtime.notify_dependency(first));
        assert!(runtime.cancel(first));

        let second = runtime.register(2, WaitKind::Sleep, Some(5)).unwrap();
        let wake = runtime.next_wake(5).unwrap();
        assert_eq!(wake.token, second);
        observer.notify(second);

        assert_eq!(
            runtime.diagnostics(),
            WaitRuntimeDiagnostics {
                active: 0,
                peak_active: 1,
                object_notifications: 2,
                dependency_notifications: 1,
                coalesced_notifications: 2,
                stale_notifications: 1,
                deadline_wakes: 1,
                cancellations: 1,
                queue_peak: 1,
            }
        );
    }
}
