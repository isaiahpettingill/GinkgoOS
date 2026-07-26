//! Bounded 4 KiB RedoxFS cache with deferred ordered writeback.
//!
//! Construction allocates the entry table and open-address lookup table. After
//! construction, reads, writes, flush requests, and writeback steps never grow a
//! collection. A flush request is a sequence ticket: writes through that ticket
//! are dispatched in sequence order and the backing disk is flushed before any
//! later write is dispatched. Flushes synchronously drain during boot until
//! [`WriteBackDisk::enable_async_writeback`] enables worker-driven runtime mode.

extern crate alloc;

use alloc::vec::Vec;

use redoxfs::Disk;
use syscall::error::{Error, Result, EAGAIN, EINVAL, EIO, ENOSPC, EROFS};

pub const WRITEBACK_BLOCK_SIZE: usize = 4096;
const READ_AHEAD_BLOCKS: usize = 4;
const DEFAULT_WRITEBACK_BATCH_BLOCKS: usize = 2;
const MAX_WRITEBACK_BATCH_BLOCKS: usize = 4;
const READ_AHEAD_BYTES: usize = READ_AHEAD_BLOCKS * WRITEBACK_BLOCK_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteBackConfigError {
    ZeroCapacity,
    InvalidWritebackBatch,
    CapacityOverflow,
    AllocationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteBackFailureOperation {
    Write {
        block: u64,
        first_sequence: u64,
        last_sequence: u64,
    },
    Flush {
        requested_sequence: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteBackFailure {
    pub errno: i32,
    pub operation: WriteBackFailureOperation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteBackProgress {
    Idle,
    WroteBlock {
        block: u64,
        first_sequence: u64,
        last_sequence: u64,
    },
    Flushed {
        durable_sequence: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainReport {
    pub ticket: u64,
    pub durable_sequence: u64,
    pub dirty_remaining: usize,
    pub steps: usize,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WriteBackMetrics {
    pub read_requests: u64,
    pub read_blocks: u64,
    pub read_hits: u64,
    pub dirty_read_hits: u64,
    pub clean_read_hits: u64,
    pub read_misses: u64,
    pub underlying_reads: u64,
    pub read_errors: u64,
    pub read_cache_admission_failures: u64,
    pub read_ahead_requests: u64,
    pub read_ahead_blocks: u64,
    pub write_requests: u64,
    pub write_blocks_accepted: u64,
    pub coalesced_writes: u64,
    pub rejected_writes: u64,
    pub backpressure_events: u64,
    pub pressure_writeback_steps: u64,
    pub pressure_entries_freed: u64,
    pub pressure_stalls: u64,
    pub cache_insertions: u64,
    pub clean_evictions: u64,
    pub lookup_tombstones_created: u64,
    pub flush_requests: u64,
    pub flush_backpressure_events: u64,
    pub synchronous_flush_drains: u64,
    pub synchronous_flush_incomplete: u64,
    pub async_writeback_enables: u64,
    pub writeback_steps: u64,
    pub blocks_written_back: u64,
    pub bytes_written_back: u64,
    pub underlying_flushes: u64,
    pub writeback_errors: u64,
    pub retries: u64,
    pub dirty_high_watermark: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteBackStatus {
    pub write_sequence: u64,
    pub requested_sequence: u64,
    pub durable_sequence: u64,
    pub dirty_count: usize,
    pub resident_count: usize,
    pub entry_count: usize,
    pub lookup_slot_count: usize,
    pub flush_ticket_slot_count: usize,
    pub pending_flush_tickets: usize,
    pub entry_allocation_capacity: usize,
    pub lookup_allocation_capacity: usize,
    pub flush_ticket_allocation_capacity: usize,
    pub lookup_tombstones: usize,
    pub writeback_batch_blocks: usize,
    pub async_writeback_enabled: bool,
    pub quiesced: bool,
    pub read_only: bool,
    pub failure: Option<WriteBackFailure>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryState {
    Vacant,
    Clean,
    Dirty,
}

#[derive(Clone)]
struct CacheEntry {
    block: u64,
    data: [u8; WRITEBACK_BLOCK_SIZE],
    state: EntryState,
    first_sequence: u64,
    last_sequence: u64,
    last_used: u64,
}

impl CacheEntry {
    const fn vacant() -> Self {
        Self {
            block: 0,
            data: [0; WRITEBACK_BLOCK_SIZE],
            state: EntryState::Vacant,
            first_sequence: 0,
            last_sequence: 0,
            last_used: 0,
        }
    }
}

#[derive(Clone, Copy)]
enum LookupSlot {
    Empty,
    Tombstone,
    Occupied { block: u64, entry: usize },
}

/// A fixed-capacity write-back cache around a RedoxFS disk.
///
/// `write_at` accepts complete 4 KiB blocks and returns as soon as their bytes
/// are copied into this cache. Call [`Self::writeback_step`] from a worker or
/// idle loop to perform at most one backing operation. Once a writeback error
/// occurs, new writes are rejected with `EROFS` until an explicit
/// [`Self::retry_writeback_step`] succeeds.
///
/// Do not mutate the backing disk behind this wrapper. Doing so bypasses cache
/// coherency and durability accounting.
pub struct WriteBackDisk<D: Disk> {
    inner: D,
    entries: Vec<CacheEntry>,
    lookup: Vec<LookupSlot>,
    lookup_mask: usize,
    read_ahead: Vec<u8>,
    flush_tickets: Vec<u64>,
    flush_ticket_head: usize,
    flush_ticket_len: usize,
    resident_count: usize,
    dirty_count: usize,
    lookup_tombstones: usize,
    writeback_batch_blocks: usize,
    access_clock: u64,
    write_sequence: u64,
    requested_sequence: u64,
    durable_sequence: u64,
    async_writeback_enabled: bool,
    quiesced: bool,
    failure: Option<WriteBackFailure>,
    metrics: WriteBackMetrics,
}

impl<D: Disk> WriteBackDisk<D> {
    /// Preallocates `entry_count` cache entries and a lookup table kept at or
    /// below 50 percent occupancy.
    pub fn new(inner: D, entry_count: usize) -> core::result::Result<Self, WriteBackConfigError> {
        Self::try_new(inner, entry_count)
    }

    pub fn try_new(
        inner: D,
        entry_count: usize,
    ) -> core::result::Result<Self, WriteBackConfigError> {
        Self::try_new_with_writeback_batch(inner, entry_count, DEFAULT_WRITEBACK_BATCH_BLOCKS)
    }

    pub fn try_new_with_writeback_batch(
        inner: D,
        entry_count: usize,
        writeback_batch_blocks: usize,
    ) -> core::result::Result<Self, WriteBackConfigError> {
        if entry_count == 0 {
            return Err(WriteBackConfigError::ZeroCapacity);
        }
        if writeback_batch_blocks == 0 || writeback_batch_blocks > MAX_WRITEBACK_BATCH_BLOCKS {
            return Err(WriteBackConfigError::InvalidWritebackBatch);
        }
        let lookup_count = entry_count
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(WriteBackConfigError::CapacityOverflow)?;
        let flush_ticket_count = entry_count
            .checked_add(1)
            .ok_or(WriteBackConfigError::CapacityOverflow)?;

        let mut entries = Vec::new();
        entries
            .try_reserve_exact(entry_count)
            .map_err(|_| WriteBackConfigError::AllocationFailed)?;
        for _ in 0..entry_count {
            entries.push(CacheEntry::vacant());
        }

        let mut lookup = Vec::new();
        lookup
            .try_reserve_exact(lookup_count)
            .map_err(|_| WriteBackConfigError::AllocationFailed)?;
        for _ in 0..lookup_count {
            lookup.push(LookupSlot::Empty);
        }

        let mut read_ahead = Vec::new();
        read_ahead
            .try_reserve_exact(READ_AHEAD_BYTES)
            .map_err(|_| WriteBackConfigError::AllocationFailed)?;
        read_ahead.resize(READ_AHEAD_BYTES, 0);

        let mut flush_tickets = Vec::new();
        flush_tickets
            .try_reserve_exact(flush_ticket_count)
            .map_err(|_| WriteBackConfigError::AllocationFailed)?;
        for _ in 0..flush_ticket_count {
            flush_tickets.push(0);
        }

        Ok(Self {
            inner,
            entries,
            lookup,
            lookup_mask: lookup_count - 1,
            read_ahead,
            flush_tickets,
            flush_ticket_head: 0,
            flush_ticket_len: 0,
            resident_count: 0,
            dirty_count: 0,
            lookup_tombstones: 0,
            writeback_batch_blocks,
            access_clock: 0,
            write_sequence: 0,
            requested_sequence: 0,
            durable_sequence: 0,
            async_writeback_enabled: false,
            quiesced: false,
            failure: None,
            metrics: WriteBackMetrics::default(),
        })
    }

    pub fn inner(&self) -> &D {
        &self.inner
    }

    /// Direct mutation is intended for device control and diagnostics only.
    /// Reads or writes through the returned disk bypass cache coherency.
    pub fn inner_mut(&mut self) -> &mut D {
        &mut self.inner
    }

    /// Returns the backing disk without draining dirty entries.
    pub fn into_inner(self) -> D {
        self.inner
    }

    pub const fn requested_sequence(&self) -> u64 {
        self.requested_sequence
    }

    pub const fn durable_sequence(&self) -> u64 {
        self.durable_sequence
    }

    /// Name used by the RedoxFS durability-status extension.
    pub const fn requested_flush_sequence(&self) -> u64 {
        self.requested_sequence
    }

    /// Name used by the RedoxFS durability-status extension.
    pub const fn durable_flush_sequence(&self) -> u64 {
        self.durable_sequence
    }

    pub const fn dirty_count(&self) -> usize {
        self.dirty_count
    }

    /// Permanently switches flushes to nonblocking worker-driven writeback.
    /// Returns `true` only for the first call.
    pub fn enable_async_writeback(&mut self) -> bool {
        if self.async_writeback_enabled {
            return false;
        }
        self.async_writeback_enabled = true;
        bump(&mut self.metrics.async_writeback_enables);
        true
    }

    pub const fn async_writeback_enabled(&self) -> bool {
        self.async_writeback_enabled
    }

    pub const fn is_async_writeback_enabled(&self) -> bool {
        self.async_writeback_enabled
    }

    pub const fn is_quiesced(&self) -> bool {
        self.quiesced
    }

    pub const fn is_read_only(&self) -> bool {
        self.quiesced || self.failure.is_some()
    }

    pub const fn failure(&self) -> Option<WriteBackFailure> {
        self.failure
    }

    pub const fn metrics(&self) -> WriteBackMetrics {
        self.metrics
    }

    pub fn status(&self) -> WriteBackStatus {
        WriteBackStatus {
            write_sequence: self.write_sequence,
            requested_sequence: self.requested_sequence,
            durable_sequence: self.durable_sequence,
            dirty_count: self.dirty_count,
            resident_count: self.resident_count,
            entry_count: self.entries.len(),
            lookup_slot_count: self.lookup.len(),
            flush_ticket_slot_count: self.flush_tickets.len(),
            pending_flush_tickets: self.flush_ticket_len,
            entry_allocation_capacity: self.entries.capacity(),
            lookup_allocation_capacity: self.lookup.capacity(),
            flush_ticket_allocation_capacity: self.flush_tickets.capacity(),
            lookup_tombstones: self.lookup_tombstones,
            writeback_batch_blocks: self.writeback_batch_blocks,
            async_writeback_enabled: self.async_writeback_enabled,
            quiesced: self.quiesced,
            read_only: self.is_read_only(),
            failure: self.failure,
        }
    }

    /// Stops new writes and requests durability for every accepted write.
    pub fn quiesce(&mut self) -> Result<u64> {
        self.quiesced = true;
        self.request_durability()
    }

    /// Reopens writes after a canceled shutdown if no writeback failure occurred.
    pub fn resume_after_quiesce(&mut self) -> Result<()> {
        if let Some(failure) = self.failure {
            return Err(Error::new(failure.errno));
        }
        self.quiesced = false;
        Ok(())
    }

    /// Performs a bounded synchronous shutdown drain. The disk stays quiesced
    /// even if the step limit is reached or an I/O operation fails.
    pub fn shutdown_drain(&mut self, max_steps: usize) -> Result<DrainReport> {
        let ticket = self.quiesce()?;
        self.drain_ticket(ticket, max_steps)
    }

    /// Alias suitable for bounded boot-time recovery paths that have already
    /// decided no new writes may enter the cache.
    pub fn quiesce_and_drain(&mut self, max_steps: usize) -> Result<DrainReport> {
        self.shutdown_drain(max_steps)
    }

    /// Advances an already requested ticket synchronously, with at most
    /// `max_steps` backing operations.
    pub fn drain_ticket(&mut self, ticket: u64, max_steps: usize) -> Result<DrainReport> {
        let mut steps = 0;
        while steps < max_steps && self.durable_sequence < ticket {
            match self.writeback_step()? {
                WriteBackProgress::Idle => break,
                WriteBackProgress::WroteBlock { .. } | WriteBackProgress::Flushed { .. } => {
                    steps += 1;
                }
            }
        }
        Ok(DrainReport {
            ticket,
            durable_sequence: self.durable_sequence,
            dirty_remaining: self.dirty_count,
            steps,
            complete: self.durable_sequence >= ticket,
        })
    }

    /// Clears a sticky writeback failure, retries exactly one backing operation,
    /// and restores write acceptance only if that operation succeeds.
    pub fn retry_writeback_step(&mut self) -> Result<WriteBackProgress> {
        if self.failure.is_some() {
            self.failure = None;
            bump(&mut self.metrics.retries);
        }
        self.writeback_step()
    }

    /// Writes at most one dirty block, or issues one backing flush when the
    /// oldest outstanding durability ticket has reached its barrier.
    pub fn writeback_step(&mut self) -> Result<WriteBackProgress> {
        bump(&mut self.metrics.writeback_steps);
        if let Some(failure) = self.failure {
            return Err(Error::new(failure.errno));
        }

        let dirty = self.lowest_sequence_dirty();
        let ticket = self.current_flush_ticket();
        if let Some(ticket) = ticket {
            let ticket_ready = dirty
                .map(|index| self.entries[index].first_sequence > ticket)
                .unwrap_or(true);
            if ticket_ready {
                return self.flush_backing(ticket);
            }
        }

        let Some(entry_index) = dirty else {
            return Ok(WriteBackProgress::Idle);
        };
        self.write_back_run(entry_index, ticket)
    }

    fn request_durability(&mut self) -> Result<u64> {
        if let Some(failure) = self.failure {
            return Err(Error::new(failure.errno));
        }
        if self.write_sequence == self.requested_sequence {
            bump(&mut self.metrics.flush_requests);
            return Ok(self.requested_sequence);
        }
        if self.flush_ticket_len == self.flush_tickets.len() {
            bump(&mut self.metrics.flush_backpressure_events);
            return Err(Error::new(EAGAIN));
        }
        let tail = (self.flush_ticket_head + self.flush_ticket_len) % self.flush_tickets.len();
        self.flush_tickets[tail] = self.write_sequence;
        self.flush_ticket_len += 1;
        self.requested_sequence = self.write_sequence;
        bump(&mut self.metrics.flush_requests);
        Ok(self.requested_sequence)
    }

    fn current_flush_ticket(&self) -> Option<u64> {
        (self.flush_ticket_len != 0).then(|| self.flush_tickets[self.flush_ticket_head])
    }

    fn flush_backing(&mut self, ticket: u64) -> Result<WriteBackProgress> {
        match self.inner.flush() {
            Ok(()) => {
                self.durable_sequence = ticket;
                self.flush_ticket_head = (self.flush_ticket_head + 1) % self.flush_tickets.len();
                self.flush_ticket_len -= 1;
                bump(&mut self.metrics.underlying_flushes);
                Ok(WriteBackProgress::Flushed {
                    durable_sequence: ticket,
                })
            }
            Err(error) => {
                self.record_failure(
                    error.errno,
                    WriteBackFailureOperation::Flush {
                        requested_sequence: ticket,
                    },
                );
                Err(error)
            }
        }
    }

    fn write_back_run(
        &mut self,
        first_entry: usize,
        ticket: Option<u64>,
    ) -> Result<WriteBackProgress> {
        let mut run = [usize::MAX; MAX_WRITEBACK_BATCH_BLOCKS];
        run[0] = first_entry;
        let mut run_len = 1;
        while run_len < self.writeback_batch_blocks {
            let previous = &self.entries[run[run_len - 1]];
            let next = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| {
                    entry.state == EntryState::Dirty
                        && entry.first_sequence > previous.first_sequence
                })
                .min_by_key(|(_, entry)| entry.first_sequence);
            let Some((index, entry)) = next else {
                break;
            };
            if entry.block != previous.block.saturating_add(1)
                || ticket.is_some_and(|ticket| entry.first_sequence > ticket)
            {
                break;
            }
            run[run_len] = index;
            run_len += 1;
        }

        let block = self.entries[first_entry].block;
        let first_sequence = self.entries[first_entry].first_sequence;
        let last_sequence = run[..run_len]
            .iter()
            .map(|entry_index| self.entries[*entry_index].last_sequence)
            .max()
            .unwrap_or(first_sequence);
        for (offset, entry_index) in run[..run_len].iter().copied().enumerate() {
            let start = offset * WRITEBACK_BLOCK_SIZE;
            self.read_ahead[start..start + WRITEBACK_BLOCK_SIZE]
                .copy_from_slice(&self.entries[entry_index].data);
        }
        let byte_len = run_len * WRITEBACK_BLOCK_SIZE;
        let result = unsafe { self.inner.write_at(block, &self.read_ahead[..byte_len]) };
        match result {
            Ok(written) if written == byte_len => {
                for entry_index in run[..run_len].iter().copied() {
                    self.entries[entry_index].state = EntryState::Clean;
                }
                self.dirty_count -= run_len;
                self.metrics.blocks_written_back = self
                    .metrics
                    .blocks_written_back
                    .saturating_add(run_len as u64);
                self.metrics.bytes_written_back = self
                    .metrics
                    .bytes_written_back
                    .saturating_add(byte_len as u64);
                Ok(WriteBackProgress::WroteBlock {
                    block,
                    first_sequence,
                    last_sequence,
                })
            }
            Ok(_) => {
                self.record_failure(
                    EIO,
                    WriteBackFailureOperation::Write {
                        block,
                        first_sequence,
                        last_sequence,
                    },
                );
                Err(Error::new(EIO))
            }
            Err(error) => {
                self.record_failure(
                    error.errno,
                    WriteBackFailureOperation::Write {
                        block,
                        first_sequence,
                        last_sequence,
                    },
                );
                Err(error)
            }
        }
    }

    fn record_failure(&mut self, errno: i32, operation: WriteBackFailureOperation) {
        if self.failure.is_none() {
            self.failure = Some(WriteBackFailure { errno, operation });
        }
        bump(&mut self.metrics.writeback_errors);
    }

    fn lowest_sequence_dirty(&self) -> Option<usize> {
        let mut selected: Option<usize> = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.state != EntryState::Dirty {
                continue;
            }
            match selected {
                Some(previous) if self.entries[previous].first_sequence <= entry.first_sequence => {
                }
                _ => selected = Some(index),
            }
        }
        selected
    }

    fn validate_transfer(block: u64, byte_len: usize) -> Result<usize> {
        if byte_len % WRITEBACK_BLOCK_SIZE != 0 {
            return Err(Error::new(EINVAL));
        }
        let blocks = byte_len / WRITEBACK_BLOCK_SIZE;
        let blocks_u64 = u64::try_from(blocks).map_err(|_| Error::new(EINVAL))?;
        block.checked_add(blocks_u64).ok_or(Error::new(EINVAL))?;
        Ok(blocks)
    }

    fn preflight_write(&mut self, block: u64, block_count: usize) -> Result<()> {
        if self.is_read_only() {
            bump(&mut self.metrics.rejected_writes);
            return Err(Error::new(EROFS));
        }
        if block_count > self.entries.len() {
            bump(&mut self.metrics.rejected_writes);
            bump(&mut self.metrics.backpressure_events);
            return Err(Error::new(ENOSPC));
        }
        self.write_sequence
            .checked_add(block_count as u64)
            .ok_or_else(|| Error::new(EIO))?;

        let end = block + block_count as u64;
        let barrier_pending = self.flush_ticket_len != 0;
        let mut new_entries = 0_usize;
        for offset in 0..block_count {
            let target = block + offset as u64;
            if let Some(index) = self.lookup_entry(target) {
                let entry = &self.entries[index];
                if barrier_pending
                    && entry.state == EntryState::Dirty
                    && entry.first_sequence <= self.requested_sequence
                {
                    bump(&mut self.metrics.rejected_writes);
                    bump(&mut self.metrics.backpressure_events);
                    return Err(Error::new(EAGAIN));
                }
            } else {
                new_entries += 1;
            }
        }

        let mut reusable = self.reusable_count(block, end);
        let pressure_steps = new_entries.saturating_sub(reusable);
        for _ in 0..pressure_steps {
            if reusable >= new_entries {
                break;
            }
            let before = reusable;
            bump(&mut self.metrics.pressure_writeback_steps);
            self.writeback_step()?;
            reusable = self.reusable_count(block, end);
            if reusable <= before {
                bump(&mut self.metrics.rejected_writes);
                bump(&mut self.metrics.backpressure_events);
                bump(&mut self.metrics.pressure_stalls);
                return Err(Error::new(EAGAIN));
            }
            self.metrics.pressure_entries_freed = self
                .metrics
                .pressure_entries_freed
                .saturating_add((reusable - before) as u64);
        }
        if new_entries > reusable {
            bump(&mut self.metrics.rejected_writes);
            bump(&mut self.metrics.backpressure_events);
            bump(&mut self.metrics.pressure_stalls);
            return Err(Error::new(EAGAIN));
        }
        Ok(())
    }

    fn reusable_count(&self, protected_start: u64, protected_end: u64) -> usize {
        self.entries
            .iter()
            .filter(|entry| {
                entry.state == EntryState::Vacant
                    || (entry.state == EntryState::Clean
                        && !(entry.block >= protected_start && entry.block < protected_end))
            })
            .count()
    }

    fn accept_block(&mut self, block: u64, data: &[u8], sequence: u64) -> Result<()> {
        let access = self.next_access();
        if let Some(index) = self.lookup_entry(block) {
            let entry = &mut self.entries[index];
            if entry.state == EntryState::Dirty {
                bump(&mut self.metrics.coalesced_writes);
            } else {
                entry.state = EntryState::Dirty;
                entry.first_sequence = sequence;
                self.dirty_count += 1;
            }
            entry.data.copy_from_slice(data);
            entry.last_sequence = sequence;
            entry.last_used = access;
            return Ok(());
        }

        let Some(index) = self.reusable_entry(Some((block, block + 1))) else {
            return Err(Error::new(EAGAIN));
        };
        if !self.prepare_entry(index, block) {
            return Err(Error::new(EIO));
        }
        let entry = &mut self.entries[index];
        entry.data.copy_from_slice(data);
        entry.state = EntryState::Dirty;
        entry.first_sequence = sequence;
        entry.last_sequence = sequence;
        entry.last_used = access;
        self.dirty_count += 1;
        self.metrics.dirty_high_watermark = self.metrics.dirty_high_watermark.max(self.dirty_count);
        Ok(())
    }

    fn admit_clean(&mut self, block: u64, data: &[u8]) -> bool {
        if self.lookup_entry(block).is_some() {
            return true;
        }
        let Some(index) = self.reusable_entry(None) else {
            bump(&mut self.metrics.read_cache_admission_failures);
            return false;
        };
        let access = self.next_access();
        if !self.prepare_entry(index, block) {
            bump(&mut self.metrics.read_cache_admission_failures);
            return false;
        }
        let entry = &mut self.entries[index];
        entry.data.copy_from_slice(data);
        entry.state = EntryState::Clean;
        entry.first_sequence = 0;
        entry.last_sequence = 0;
        entry.last_used = access;
        true
    }

    fn reusable_entry(&self, protected: Option<(u64, u64)>) -> Option<usize> {
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.state == EntryState::Vacant)
        {
            return Some(index);
        }
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.state == EntryState::Clean
                    && protected
                        .map(|(start, end)| entry.block < start || entry.block >= end)
                        .unwrap_or(true)
            })
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(index, _)| index)
    }

    fn prepare_entry(&mut self, index: usize, block: u64) -> bool {
        if self.entries[index].state == EntryState::Clean {
            let old_block = self.entries[index].block;
            self.remove_lookup(old_block);
            bump(&mut self.metrics.clean_evictions);
        } else {
            self.resident_count += 1;
        }
        self.entries[index].block = block;
        if !self.insert_lookup(block, index) {
            return false;
        }
        bump(&mut self.metrics.cache_insertions);
        true
    }

    fn lookup_entry(&self, block: u64) -> Option<usize> {
        let mut slot = hash_block(block) as usize & self.lookup_mask;
        for _ in 0..self.lookup.len() {
            match self.lookup[slot] {
                LookupSlot::Empty => return None,
                LookupSlot::Occupied {
                    block: stored,
                    entry,
                } if stored == block => return Some(entry),
                LookupSlot::Tombstone | LookupSlot::Occupied { .. } => {
                    slot = (slot + 1) & self.lookup_mask;
                }
            }
        }
        None
    }

    fn insert_lookup(&mut self, block: u64, entry: usize) -> bool {
        let mut slot = hash_block(block) as usize & self.lookup_mask;
        let mut first_tombstone = None;
        for _ in 0..self.lookup.len() {
            match self.lookup[slot] {
                LookupSlot::Empty => {
                    let target = first_tombstone.unwrap_or(slot);
                    if first_tombstone.is_some() {
                        self.lookup_tombstones -= 1;
                    }
                    self.lookup[target] = LookupSlot::Occupied { block, entry };
                    return true;
                }
                LookupSlot::Tombstone => {
                    if first_tombstone.is_none() {
                        first_tombstone = Some(slot);
                    }
                }
                LookupSlot::Occupied { .. } => {}
            }
            slot = (slot + 1) & self.lookup_mask;
        }
        if let Some(target) = first_tombstone {
            self.lookup_tombstones -= 1;
            self.lookup[target] = LookupSlot::Occupied { block, entry };
            return true;
        }
        false
    }

    fn remove_lookup(&mut self, block: u64) {
        let mut slot = hash_block(block) as usize & self.lookup_mask;
        for _ in 0..self.lookup.len() {
            match self.lookup[slot] {
                LookupSlot::Empty => return,
                LookupSlot::Occupied { block: stored, .. } if stored == block => {
                    self.lookup[slot] = LookupSlot::Tombstone;
                    self.lookup_tombstones += 1;
                    bump(&mut self.metrics.lookup_tombstones_created);
                    return;
                }
                LookupSlot::Tombstone | LookupSlot::Occupied { .. } => {
                    slot = (slot + 1) & self.lookup_mask;
                }
            }
        }
    }

    fn next_access(&mut self) -> u64 {
        self.access_clock = self.access_clock.saturating_add(1);
        self.access_clock
    }
}

impl<D: Disk> Disk for WriteBackDisk<D> {
    unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        let block_count = Self::validate_transfer(block, buffer.len())?;
        bump(&mut self.metrics.read_requests);
        self.metrics.read_blocks = self.metrics.read_blocks.saturating_add(block_count as u64);

        let mut offset = 0;
        while offset < block_count {
            let target = block + offset as u64;
            let start = offset * WRITEBACK_BLOCK_SIZE;
            let end = start + WRITEBACK_BLOCK_SIZE;
            if let Some(index) = self.lookup_entry(target) {
                let access = self.next_access();
                let entry = &mut self.entries[index];
                if entry.state == EntryState::Vacant {
                    bump(&mut self.metrics.read_errors);
                    return Err(Error::new(EIO));
                }
                buffer[start..end].copy_from_slice(&entry.data);
                entry.last_used = access;
                bump(&mut self.metrics.read_hits);
                if entry.state == EntryState::Dirty {
                    bump(&mut self.metrics.dirty_read_hits);
                } else {
                    bump(&mut self.metrics.clean_read_hits);
                }
                offset += 1;
                continue;
            }

            let run_start = offset;
            let mut run_end = run_start + 1;
            while run_end < block_count && self.lookup_entry(block + run_end as u64).is_none() {
                run_end += 1;
            }
            let run_blocks = run_end - run_start;
            let byte_start = run_start * WRITEBACK_BLOCK_SIZE;
            let byte_end = run_end * WRITEBACK_BLOCK_SIZE;
            self.metrics.read_misses = self.metrics.read_misses.saturating_add(run_blocks as u64);
            bump(&mut self.metrics.underlying_reads);

            if run_blocks == 1 {
                let backing_bytes = self.inner.size().map_err(|error| {
                    bump(&mut self.metrics.read_errors);
                    error
                })?;
                let backing_blocks = backing_bytes / WRITEBACK_BLOCK_SIZE as u64;
                let target = block + run_start as u64;
                let read_ahead_blocks = usize::try_from(backing_blocks.saturating_sub(target))
                    .unwrap_or(usize::MAX)
                    .min(READ_AHEAD_BLOCKS)
                    .min(self.entries.len());

                if read_ahead_blocks > 1 {
                    let read_ahead_bytes = read_ahead_blocks * WRITEBACK_BLOCK_SIZE;
                    match self
                        .inner
                        .read_at(target, &mut self.read_ahead[..read_ahead_bytes])
                    {
                        Ok(bytes) if bytes == read_ahead_bytes => {
                            buffer[byte_start..byte_end]
                                .copy_from_slice(&self.read_ahead[..WRITEBACK_BLOCK_SIZE]);
                            for ahead in (1..read_ahead_blocks).chain(core::iter::once(0)) {
                                let start = ahead * WRITEBACK_BLOCK_SIZE;
                                let end = start + WRITEBACK_BLOCK_SIZE;
                                let mut block_data = [0; WRITEBACK_BLOCK_SIZE];
                                block_data.copy_from_slice(&self.read_ahead[start..end]);
                                self.admit_clean(target + ahead as u64, &block_data);
                            }
                            bump(&mut self.metrics.read_ahead_requests);
                            self.metrics.read_ahead_blocks = self
                                .metrics
                                .read_ahead_blocks
                                .saturating_add(read_ahead_blocks as u64);
                            offset = run_end;
                            continue;
                        }
                        Ok(_) => {
                            bump(&mut self.metrics.read_errors);
                            return Err(Error::new(EIO));
                        }
                        Err(error) => {
                            bump(&mut self.metrics.read_errors);
                            return Err(error);
                        }
                    }
                }
            }

            match self
                .inner
                .read_at(block + run_start as u64, &mut buffer[byte_start..byte_end])
            {
                Ok(bytes) if bytes == byte_end - byte_start => {
                    for admitted in run_start..run_end {
                        let admitted_start = admitted * WRITEBACK_BLOCK_SIZE;
                        let admitted_end = admitted_start + WRITEBACK_BLOCK_SIZE;
                        self.admit_clean(
                            block + admitted as u64,
                            &buffer[admitted_start..admitted_end],
                        );
                    }
                }
                Ok(_) => {
                    bump(&mut self.metrics.read_errors);
                    return Err(Error::new(EIO));
                }
                Err(error) => {
                    bump(&mut self.metrics.read_errors);
                    return Err(error);
                }
            }
            offset = run_end;
        }
        Ok(buffer.len())
    }

    unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        let block_count = Self::validate_transfer(block, buffer.len())?;
        bump(&mut self.metrics.write_requests);
        if block_count == 0 {
            return Ok(0);
        }
        self.preflight_write(block, block_count)?;

        for offset in 0..block_count {
            self.write_sequence += 1;
            let sequence = self.write_sequence;
            let start = offset * WRITEBACK_BLOCK_SIZE;
            let end = start + WRITEBACK_BLOCK_SIZE;
            self.accept_block(block + offset as u64, &buffer[start..end], sequence)?;
        }
        self.metrics.write_blocks_accepted = self
            .metrics
            .write_blocks_accepted
            .saturating_add(block_count as u64);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> Result<()> {
        let ticket = self.request_durability()?;
        if self.async_writeback_enabled {
            return Ok(());
        }

        bump(&mut self.metrics.synchronous_flush_drains);
        let max_steps = self.entries.len() + 1;
        let report = self
            .drain_ticket(ticket, max_steps)
            .map_err(|_| Error::new(EIO))?;
        if report.complete {
            Ok(())
        } else {
            bump(&mut self.metrics.synchronous_flush_incomplete);
            Err(Error::new(EAGAIN))
        }
    }

    fn requested_flush_sequence(&self) -> u64 {
        self.requested_sequence
    }

    fn durable_flush_sequence(&self) -> u64 {
        self.durable_sequence
    }

    fn size(&mut self) -> Result<u64> {
        self.inner.size()
    }
}

fn hash_block(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn bump(value: &mut u64) {
    *value = value.saturating_add(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Write(u64, u8),
        Flush,
    }

    struct FakeDisk {
        data: Vec<u8>,
        events: Vec<Event>,
        reads: usize,
        fail_flushes: usize,
        fail_writes: usize,
    }

    impl FakeDisk {
        fn new(blocks: usize) -> Self {
            let mut data = vec![0; blocks * WRITEBACK_BLOCK_SIZE];
            for block in 0..blocks {
                data[block * WRITEBACK_BLOCK_SIZE..(block + 1) * WRITEBACK_BLOCK_SIZE]
                    .fill(block as u8);
            }
            Self {
                data,
                events: Vec::new(),
                reads: 0,
                fail_flushes: 0,
                fail_writes: 0,
            }
        }
    }

    impl Disk for FakeDisk {
        unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
            self.reads += 1;
            let start = block as usize * WRITEBACK_BLOCK_SIZE;
            let end = start.checked_add(buffer.len()).ok_or(Error::new(EIO))?;
            let source = self.data.get(start..end).ok_or(Error::new(EIO))?;
            buffer.copy_from_slice(source);
            Ok(buffer.len())
        }

        unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
            if self.fail_writes != 0 {
                self.fail_writes -= 1;
                return Err(Error::new(EIO));
            }
            let start = block as usize * WRITEBACK_BLOCK_SIZE;
            let end = start.checked_add(buffer.len()).ok_or(Error::new(EIO))?;
            let destination = self.data.get_mut(start..end).ok_or(Error::new(EIO))?;
            destination.copy_from_slice(buffer);
            self.events.push(Event::Write(block, buffer[0]));
            Ok(buffer.len())
        }

        fn flush(&mut self) -> Result<()> {
            if self.fail_flushes != 0 {
                self.fail_flushes -= 1;
                return Err(Error::new(EIO));
            }
            self.events.push(Event::Flush);
            Ok(())
        }

        fn size(&mut self) -> Result<u64> {
            Ok(self.data.len() as u64)
        }
    }

    fn block(byte: u8) -> Vec<u8> {
        vec![byte; WRITEBACK_BLOCK_SIZE]
    }

    #[test]
    fn writeback_batch_limit_is_bounded_and_configurable() {
        assert!(matches!(
            WriteBackDisk::try_new_with_writeback_batch(FakeDisk::new(4), 2, 0),
            Err(WriteBackConfigError::InvalidWritebackBatch)
        ));
        assert!(matches!(
            WriteBackDisk::try_new_with_writeback_batch(
                FakeDisk::new(4),
                2,
                MAX_WRITEBACK_BATCH_BLOCKS + 1,
            ),
            Err(WriteBackConfigError::InvalidWritebackBatch)
        ));

        let mut disk = WriteBackDisk::try_new_with_writeback_batch(FakeDisk::new(4), 2, 1).unwrap();
        unsafe {
            disk.write_at(0, &vec![0x77; 2 * WRITEBACK_BLOCK_SIZE])
                .unwrap()
        };
        disk.writeback_step().unwrap();
        assert_eq!(disk.status().writeback_batch_blocks, 1);
        assert_eq!(disk.dirty_count(), 1);
        assert_eq!(disk.inner().events, vec![Event::Write(0, 0x77)]);
    }

    #[test]
    fn reads_miss_then_hit_and_dirty_data_wins() {
        let mut disk = WriteBackDisk::new(FakeDisk::new(8), 2).unwrap();
        let mut output = block(0xff);
        unsafe { disk.read_at(3, &mut output).unwrap() };
        assert_eq!(output[0], 3);
        unsafe { disk.read_at(3, &mut output).unwrap() };
        assert_eq!(disk.inner().reads, 1);

        unsafe { disk.write_at(3, &block(0xa5)).unwrap() };
        output.fill(0);
        unsafe { disk.read_at(3, &mut output).unwrap() };
        assert_eq!(output[0], 0xa5);
        let metrics = disk.metrics();
        assert_eq!(metrics.read_misses, 1);
        assert_eq!(metrics.clean_read_hits, 1);
        assert_eq!(metrics.dirty_read_hits, 1);
    }

    #[test]
    fn single_block_miss_reads_a_bounded_adjacent_window() {
        let mut disk = WriteBackDisk::new(FakeDisk::new(8), 4).unwrap();
        let mut output = block(0xff);

        unsafe { disk.read_at(0, &mut output).unwrap() };
        assert!(output.iter().all(|byte| *byte == 0));
        assert_eq!(disk.inner().reads, 1);
        assert_eq!(disk.metrics().read_ahead_requests, 1);
        assert_eq!(disk.metrics().read_ahead_blocks, READ_AHEAD_BLOCKS as u64);

        unsafe { disk.read_at(1, &mut output).unwrap() };
        assert!(output.iter().all(|byte| *byte == 1));
        assert_eq!(disk.inner().reads, 1);
        assert_eq!(disk.metrics().clean_read_hits, 1);
    }

    #[test]
    fn adjacent_cache_misses_use_one_backing_read_per_run() {
        let mut disk = WriteBackDisk::new(FakeDisk::new(8), 4).unwrap();
        unsafe { disk.write_at(2, &block(0xa5)).unwrap() };
        let mut output = vec![0; 4 * WRITEBACK_BLOCK_SIZE];

        unsafe { disk.read_at(0, &mut output).unwrap() };

        assert_eq!(disk.inner().reads, 2);
        assert_eq!(disk.metrics().underlying_reads, 2);
        assert_eq!(disk.metrics().read_misses, 3);
        assert_eq!(disk.metrics().dirty_read_hits, 1);
        assert!(output[..WRITEBACK_BLOCK_SIZE].iter().all(|byte| *byte == 0));
        assert!(output[WRITEBACK_BLOCK_SIZE..2 * WRITEBACK_BLOCK_SIZE]
            .iter()
            .all(|byte| *byte == 1));
        assert!(output[2 * WRITEBACK_BLOCK_SIZE..3 * WRITEBACK_BLOCK_SIZE]
            .iter()
            .all(|byte| *byte == 0xa5));
        assert!(output[3 * WRITEBACK_BLOCK_SIZE..]
            .iter()
            .all(|byte| *byte == 3));
    }

    #[test]
    fn coalesces_rewrites_without_losing_sequence_order() {
        let mut disk = WriteBackDisk::new(FakeDisk::new(8), 3).unwrap();
        unsafe {
            disk.write_at(2, &block(0x12)).unwrap();
            disk.write_at(3, &block(0x23)).unwrap();
            disk.write_at(2, &block(0x34)).unwrap();
        }

        assert_eq!(
            disk.writeback_step().unwrap(),
            WriteBackProgress::WroteBlock {
                block: 2,
                first_sequence: 1,
                last_sequence: 3,
            }
        );
        disk.writeback_step().unwrap();
        assert_eq!(disk.inner().events, vec![Event::Write(2, 0x34)]);
        assert_eq!(disk.metrics().coalesced_writes, 1);
    }

    #[test]
    fn evicts_clean_entries_and_applies_bounded_backpressure() {
        let mut disk = WriteBackDisk::new(FakeDisk::new(16), 2).unwrap();
        assert!(disk.enable_async_writeback());
        let mut output = block(0);
        unsafe {
            disk.read_at(0, &mut output).unwrap();
            disk.read_at(1, &mut output).unwrap();
            disk.read_at(2, &mut output).unwrap();
        }
        assert!(disk.metrics().clean_evictions >= 1);
        assert!(disk.status().lookup_tombstones <= disk.status().lookup_slot_count);

        unsafe {
            disk.write_at(8, &block(8)).unwrap();
            disk.write_at(9, &block(9)).unwrap();
        }
        Disk::flush(&mut disk).unwrap();
        unsafe {
            disk.write_at(10, &block(10)).unwrap();
            disk.write_at(11, &block(11)).unwrap();
        }
        let error = unsafe { disk.write_at(12, &block(12)) }.unwrap_err();
        assert_eq!(error.errno, EAGAIN);
        unsafe { disk.write_at(12, &block(12)).unwrap() };
        let error = unsafe { disk.write_at(13, &vec![1; 3 * WRITEBACK_BLOCK_SIZE]) }.unwrap_err();
        assert_eq!(error.errno, ENOSPC);
        assert_eq!(disk.dirty_count(), 1);
        assert_eq!(disk.metrics().pressure_stalls, 1);
    }

    #[test]
    fn boot_flush_is_durable_and_releases_same_block_barrier() {
        let mut disk = WriteBackDisk::new(FakeDisk::new(8), 2).unwrap();
        let before = disk.status();
        assert!(!disk.async_writeback_enabled());

        unsafe { disk.write_at(3, &block(0x31)).unwrap() };
        Disk::flush(&mut disk).unwrap();
        assert_eq!(disk.requested_sequence(), 1);
        assert_eq!(disk.durable_sequence(), 1);
        assert_eq!(disk.dirty_count(), 0);
        assert_eq!(
            disk.inner().events,
            vec![Event::Write(3, 0x31), Event::Flush]
        );

        unsafe { disk.write_at(3, &block(0x32)).unwrap() };
        Disk::flush(&mut disk).unwrap();
        assert_eq!(disk.requested_sequence(), 2);
        assert_eq!(disk.durable_sequence(), 2);
        assert_eq!(
            disk.inner().events,
            vec![
                Event::Write(3, 0x31),
                Event::Flush,
                Event::Write(3, 0x32),
                Event::Flush
            ]
        );
        let after = disk.status();
        assert_eq!(
            after.entry_allocation_capacity,
            before.entry_allocation_capacity
        );
        assert_eq!(
            after.lookup_allocation_capacity,
            before.lookup_allocation_capacity
        );
        assert_eq!(
            after.flush_ticket_allocation_capacity,
            before.flush_ticket_allocation_capacity
        );
    }

    #[test]
    fn async_mode_flush_returns_pending_and_steps_make_it_durable() {
        let mut disk = WriteBackDisk::new(FakeDisk::new(8), 2).unwrap();
        let before = disk.status();
        assert!(disk.enable_async_writeback());
        assert!(!disk.enable_async_writeback());
        assert!(disk.is_async_writeback_enabled());

        unsafe { disk.write_at(4, &block(0x44)).unwrap() };
        Disk::flush(&mut disk).unwrap();
        assert_eq!(disk.requested_sequence(), 1);
        assert_eq!(disk.durable_sequence(), 0);
        assert_eq!(disk.status().pending_flush_tickets, 1);
        assert!(disk.inner().events.is_empty());

        assert!(matches!(
            disk.writeback_step().unwrap(),
            WriteBackProgress::WroteBlock { block: 4, .. }
        ));
        assert_eq!(disk.durable_sequence(), 0);
        assert!(matches!(
            disk.writeback_step().unwrap(),
            WriteBackProgress::Flushed {
                durable_sequence: 1
            }
        ));
        assert_eq!(disk.durable_sequence(), 1);
        assert_eq!(disk.status().pending_flush_tickets, 0);
        assert_eq!(
            disk.inner().events,
            vec![Event::Write(4, 0x44), Event::Flush]
        );

        let after = disk.status();
        assert_eq!(
            after.entry_allocation_capacity,
            before.entry_allocation_capacity
        );
        assert_eq!(
            after.lookup_allocation_capacity,
            before.lookup_allocation_capacity
        );
        assert_eq!(
            after.flush_ticket_allocation_capacity,
            before.flush_ticket_allocation_capacity
        );
        assert_eq!(disk.metrics().async_writeback_enables, 1);
    }

    #[test]
    fn flush_ticket_excludes_later_dispatch_and_barrier_crossing_rewrite() {
        let mut disk = WriteBackDisk::new(FakeDisk::new(8), 3).unwrap();
        assert!(disk.enable_async_writeback());
        unsafe { disk.write_at(1, &block(0x11)).unwrap() };
        Disk::flush(&mut disk).unwrap();
        let ticket = disk.requested_sequence();
        assert_eq!(ticket, 1);

        let error = unsafe { disk.write_at(1, &block(0x22)) }.unwrap_err();
        assert_eq!(error.errno, EAGAIN);
        unsafe { disk.write_at(2, &block(0x33)).unwrap() };
        Disk::flush(&mut disk).unwrap();
        assert_eq!(disk.requested_sequence(), 2);

        disk.writeback_step().unwrap();
        disk.writeback_step().unwrap();
        assert_eq!(disk.durable_sequence(), ticket);
        assert_eq!(
            disk.inner().events,
            vec![Event::Write(1, 0x11), Event::Flush]
        );
        disk.writeback_step().unwrap();
        assert_eq!(
            disk.inner().events,
            vec![Event::Write(1, 0x11), Event::Flush, Event::Write(2, 0x33)]
        );
        disk.writeback_step().unwrap();
        assert_eq!(disk.durable_sequence(), 2);
        assert_eq!(disk.inner().events.last(), Some(&Event::Flush));
    }

    #[test]
    fn flush_failure_is_sticky_read_only_and_can_be_retried() {
        let mut inner = FakeDisk::new(8);
        inner.fail_flushes = 1;
        let mut disk = WriteBackDisk::new(inner, 2).unwrap();
        assert!(disk.enable_async_writeback());
        unsafe { disk.write_at(1, &block(0x44)).unwrap() };
        Disk::flush(&mut disk).unwrap();
        disk.writeback_step().unwrap();
        assert_eq!(disk.writeback_step().unwrap_err().errno, EIO);
        assert!(disk.is_read_only());
        assert!(matches!(
            disk.failure().unwrap().operation,
            WriteBackFailureOperation::Flush { .. }
        ));
        assert_eq!(disk.writeback_step().unwrap_err().errno, EIO);
        assert_eq!(
            unsafe { disk.write_at(2, &block(2)) }.unwrap_err().errno,
            EROFS
        );

        assert!(matches!(
            disk.retry_writeback_step().unwrap(),
            WriteBackProgress::Flushed {
                durable_sequence: 1
            }
        ));
        assert!(!disk.is_read_only());
        assert_eq!(disk.durable_sequence(), 1);
        unsafe { disk.write_at(2, &block(2)).unwrap() };
    }

    #[test]
    fn accepts_and_writes_back_transfers_larger_than_4k() {
        let mut disk = WriteBackDisk::new(FakeDisk::new(8), 4).unwrap();
        let mut input = vec![0; 3 * WRITEBACK_BLOCK_SIZE];
        input[..WRITEBACK_BLOCK_SIZE].fill(0x51);
        input[WRITEBACK_BLOCK_SIZE..2 * WRITEBACK_BLOCK_SIZE].fill(0x52);
        input[2 * WRITEBACK_BLOCK_SIZE..].fill(0x53);
        assert_eq!(unsafe { disk.write_at(2, &input).unwrap() }, input.len());

        let mut output = vec![0; input.len()];
        unsafe { disk.read_at(2, &mut output).unwrap() };
        assert_eq!(output, input);
        assert_eq!(disk.inner().reads, 0);
        disk.writeback_step().unwrap();
        disk.writeback_step().unwrap();
        assert_eq!(
            disk.inner().events,
            vec![Event::Write(2, 0x51), Event::Write(4, 0x53)]
        );
        assert_eq!(disk.dirty_count(), 0);
        for (offset, expected) in [0x51, 0x52, 0x53].into_iter().enumerate() {
            let start = (2 + offset) * WRITEBACK_BLOCK_SIZE;
            assert!(disk.inner().data[start..start + WRITEBACK_BLOCK_SIZE]
                .iter()
                .all(|byte| *byte == expected));
        }
    }

    #[test]
    fn quiesce_and_shutdown_drain_are_bounded() {
        let mut disk = WriteBackDisk::new(FakeDisk::new(8), 3).unwrap();
        unsafe {
            disk.write_at(0, &block(1)).unwrap();
            disk.write_at(1, &block(2)).unwrap();
        }
        let first = disk.shutdown_drain(2).unwrap();
        assert!(first.complete);
        assert_eq!(first.steps, 2);
        assert_eq!(first.dirty_remaining, 0);
        assert!(disk.is_quiesced());
        assert_eq!(
            unsafe { disk.write_at(2, &block(3)) }.unwrap_err().errno,
            EROFS
        );

        let second = disk.shutdown_drain(1).unwrap();
        assert!(second.complete);
        assert_eq!(second.steps, 0);
        assert_eq!(second.ticket, 2);
        assert_eq!(disk.inner().events.last(), Some(&Event::Flush));
    }

    #[test]
    fn pressure_writes_more_unique_blocks_than_capacity_without_a_worker() {
        const CACHE_ENTRIES: usize = 3;
        const BLOCKS_WRITTEN: usize = 8;

        let mut disk = WriteBackDisk::new(FakeDisk::new(16), CACHE_ENTRIES).unwrap();
        let before = disk.status();
        for target in 0..BLOCKS_WRITTEN {
            unsafe {
                disk.write_at(target as u64, &block(0x40 + target as u8))
                    .unwrap();
            }
            if target < CACHE_ENTRIES {
                assert!(disk.inner().events.is_empty());
            }
        }

        assert_eq!(
            disk.inner().events,
            vec![
                Event::Write(0, 0x40),
                Event::Write(2, 0x42),
                Event::Write(4, 0x44)
            ]
        );
        for target in 0..BLOCKS_WRITTEN {
            let mut output = block(0);
            unsafe { disk.read_at(target as u64, &mut output).unwrap() };
            assert!(output.iter().all(|byte| *byte == 0x40 + target as u8));
        }

        let after_pressure = disk.status();
        assert_eq!(after_pressure.entry_count, before.entry_count);
        assert_eq!(after_pressure.lookup_slot_count, before.lookup_slot_count);
        assert_eq!(
            after_pressure.entry_allocation_capacity,
            before.entry_allocation_capacity
        );
        assert_eq!(
            after_pressure.lookup_allocation_capacity,
            before.lookup_allocation_capacity
        );
        assert_eq!(
            after_pressure.flush_ticket_allocation_capacity,
            before.flush_ticket_allocation_capacity
        );
        assert_eq!(disk.metrics().pressure_writeback_steps, 3);
        assert_eq!(disk.metrics().pressure_entries_freed, 6);

        Disk::flush(&mut disk).unwrap();
        while disk.durable_sequence() < disk.requested_sequence() {
            disk.writeback_step().unwrap();
        }
        assert_eq!(
            disk.inner().events,
            vec![
                Event::Write(0, 0x40),
                Event::Write(2, 0x42),
                Event::Write(4, 0x44),
                Event::Write(6, 0x46),
                Event::Flush
            ]
        );
        for target in 0..BLOCKS_WRITTEN {
            let start = target * WRITEBACK_BLOCK_SIZE;
            assert!(disk.inner().data[start..start + WRITEBACK_BLOCK_SIZE]
                .iter()
                .all(|byte| *byte == 0x40 + target as u8));
        }
    }

    #[test]
    fn operation_paths_never_grow_preallocated_storage() {
        let mut disk = WriteBackDisk::new(FakeDisk::new(64), 4).unwrap();
        let before = disk.status();
        let mut output = block(0);
        for target in 0..24 {
            unsafe { disk.read_at(target, &mut output).unwrap() };
        }
        for target in 24..28 {
            unsafe { disk.write_at(target, &block(target as u8)).unwrap() };
        }
        Disk::flush(&mut disk).unwrap();
        while disk.durable_sequence() < disk.requested_sequence() {
            disk.writeback_step().unwrap();
        }
        let after = disk.status();
        assert_eq!(after.entry_count, before.entry_count);
        assert_eq!(after.lookup_slot_count, before.lookup_slot_count);
        assert_eq!(
            after.flush_ticket_slot_count,
            before.flush_ticket_slot_count
        );
        assert_eq!(
            after.entry_allocation_capacity,
            before.entry_allocation_capacity
        );
        assert_eq!(
            after.lookup_allocation_capacity,
            before.lookup_allocation_capacity
        );
        assert_eq!(
            after.flush_ticket_allocation_capacity,
            before.flush_ticket_allocation_capacity
        );
    }

    #[test]
    fn rejects_partial_blocks_without_mutating_sequences() {
        let mut disk = WriteBackDisk::new(FakeDisk::new(4), 2).unwrap();
        assert_eq!(unsafe { disk.write_at(0, &[1]) }.unwrap_err().errno, EINVAL);
        assert_eq!(disk.status().write_sequence, 0);
        let mut short = [0; 1];
        assert_eq!(
            unsafe { disk.read_at(0, &mut short) }.unwrap_err().errno,
            EINVAL
        );
    }

    #[test]
    fn write_failure_retries_the_same_dirty_block() {
        let mut inner = FakeDisk::new(4);
        inner.fail_writes = 1;
        let mut disk = WriteBackDisk::new(inner, 1).unwrap();
        unsafe { disk.write_at(1, &block(0x77)).unwrap() };
        assert_eq!(disk.writeback_step().unwrap_err().errno, EIO);
        assert_eq!(disk.dirty_count(), 1);
        assert!(matches!(
            disk.retry_writeback_step().unwrap(),
            WriteBackProgress::WroteBlock { block: 1, .. }
        ));
        assert_eq!(disk.dirty_count(), 0);
        assert_eq!(disk.inner().events, vec![Event::Write(1, 0x77)]);
    }
}
