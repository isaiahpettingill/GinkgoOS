//! Physical-frame-backed shared memory and allocation-free deferred reclamation.

use alloc::{sync::Arc, vec::Vec};
use core::{cmp, ptr};

use ginkgo_ipc::{Handle, HandleTable, IpcError, SharedMemoryStorage, SHARED_MEMORY_PAGE_SIZE};
use spinning_top::Spinlock;
use x86_64::{
    structures::paging::{PhysFrame, Size4KiB},
    VirtAddr,
};

use crate::{
    memory::{FrameAllocatorError, UsableFrameAllocator},
    paging::ActivePageTable,
};

const PAGE_SIZE: usize = SHARED_MEMORY_PAGE_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameSharedMemoryError {
    InvalidSize,
    OutOfMemory,
    FrameAllocator(FrameAllocatorError),
    InvalidHhdmAddress(u64),
    InvalidHhdmAlignment(u64),
}

impl From<FrameSharedMemoryError> for IpcError {
    fn from(error: FrameSharedMemoryError) -> Self {
        match error {
            FrameSharedMemoryError::InvalidSize
            | FrameSharedMemoryError::InvalidHhdmAddress(_)
            | FrameSharedMemoryError::InvalidHhdmAlignment(_) => IpcError::InvalidMessage,
            FrameSharedMemoryError::OutOfMemory | FrameSharedMemoryError::FrameAllocator(_) => {
                IpcError::OutOfMemory
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SharedFrameArenaStats {
    pub owned_frames: usize,
    pub free_frames: usize,
    pub returned_frames: usize,
    pub reclaimed_frames: usize,
    pub reclaim_failures: usize,
    pub last_reclaim_error: Option<FrameAllocatorError>,
}

struct SharedFrameArenaState {
    free: Vec<PhysFrame<Size4KiB>>,
    owned_frames: usize,
    returned_frames: usize,
    reclaimed_frames: usize,
    reclaim_failures: usize,
    last_reclaim_error: Option<FrameAllocatorError>,
}

/// Owns frame metadata between backing destruction and an explicit allocator safe point.
///
/// Before fresh frames are issued, `free` reserves capacity for every frame owned by
/// the arena. A storage destructor can therefore return its complete frame vector by
/// pushing into already-reserved capacity and never allocates.
#[derive(Clone)]
pub struct SharedFrameArena {
    state: Arc<Spinlock<SharedFrameArenaState>>,
}

impl SharedFrameArena {
    pub fn new() -> Result<Self, FrameSharedMemoryError> {
        let state = Arc::try_new(Spinlock::new(SharedFrameArenaState {
            free: Vec::new(),
            owned_frames: 0,
            returned_frames: 0,
            reclaimed_frames: 0,
            reclaim_failures: 0,
            last_reclaim_error: None,
        }))
        .map_err(|_| FrameSharedMemoryError::OutOfMemory)?;
        Ok(Self { state })
    }

    pub fn stats(&self) -> SharedFrameArenaStats {
        let state = self.state.lock();
        SharedFrameArenaStats {
            owned_frames: state.owned_frames,
            free_frames: state.free.len(),
            returned_frames: state.returned_frames,
            reclaimed_frames: state.reclaimed_frames,
            reclaim_failures: state.reclaim_failures,
            last_reclaim_error: state.last_reclaim_error,
        }
    }

    /// Returns every currently idle frame to the general allocator exactly once.
    pub fn reclaim_idle(
        &self,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<usize, FrameAllocatorError> {
        let mut state = self.state.lock();
        if state.free.is_empty() {
            return Ok(0);
        }
        if let Err(error) = allocator.deallocate_frames(&state.free) {
            state.reclaim_failures = state.reclaim_failures.saturating_add(1);
            state.last_reclaim_error = Some(error);
            return Err(error);
        }
        let reclaimed = state.free.len();
        state.free.clear();
        state.owned_frames = state
            .owned_frames
            .checked_sub(reclaimed)
            .expect("shared-frame arena ownership underflow");
        state.reclaimed_frames = state.reclaimed_frames.saturating_add(reclaimed);
        state.last_reclaim_error = None;
        Ok(reclaimed)
    }

    fn acquire(
        &self,
        page_count: usize,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<Vec<PhysFrame<Size4KiB>>, FrameSharedMemoryError> {
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(page_count)
            .map_err(|_| FrameSharedMemoryError::OutOfMemory)?;

        // One lock covers capacity reservation, removal of reusable frames, fresh
        // allocator ownership, and commit or rollback. Concurrent acquisitions and
        // drops therefore cannot consume capacity reserved for this transaction.
        let mut state = self.state.lock();
        let fresh_needed = page_count.saturating_sub(state.free.len());
        let target_capacity = state
            .owned_frames
            .checked_add(fresh_needed)
            .ok_or(FrameSharedMemoryError::InvalidSize)?;
        let additional = target_capacity.saturating_sub(state.free.len());
        state
            .free
            .try_reserve_exact(additional)
            .map_err(|_| FrameSharedMemoryError::OutOfMemory)?;
        debug_assert!(state.free.capacity() >= target_capacity);

        let reused = cmp::min(page_count, state.free.len());
        for _ in 0..reused {
            frames.push(
                state
                    .free
                    .pop()
                    .expect("reused frame count was preflighted"),
            );
        }

        while frames.len() < page_count {
            let allocation_error = match allocator.allocate_frame() {
                Ok(Some(frame)) => {
                    frames.push(frame);
                    continue;
                }
                Ok(None) => FrameSharedMemoryError::OutOfMemory,
                Err(error) => FrameSharedMemoryError::FrameAllocator(error),
            };
            if let Err(rollback_error) =
                Self::rollback_acquire_locked(&mut state, &mut frames, reused, allocator)
            {
                return Err(rollback_error);
            }
            return Err(allocation_error);
        }

        let fresh = page_count - reused;
        state.owned_frames = state
            .owned_frames
            .checked_add(fresh)
            .expect("shared-frame ownership was preflighted");
        debug_assert!(state.free.capacity() >= state.owned_frames);
        Ok(frames)
    }

    fn rollback_acquire_locked(
        state: &mut SharedFrameArenaState,
        frames: &mut Vec<PhysFrame<Size4KiB>>,
        reused: usize,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<(), FrameSharedMemoryError> {
        if frames.len() > reused {
            let fresh = frames.len() - reused;
            if let Err(error) = allocator.deallocate_frames(&frames[reused..]) {
                state.owned_frames = state
                    .owned_frames
                    .checked_add(fresh)
                    .expect("shared-frame rollback ownership was preflighted");
                Self::return_frames_locked(state, frames, false);
                return Err(FrameSharedMemoryError::FrameAllocator(error));
            }
            frames.truncate(reused);
        }
        Self::return_frames_locked(state, frames, false);
        Ok(())
    }

    fn return_frames(&self, frames: &mut Vec<PhysFrame<Size4KiB>>, count_return: bool) {
        let mut state = self.state.lock();
        Self::return_frames_locked(&mut state, frames, count_return);
    }

    fn return_frames_locked(
        state: &mut SharedFrameArenaState,
        frames: &mut Vec<PhysFrame<Size4KiB>>,
        count_return: bool,
    ) {
        assert!(
            state.free.len() + frames.len() <= state.free.capacity(),
            "shared-frame ownership metadata invariant violated"
        );
        if count_return {
            state.returned_frames = state.returned_frames.saturating_add(frames.len());
        }
        for frame in frames.drain(..) {
            state.free.push(frame);
        }
    }
}

/// One immutable list of noncontiguous physical pages owned until final `Arc` drop.
pub struct FrameSharedMemoryStorage {
    arena: SharedFrameArena,
    frames: Vec<PhysFrame<Size4KiB>>,
    logical_len: usize,
    mapped_len: usize,
    hhdm_offset: VirtAddr,
    access: Spinlock<()>,
}

impl FrameSharedMemoryStorage {
    fn create(
        arena: &SharedFrameArena,
        logical_len: usize,
        hhdm_offset: VirtAddr,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<Arc<dyn SharedMemoryStorage>, FrameSharedMemoryError> {
        if logical_len == 0 {
            return Err(FrameSharedMemoryError::InvalidSize);
        }
        let mapped_len = logical_len
            .checked_add(PAGE_SIZE - 1)
            .ok_or(FrameSharedMemoryError::InvalidSize)?
            & !(PAGE_SIZE - 1);
        let page_count = mapped_len / PAGE_SIZE;
        let mut frames = arena.acquire(page_count, allocator)?;

        if let Err(error) = zero_frames(&frames, hhdm_offset) {
            // Acquisition already transferred every frame into arena ownership.
            // Preserve that exact owner even when an invalid HHDM prevents zeroing.
            arena.return_frames(&mut frames, false);
            return Err(error);
        }

        let storage = Self {
            arena: arena.clone(),
            frames,
            logical_len,
            mapped_len,
            hhdm_offset,
            access: Spinlock::new(()),
        };
        let storage: Arc<dyn SharedMemoryStorage> =
            Arc::try_new(storage).map_err(|_| FrameSharedMemoryError::OutOfMemory)?;
        Ok(storage)
    }

    fn copy_out(&self, offset: usize, output: &mut [u8]) -> Result<(), IpcError> {
        checked_range(offset, output.len(), self.logical_len)?;
        let mut copied = 0;
        while copied < output.len() {
            let absolute = offset + copied;
            let page_index = absolute / PAGE_SIZE;
            let in_page = absolute % PAGE_SIZE;
            let count = cmp::min(PAGE_SIZE - in_page, output.len() - copied);
            let page = frame_pointer(self.frames[page_index], self.hhdm_offset)
                .map_err(|_| IpcError::InvalidMessage)?;
            unsafe {
                ptr::copy_nonoverlapping(page.add(in_page), output.as_mut_ptr().add(copied), count)
            };
            copied += count;
        }
        Ok(())
    }

    fn copy_in(&self, offset: usize, input: &[u8]) -> Result<(), IpcError> {
        checked_range(offset, input.len(), self.logical_len)?;
        let mut copied = 0;
        while copied < input.len() {
            let absolute = offset + copied;
            let page_index = absolute / PAGE_SIZE;
            let in_page = absolute % PAGE_SIZE;
            let count = cmp::min(PAGE_SIZE - in_page, input.len() - copied);
            let page = frame_pointer(self.frames[page_index], self.hhdm_offset)
                .map_err(|_| IpcError::InvalidMessage)?;
            unsafe {
                ptr::copy_nonoverlapping(input.as_ptr().add(copied), page.add(in_page), count)
            };
            copied += count;
        }
        Ok(())
    }
}

// SAFETY: every reported frame was transferred from UsableFrameAllocator into
// this storage's arena and is returned only after the final storage Arc drops.
unsafe impl SharedMemoryStorage for FrameSharedMemoryStorage {
    fn logical_len(&self) -> usize {
        self.logical_len
    }

    fn mapped_len(&self) -> usize {
        self.mapped_len
    }

    fn physical_page(&self, page_index: usize) -> Option<u64> {
        self.frames
            .get(page_index)
            .map(|frame| frame.start_address().as_u64())
    }

    fn read(&self, offset: usize, output: &mut [u8]) -> Result<(), IpcError> {
        let _access = self.access.lock();
        self.copy_out(offset, output)
    }

    fn write(&self, offset: usize, input: &[u8]) -> Result<(), IpcError> {
        let _access = self.access.lock();
        self.copy_in(offset, input)
    }
}

impl Drop for FrameSharedMemoryStorage {
    fn drop(&mut self) {
        self.arena.return_frames(&mut self.frames, true);
    }
}

/// Short-lived creation authority combining the arena with the general allocator.
pub struct SharedMemoryFactory<'a, 'memory> {
    arena: &'a SharedFrameArena,
    allocator: &'a mut UsableFrameAllocator<'memory>,
    hhdm_offset: VirtAddr,
}

impl<'a, 'memory> SharedMemoryFactory<'a, 'memory> {
    /// Derives shared-frame direct access from the active page-table authority.
    pub fn new(
        arena: &'a SharedFrameArena,
        allocator: &'a mut UsableFrameAllocator<'memory>,
        page_table: &ActivePageTable,
    ) -> Self {
        Self {
            arena,
            allocator,
            hhdm_offset: page_table.hhdm_offset(),
        }
    }

    /// Builds test-only creation authority over a caller-provided direct mapping.
    ///
    /// # Safety
    ///
    /// `hhdm_offset + frame.start_address()` must identify a writable, coherent,
    /// aligned mapping of every complete allocator-issued frame for the lifetime of
    /// all storage created by this factory. No incompatible Rust references or
    /// mappings may access those bytes concurrently.
    #[cfg(test)]
    pub(crate) unsafe fn from_test_hhdm(
        arena: &'a SharedFrameArena,
        allocator: &'a mut UsableFrameAllocator<'memory>,
        hhdm_offset: u64,
    ) -> Result<Self, FrameSharedMemoryError> {
        let hhdm_offset = VirtAddr::try_new(hhdm_offset)
            .map_err(|_| FrameSharedMemoryError::InvalidHhdmAddress(hhdm_offset))?;
        if !hhdm_offset.is_aligned(PAGE_SIZE as u64) {
            return Err(FrameSharedMemoryError::InvalidHhdmAlignment(
                hhdm_offset.as_u64(),
            ));
        }
        Ok(Self {
            arena,
            allocator,
            hhdm_offset,
        })
    }

    pub fn create_handle(
        &mut self,
        handles: &mut HandleTable,
        logical_len: usize,
    ) -> Result<Handle, IpcError> {
        let storage = FrameSharedMemoryStorage::create(
            self.arena,
            logical_len,
            self.hhdm_offset,
            self.allocator,
        )?;
        handles.shared_memory_create_with_storage(storage)
    }
}

fn zero_frames(
    frames: &[PhysFrame<Size4KiB>],
    hhdm_offset: VirtAddr,
) -> Result<(), FrameSharedMemoryError> {
    for frame in frames {
        let page = frame_pointer(*frame, hhdm_offset)?;
        unsafe { ptr::write_bytes(page, 0, PAGE_SIZE) };
    }
    Ok(())
}

fn frame_pointer(
    frame: PhysFrame<Size4KiB>,
    hhdm_offset: VirtAddr,
) -> Result<*mut u8, FrameSharedMemoryError> {
    let physical = frame.start_address().as_u64();
    let address = hhdm_offset
        .as_u64()
        .checked_add(physical)
        .ok_or(FrameSharedMemoryError::InvalidHhdmAddress(physical))?;
    let final_byte = address
        .checked_add(PAGE_SIZE as u64 - 1)
        .ok_or(FrameSharedMemoryError::InvalidHhdmAddress(address))?;
    let address = VirtAddr::try_new(address)
        .map_err(|_| FrameSharedMemoryError::InvalidHhdmAddress(address))?;
    VirtAddr::try_new(final_byte)
        .map_err(|_| FrameSharedMemoryError::InvalidHhdmAddress(final_byte))?;
    Ok(address.as_mut_ptr())
}

fn checked_range(offset: usize, len: usize, logical_len: usize) -> Result<(), IpcError> {
    let end = offset.checked_add(len).ok_or(IpcError::InvalidMessage)?;
    if end > logical_len {
        Err(IpcError::InvalidMessage)
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use alloc::alloc::{alloc_zeroed, dealloc, Layout};
    use core::ptr::NonNull;

    use super::*;

    pub struct TestSharedMemoryContext {
        allocator: UsableFrameAllocator<'static>,
        arena: SharedFrameArena,
        pointer: NonNull<u8>,
        layout: Layout,
    }

    impl TestSharedMemoryContext {
        pub fn new(pages: usize) -> Self {
            let size = pages * PAGE_SIZE;
            let layout = Layout::from_size_align(size, PAGE_SIZE).unwrap();
            let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).expect("test frame region");
            let allocator = unsafe {
                UsableFrameAllocator::from_test_region(pointer.as_ptr() as u64, size as u64, 52)
            };
            Self {
                allocator,
                arena: SharedFrameArena::new().unwrap(),
                pointer,
                layout,
            }
        }

        pub fn factory(&mut self) -> SharedMemoryFactory<'_, 'static> {
            // SAFETY: the test allocator issues pages inside the retained aligned
            // host allocation, whose address is used directly with offset zero.
            unsafe { SharedMemoryFactory::from_test_hhdm(&self.arena, &mut self.allocator, 0) }
                .unwrap()
        }

        pub fn arena(&self) -> &SharedFrameArena {
            &self.arena
        }

        pub fn allocator(&mut self) -> &mut UsableFrameAllocator<'static> {
            &mut self.allocator
        }

        pub fn create_storage(
            &mut self,
            logical_len: usize,
        ) -> Result<Arc<dyn SharedMemoryStorage>, FrameSharedMemoryError> {
            // SAFETY: `new` retains the complete aligned host allocation and the
            // test allocator issues only frames within it.
            let hhdm = unsafe {
                SharedMemoryFactory::from_test_hhdm(&self.arena, &mut self.allocator, 0)?
            };
            FrameSharedMemoryStorage::create(
                hhdm.arena,
                logical_len,
                hhdm.hhdm_offset,
                hhdm.allocator,
            )
        }

        pub fn reclaim_idle(&mut self) -> Result<usize, FrameAllocatorError> {
            self.arena.reclaim_idle(&mut self.allocator)
        }

        pub fn free_capacity(&self) -> usize {
            self.arena.state.lock().free.capacity()
        }
    }

    impl Drop for TestSharedMemoryContext {
        fn drop(&mut self) {
            assert_eq!(
                self.arena.stats().owned_frames,
                self.arena.stats().free_frames
            );
            self.arena.reclaim_idle(&mut self.allocator).unwrap();
            assert_eq!(self.allocator.allocated_count(), 0);
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::vec;

    use ginkgo_ipc::SharedMemoryMappingAccess;
    use std::thread;
    use x86_64::PhysAddr;

    use super::test_support::TestSharedMemoryContext;
    use super::*;

    #[test]
    fn page_plus_one_is_zeroed_and_reused_pages_need_not_be_contiguous() {
        let mut context = TestSharedMemoryContext::new(4);
        {
            let storage = context.create_storage(PAGE_SIZE * 3).unwrap();
            drop(storage);
        }
        let storage = context.create_storage(PAGE_SIZE + 1).unwrap();
        assert_ne!(
            storage.physical_page(1).unwrap(),
            storage.physical_page(0).unwrap() + PAGE_SIZE as u64
        );
        let mut bytes = vec![0xff; PAGE_SIZE + 1];
        storage.read(0, &mut bytes).unwrap();
        assert!(bytes.iter().all(|byte| *byte == 0));
        let tail_page = frame_pointer(
            PhysFrame::from_start_address(x86_64::PhysAddr::new(storage.physical_page(1).unwrap()))
                .unwrap(),
            VirtAddr::zero(),
        )
        .unwrap();
        let complete_tail = unsafe { core::slice::from_raw_parts(tail_page, PAGE_SIZE) };
        assert!(complete_tail.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn read_and_write_cross_page_boundaries() {
        let mut context = TestSharedMemoryContext::new(2);
        let storage = context.create_storage(PAGE_SIZE + 8).unwrap();
        storage.write(PAGE_SIZE - 3, b"crossing").unwrap();
        let mut bytes = [0; 8];
        storage.read(PAGE_SIZE - 3, &mut bytes).unwrap();
        assert_eq!(&bytes, b"crossing");
    }

    #[test]
    fn allocation_failure_rolls_back_every_fresh_frame() {
        let mut context = TestSharedMemoryContext::new(1);
        let before = context.allocator().allocated_count();
        assert!(matches!(
            context.create_storage(PAGE_SIZE + 1),
            Err(FrameSharedMemoryError::OutOfMemory)
        ));
        assert_eq!(context.allocator().allocated_count(), before);
        assert_eq!(context.arena().stats().owned_frames, 0);
    }

    #[test]
    fn handles_windows_and_mapping_leases_each_retain_frame_ownership() {
        let mut context = TestSharedMemoryContext::new(4);
        let mut handles = HandleTable::new();
        let memory = context
            .factory()
            .create_handle(&mut handles, PAGE_SIZE * 2)
            .unwrap();
        let lease = handles
            .shared_memory_mapping_lease(memory, SharedMemoryMappingAccess::ReadWrite)
            .unwrap();
        let (client, manager) = handles.window_create(memory).unwrap();

        handles.handle_close(memory).unwrap();
        assert_eq!(context.arena().stats().free_frames, 0);
        handles.handle_close(client).unwrap();
        handles.handle_close(manager).unwrap();
        assert_eq!(context.arena().stats().free_frames, 0);
        drop(lease);
        assert_eq!(context.arena().stats().free_frames, 2);

        let memory = context
            .factory()
            .create_handle(&mut handles, PAGE_SIZE)
            .unwrap();
        let (client, manager) = handles.window_create(memory).unwrap();
        handles.handle_close(memory).unwrap();
        assert_eq!(context.arena().stats().free_frames, 1);
        handles.handle_close(client).unwrap();
        handles.handle_close(manager).unwrap();
        assert_eq!(context.arena().stats().free_frames, 2);
    }

    #[test]
    fn final_storage_drop_reuses_then_reclaims_frames_exactly_once() {
        let mut context = TestSharedMemoryContext::new(2);
        let storage = context.create_storage(PAGE_SIZE * 2).unwrap();
        let first_pages = [storage.physical_page(0), storage.physical_page(1)];
        let capacity_before_drop = context.free_capacity();
        drop(storage);
        assert_eq!(context.free_capacity(), capacity_before_drop);
        assert_eq!(context.arena().stats().free_frames, 2);

        let reused = context.create_storage(PAGE_SIZE * 2).unwrap();
        assert_eq!(context.allocator().fresh_issued_count(), 2);
        assert!(first_pages.contains(&reused.physical_page(0)));
        assert!(first_pages.contains(&reused.physical_page(1)));
        drop(reused);

        assert_eq!(context.reclaim_idle().unwrap(), 2);
        assert_eq!(context.reclaim_idle().unwrap(), 0);
        assert_eq!(context.allocator().allocated_count(), 0);
    }

    #[test]
    fn reclaim_idle_failure_preserves_frames_ownership_and_allocator_counts() {
        let arena = SharedFrameArena::new().unwrap();
        let frame = PhysFrame::from_start_address(PhysAddr::new(0x2000)).unwrap();
        {
            let mut state = arena.state.lock();
            state.free.try_reserve_exact(1).unwrap();
            state.free.push(frame);
            state.owned_frames = 1;
        }
        let mut allocator =
            unsafe { UsableFrameAllocator::from_test_region(0x1000, PAGE_SIZE as u64, 52) };
        let allocated_before = allocator.allocated_count();
        let free_before = allocator.free_count();

        assert_eq!(
            arena.reclaim_idle(&mut allocator),
            Err(FrameAllocatorError::NeverAllocatedFrame { address: 0x2000 })
        );
        assert_eq!(allocator.allocated_count(), allocated_before);
        assert_eq!(allocator.free_count(), free_before);
        assert_eq!(
            arena.stats(),
            SharedFrameArenaStats {
                owned_frames: 1,
                free_frames: 1,
                reclaim_failures: 1,
                last_reclaim_error: Some(FrameAllocatorError::NeverAllocatedFrame {
                    address: 0x2000,
                }),
                ..SharedFrameArenaStats::default()
            }
        );
    }

    #[test]
    fn concurrent_returns_stay_within_preflighted_capacity() {
        const FRAME_COUNT: usize = 16;
        let arena = SharedFrameArena::new().unwrap();
        {
            let mut state = arena.state.lock();
            state.free.try_reserve_exact(FRAME_COUNT).unwrap();
            state.owned_frames = FRAME_COUNT;
        }

        thread::scope(|scope| {
            for index in 0..FRAME_COUNT {
                let arena = arena.clone();
                scope.spawn(move || {
                    let address = (index as u64 + 1) * PAGE_SIZE as u64;
                    let mut frames =
                        vec![PhysFrame::from_start_address(PhysAddr::new(address)).unwrap()];
                    arena.return_frames(&mut frames, true);
                    assert!(frames.is_empty());
                });
            }
        });

        let state = arena.state.lock();
        assert_eq!(state.free.len(), FRAME_COUNT);
        assert_eq!(state.owned_frames, FRAME_COUNT);
        assert_eq!(state.returned_frames, FRAME_COUNT);
        assert!(state.free.len() <= state.free.capacity());
    }
}
