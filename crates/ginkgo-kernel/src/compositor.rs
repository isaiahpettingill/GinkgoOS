//! Host-testable software composition over protected window buffers.

use alloc::vec::Vec;

use ginkgo_graphics::{
    FramebufferConfig, FramebufferWriter, PixelFormat, SurfaceError, SurfaceLayout, SurfacePixel,
};
use ginkgo_ipc::{Handle, HandleTable, IpcError, WindowPresentation};

/// Stable identity assigned to a compositor window.
pub type WindowId = u64;

const DESKTOP_BACKGROUND: SurfacePixel = SurfacePixel::xrgb(14, 20, 32);
const FOCUSED_TITLE_COLOR: SurfacePixel = SurfacePixel::xrgb(46, 106, 176);
const FOCUSED_BORDER_COLOR: SurfacePixel = SurfacePixel::xrgb(24, 58, 96);
const UNFOCUSED_TITLE_COLOR: SurfacePixel = SurfacePixel::xrgb(96, 101, 112);
const UNFOCUSED_BORDER_COLOR: SurfacePixel = SurfacePixel::xrgb(58, 61, 68);
/// Maximum number of output damage rectangles retained before full-output fallback.
pub const DAMAGE_RECT_CAPACITY: usize = 8;
const LETTERBOX_COLOR: SurfacePixel = SurfacePixel::xrgb(0, 0, 0);

/// A signed screen or surface coordinate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Point {
    pub x: i64,
    pub y: i64,
}

impl Point {
    pub const fn new(x: i64, y: i64) -> Self {
        Self { x, y }
    }
}

/// A half-open rectangle. Empty rectangles are valid and hide or disable an area.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rect {
    pub x: i64,
    pub y: i64,
    pub width: usize,
    pub height: usize,
}

impl Rect {
    pub const fn new(x: i64, y: i64, width: usize, height: usize) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    fn contains(self, x: i128, y: i128) -> bool {
        let left = i128::from(self.x);
        let top = i128::from(self.y);
        x >= left && y >= top && x < left + self.width as i128 && y < top + self.height as i128
    }
}

/// Fixed-capacity source-local damage passed to a batched frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceDamage {
    rects: [Rect; DAMAGE_RECT_CAPACITY],
    len: usize,
}

impl SurfaceDamage {
    pub const FULL: Self = Self {
        rects: [Rect::new(0, 0, 0, 0); DAMAGE_RECT_CAPACITY],
        len: 0,
    };

    pub fn from_slice(rects: &[Rect]) -> Self {
        if rects.is_empty() || rects.len() > DAMAGE_RECT_CAPACITY {
            return Self::FULL;
        }
        let mut damage = Self::FULL;
        for (index, rect) in rects.iter().copied().enumerate() {
            damage.rects[index] = rect;
        }
        damage.len = rects.len();
        damage
    }

    pub fn as_slice(&self) -> &[Rect] {
        &self.rects[..self.len]
    }
}

/// Complete output placement for one window.
///
/// All rectangles use output coordinates. Applications provide only the pixels
/// for `client`; the compositor owns any space between `outer` and `client`.
/// `visible: None` hides both the client and its server-side frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowPlacement {
    pub outer: Rect,
    pub client: Rect,
    pub visible: Option<Rect>,
    pub focused: bool,
    pub decorated: bool,
}

impl WindowPlacement {
    pub const fn new(
        outer: Rect,
        client: Rect,
        visible: Option<Rect>,
        focused: bool,
        decorated: bool,
    ) -> Self {
        Self {
            outer,
            client,
            visible,
            focused,
            decorated,
        }
    }

    /// Creates a placement whose client occupies the complete outer area.
    pub const fn undecorated(client: Rect, visible: Option<Rect>, focused: bool) -> Self {
        Self::new(client, client, visible, focused, false)
    }

    /// Creates a visible fullscreen placement without a server-side frame.
    pub const fn fullscreen(area: Rect, focused: bool) -> Self {
        Self::undecorated(area, Some(area), focused)
    }
}

/// Registration data for one window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowConfig {
    pub id: WindowId,
    pub manager: Handle,
    /// Layout of the application-provided client-pixel buffer.
    pub source_layout: SurfaceLayout,
    /// Logical dimensions represented by the source buffer. When these match
    /// the client area, fractional-scale rounding must not add letterboxing.
    pub source_logical_width: usize,
    pub source_logical_height: usize,
    pub placement: WindowPlacement,
}

impl WindowConfig {
    pub const fn new(
        id: WindowId,
        manager: Handle,
        source_layout: SurfaceLayout,
        placement: WindowPlacement,
    ) -> Self {
        Self {
            id,
            manager,
            source_layout,
            source_logical_width: source_layout.width,
            source_logical_height: source_layout.height,
            placement,
        }
    }

    pub const fn with_source_logical_size(mut self, width: usize, height: usize) -> Self {
        self.source_logical_width = width;
        self.source_logical_height = height;
        self
    }

    pub const fn pixel_format(self) -> PixelFormat {
        self.source_layout.format
    }
}

/// A compositor configuration, allocation, IPC, or destination-access failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositorError {
    DuplicateWindow(WindowId),
    UnknownWindow(WindowId),
    InvalidZOrder {
        requested: usize,
        window_count: usize,
    },
    Surface(SurfaceError),
    ConfiguredBufferTooSmall {
        window_id: WindowId,
        required: usize,
        actual: usize,
    },
    ArithmeticOverflow,
    OutOfMemory,
    DestinationWrite {
        x: usize,
        y: usize,
    },
    Ipc(IpcError),
}

impl From<SurfaceError> for CompositorError {
    fn from(error: SurfaceError) -> Self {
        Self::Surface(error)
    }
}

impl From<IpcError> for CompositorError {
    fn from(error: IpcError) -> Self {
        Self::Ipc(error)
    }
}

/// Compositor hot-path counters. Durations and frame pacing are tracked by the broker.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompositorMetrics {
    pub composed_frames: u64,
    pub damaged_pixels: u64,
    pub published_pixels: u64,
    pub occluded_presentations: u64,
    pub fullscreen_fast_paths: u64,
    pub direct_copy_rows: u64,
    pub scaled_frames: u64,
    pub storage_allocations: u64,
}

#[derive(Clone, Copy)]
struct SelectedBuffer {
    presentation: WindowPresentation,
    pending: bool,
    had_displayed: bool,
}

struct DamageRegion {
    rects: [Rect; DAMAGE_RECT_CAPACITY],
    len: usize,
    full: bool,
}

impl DamageRegion {
    const fn new() -> Self {
        Self {
            rects: [Rect::new(0, 0, 0, 0); DAMAGE_RECT_CAPACITY],
            len: 0,
            full: false,
        }
    }

    fn mark_full(&mut self) {
        self.len = 0;
        self.full = true;
    }

    fn clear(&mut self) {
        self.len = 0;
        self.full = false;
    }

    fn add(&mut self, rect: Rect, output_width: usize, output_height: usize) {
        if self.full {
            return;
        }
        let Some(mut rect) = clip_rect_to_output(rect, output_width, output_height) else {
            return;
        };

        let mut index = 0;
        while index < self.len {
            if damage_rects_merge(self.rects[index], rect) {
                rect = union_rects(self.rects[index], rect);
                self.remove(index);
                index = 0;
            } else {
                index += 1;
            }
        }

        if self.len == DAMAGE_RECT_CAPACITY {
            self.mark_full();
            return;
        }
        self.rects[self.len] = rect;
        self.len += 1;
    }

    fn count(&self) -> usize {
        if self.full {
            1
        } else {
            self.len
        }
    }

    fn rect(&self, index: usize, output_width: usize, output_height: usize) -> Option<Rect> {
        if self.full {
            return (index == 0).then_some(Rect::new(0, 0, output_width, output_height));
        }
        self.rects.get(index).copied().filter(|_| index < self.len)
    }

    fn remove(&mut self, index: usize) {
        for next in index + 1..self.len {
            self.rects[next - 1] = self.rects[next];
        }
        self.len -= 1;
    }
}

struct RenderState {
    output: Option<FramebufferConfig>,
    output_width: usize,
    output_height: usize,
    scene: Vec<SurfacePixel>,
    source_row: Vec<u8>,
    selected_buffers: Vec<Option<SelectedBuffer>>,
    damage: DamageRegion,
    metrics: CompositorMetrics,
}

impl RenderState {
    const fn new() -> Self {
        Self {
            output: None,
            output_width: 0,
            output_height: 0,
            scene: Vec::new(),
            source_row: Vec::new(),
            selected_buffers: Vec::new(),
            damage: DamageRegion::new(),
            metrics: CompositorMetrics {
                composed_frames: 0,
                damaged_pixels: 0,
                published_pixels: 0,
                occluded_presentations: 0,
                fullscreen_fast_paths: 0,
                direct_copy_rows: 0,
                scaled_frames: 0,
                storage_allocations: 0,
            },
        }
    }
}

trait WindowManagerApi {
    fn pending(&self, manager: Handle) -> Result<WindowPresentation, IpcError>;
    fn displayed(&self, manager: Handle) -> Result<Option<WindowPresentation>, IpcError>;
    fn buffer_len(&self, manager: Handle) -> Result<usize, IpcError>;
    fn copy_pending(
        &self,
        manager: Handle,
        presentation: WindowPresentation,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), IpcError>;
    fn copy_displayed(
        &self,
        manager: Handle,
        presentation: WindowPresentation,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), IpcError>;
    fn complete(
        &self,
        manager: Handle,
        presentation: WindowPresentation,
        successful: bool,
    ) -> Result<(), IpcError>;
}

impl WindowManagerApi for HandleTable {
    fn pending(&self, manager: Handle) -> Result<WindowPresentation, IpcError> {
        self.window_manager_pending(manager)
    }

    fn displayed(&self, manager: Handle) -> Result<Option<WindowPresentation>, IpcError> {
        self.window_manager_displayed(manager)
    }

    fn buffer_len(&self, manager: Handle) -> Result<usize, IpcError> {
        self.window_buffer_len(manager)
    }

    fn copy_pending(
        &self,
        manager: Handle,
        presentation: WindowPresentation,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), IpcError> {
        self.window_manager_copy_pending(manager, presentation, offset, output)
    }

    fn copy_displayed(
        &self,
        manager: Handle,
        presentation: WindowPresentation,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), IpcError> {
        self.window_manager_copy_displayed(manager, presentation, offset, output)
    }

    fn complete(
        &self,
        manager: Handle,
        presentation: WindowPresentation,
        successful: bool,
    ) -> Result<(), IpcError> {
        self.window_manager_complete(manager, presentation, successful)
    }
}

/// An ordered, bottom-to-top collection of composited windows.
///
/// Composition uses only public [`HandleTable`] manager operations. A pending
/// frame is copied without taking ownership, and is completed successfully only
/// after every damaged framebuffer pixel has been written.
pub struct Compositor {
    windows: Vec<WindowConfig>,
    render_state: RenderState,
}

impl Compositor {
    pub const fn new() -> Self {
        Self {
            windows: Vec::new(),
            render_state: RenderState::new(),
        }
    }

    /// Returns windows in bottom-to-top z-order.
    pub fn windows(&self) -> &[WindowConfig] {
        &self.windows
    }

    pub fn window(&self, id: WindowId) -> Option<&WindowConfig> {
        self.windows.iter().find(|window| window.id == id)
    }

    pub const fn metrics(&self) -> CompositorMetrics {
        self.render_state.metrics
    }

    /// Forces the next redraw to publish the complete output.
    pub fn invalidate_output(&mut self) {
        self.render_state.damage.mark_full();
    }

    /// Registers a new topmost window.
    pub fn register_window(&mut self, window: WindowConfig) -> Result<(), CompositorError> {
        if self.window(window.id).is_some() {
            return Err(CompositorError::DuplicateWindow(window.id));
        }
        window.source_layout.required_bytes()?;
        self.windows
            .try_reserve(1)
            .map_err(|_| CompositorError::OutOfMemory)?;
        if self.render_state.selected_buffers.capacity() < self.windows.len() + 1 {
            self.render_state
                .selected_buffers
                .try_reserve(1)
                .map_err(|_| CompositorError::OutOfMemory)?;
            self.render_state.metrics.storage_allocations = self
                .render_state
                .metrics
                .storage_allocations
                .saturating_add(1);
        }
        self.ensure_source_row(window.source_layout.width)?;
        self.windows.push(window);
        self.render_state.selected_buffers.push(None);
        self.queue_window_damage(window.placement.visible);
        Ok(())
    }

    /// Replaces registration data without changing the window's z-order.
    pub fn update_window(&mut self, window: WindowConfig) -> Result<(), CompositorError> {
        window.source_layout.required_bytes()?;
        let index = self
            .window_index(window.id)
            .ok_or(CompositorError::UnknownWindow(window.id))?;
        if self.windows[index] != window {
            let old = self.windows[index];
            self.ensure_source_row(window.source_layout.width)?;
            self.windows[index] = window;
            self.queue_window_damage(old.placement.visible);
            self.queue_window_damage(window.placement.visible);
        }
        Ok(())
    }

    /// Replaces output placement and appearance without changing buffer config
    /// or z-order. This accepts the same shape as a desktop runtime placement.
    pub fn update_placement(
        &mut self,
        id: WindowId,
        placement: WindowPlacement,
    ) -> Result<(), CompositorError> {
        let index = self
            .window_index(id)
            .ok_or(CompositorError::UnknownWindow(id))?;
        if self.windows[index].placement != placement {
            let old = self.windows[index].placement;
            self.windows[index].placement = placement;
            self.queue_window_damage(old.visible);
            self.queue_window_damage(placement.visible);
        }
        Ok(())
    }

    /// Updates only focus appearance for placement brokers handling a focus delta.
    pub fn set_focused(&mut self, id: WindowId, focused: bool) -> Result<(), CompositorError> {
        let index = self
            .window_index(id)
            .ok_or(CompositorError::UnknownWindow(id))?;
        if self.windows[index].placement.focused != focused {
            self.windows[index].placement.focused = focused;
            if self.windows[index].placement.decorated {
                self.queue_decoration_damage(self.windows[index].placement);
            }
        }
        Ok(())
    }

    /// Moves a window to a bottom-based z-index.
    pub fn set_z_order(&mut self, id: WindowId, z_index: usize) -> Result<(), CompositorError> {
        let index = self
            .window_index(id)
            .ok_or(CompositorError::UnknownWindow(id))?;
        if z_index >= self.windows.len() {
            return Err(CompositorError::InvalidZOrder {
                requested: z_index,
                window_count: self.windows.len(),
            });
        }
        if index != z_index {
            let first = index.min(z_index);
            let last = index.max(z_index);
            let mut affected = [None; DAMAGE_RECT_CAPACITY];
            let mut affected_len = 0;
            for window in &self.windows[first..=last] {
                if affected_len == DAMAGE_RECT_CAPACITY {
                    self.render_state.damage.mark_full();
                    break;
                }
                affected[affected_len] = window.placement.visible;
                affected_len += 1;
            }
            let window = self.windows.remove(index);
            self.windows.insert(z_index, window);
            for visible in affected[..affected_len].iter().copied().flatten() {
                self.queue_window_damage(Some(visible));
            }
        }
        Ok(())
    }

    pub fn remove_window(&mut self, id: WindowId) -> Option<WindowConfig> {
        let index = self.window_index(id)?;
        let window = self.windows.remove(index);
        self.render_state.selected_buffers.remove(index);
        self.queue_window_damage(window.placement.visible);
        Some(window)
    }

    /// Returns the topmost visible window whose client pixels contain `point`.
    /// Server-side decoration is deliberately excluded.
    pub fn hit_test_client(&self, point: Point) -> Option<WindowId> {
        let screen_x = i128::from(point.x);
        let screen_y = i128::from(point.y);
        self.windows.iter().rev().find_map(|window| {
            let placement = window.placement;
            let visible = placement.visible?;
            (visible.contains(screen_x, screen_y) && placement.client.contains(screen_x, screen_y))
                .then_some(window.id)
        })
    }

    /// Composes one pending window. An empty damage slice means the complete
    /// source surface, preserving the behavior of clients that predate damage.
    pub fn compose_pending(
        &mut self,
        handles: &HandleTable,
        framebuffer: &mut FramebufferWriter<'_>,
        id: WindowId,
    ) -> Result<WindowPresentation, CompositorError> {
        self.compose_pending_damage(handles, framebuffer, id, &[])
    }

    /// Composes bounded source-local damage for one pending presentation.
    pub fn compose_pending_damage(
        &mut self,
        handles: &HandleTable,
        framebuffer: &mut FramebufferWriter<'_>,
        id: WindowId,
        damage: &[Rect],
    ) -> Result<WindowPresentation, CompositorError> {
        self.compose_pending_with(handles, framebuffer, id, damage)
    }

    /// Selects every pending window, publishes one combined frame, then completes
    /// each selected presentation. The callback returns source-local damage for
    /// the exact presentation serial selected by the compositor.
    pub fn compose_pending_batch<F>(
        &mut self,
        handles: &HandleTable,
        framebuffer: &mut FramebufferWriter<'_>,
        mut damage_for: F,
    ) -> Result<usize, CompositorError>
    where
        F: FnMut(WindowId, WindowPresentation) -> SurfaceDamage,
    {
        Self::prepare_output(&mut self.render_state, framebuffer.configuration())?;
        let pending_count = Self::select_pending_batch(
            &self.windows,
            handles,
            &mut self.render_state,
            &mut damage_for,
        )?;
        if pending_count == 0 {
            return Ok(0);
        }
        Self::render(&self.windows, handles, framebuffer, &mut self.render_state)?;
        for (window, selection) in self
            .windows
            .iter()
            .zip(self.render_state.selected_buffers.iter().copied())
        {
            if let Some(selection) = selection.filter(|selection| selection.pending) {
                handles.complete(window.manager, selection.presentation, true)?;
            }
        }
        self.render_state.damage.clear();
        self.render_state.metrics.composed_frames = self
            .render_state
            .metrics
            .composed_frames
            .saturating_add(pending_count as u64);
        Ok(pending_count)
    }

    fn compose_pending_with<H: WindowManagerApi + ?Sized>(
        &mut self,
        handles: &H,
        framebuffer: &mut FramebufferWriter<'_>,
        id: WindowId,
        damage: &[Rect],
    ) -> Result<WindowPresentation, CompositorError> {
        let target = self
            .window_index(id)
            .ok_or(CompositorError::UnknownWindow(id))?;
        let pending = handles.pending(self.windows[target].manager)?;
        Self::prepare_output(&mut self.render_state, framebuffer.configuration())?;
        Self::select_buffers(
            &self.windows,
            handles,
            Some((target, pending)),
            &mut self.render_state,
        )?;

        let mut queued_visible_damage = false;
        let first_presentation = self.render_state.selected_buffers[target]
            .is_some_and(|selection| !selection.had_displayed);
        if first_presentation || damage.is_empty() {
            let full = Rect::new(
                0,
                0,
                self.windows[target].source_layout.width,
                self.windows[target].source_layout.height,
            );
            queued_visible_damage =
                Self::queue_source_damage(&self.windows, target, full, &mut self.render_state)?;
        } else {
            for rect in damage {
                queued_visible_damage |= Self::queue_source_damage(
                    &self.windows,
                    target,
                    *rect,
                    &mut self.render_state,
                )?;
            }
        }
        if !queued_visible_damage && self.windows[target].placement.visible.is_some() {
            self.render_state.metrics.occluded_presentations = self
                .render_state
                .metrics
                .occluded_presentations
                .saturating_add(1);
        }

        Self::render(&self.windows, handles, framebuffer, &mut self.render_state)?;
        handles.complete(self.windows[target].manager, pending, true)?;
        self.render_state.damage.clear();
        self.render_state.metrics.composed_frames =
            self.render_state.metrics.composed_frames.saturating_add(1);
        Ok(pending)
    }

    /// Publishes queued scene damage using retained displayed buffers without
    /// changing buffer ownership. A changed output identity forces a full redraw.
    pub fn redraw(
        &mut self,
        handles: &HandleTable,
        framebuffer: &mut FramebufferWriter<'_>,
    ) -> Result<(), CompositorError> {
        Self::prepare_output(&mut self.render_state, framebuffer.configuration())?;
        Self::select_buffers(&self.windows, handles, None, &mut self.render_state)?;
        Self::render(&self.windows, handles, framebuffer, &mut self.render_state)?;
        self.render_state.damage.clear();
        Ok(())
    }

    fn window_index(&self, id: WindowId) -> Option<usize> {
        self.windows.iter().position(|window| window.id == id)
    }

    fn ensure_source_row(&mut self, width: usize) -> Result<(), CompositorError> {
        let bytes = width
            .checked_mul(PixelFormat::Xrgb8888.bytes_per_pixel())
            .ok_or(CompositorError::ArithmeticOverflow)?;
        if self.render_state.source_row.capacity() < bytes {
            self.render_state
                .source_row
                .try_reserve_exact(bytes - self.render_state.source_row.len())
                .map_err(|_| CompositorError::OutOfMemory)?;
            self.render_state.metrics.storage_allocations = self
                .render_state
                .metrics
                .storage_allocations
                .saturating_add(1);
        }
        let retained_len = self.render_state.source_row.len().max(bytes);
        self.render_state.source_row.resize(retained_len, 0);
        Ok(())
    }

    fn queue_window_damage(&mut self, visible: Option<Rect>) {
        let Some(visible) = visible else {
            return;
        };
        self.queue_rect_damage(visible);
    }

    fn queue_rect_damage(&mut self, rect: Rect) {
        if self.render_state.output.is_none() {
            self.render_state.damage.mark_full();
            return;
        }
        let width = self.render_state.output_width;
        let height = self.render_state.output_height;
        self.render_state.damage.add(rect, width, height);
    }

    fn queue_decoration_damage(&mut self, placement: WindowPlacement) {
        let Some(visible) = placement.visible else {
            return;
        };
        let outer = placement.outer;
        let client = placement.client;
        let outer_right = i128::from(outer.x) + outer.width as i128;
        let outer_bottom = i128::from(outer.y) + outer.height as i128;
        let client_right = i128::from(client.x) + client.width as i128;
        let client_bottom = i128::from(client.y) + client.height as i128;
        let strips = [
            Rect::new(
                outer.x,
                outer.y,
                outer.width,
                usize::try_from(
                    i128::from(client.y)
                        .saturating_sub(i128::from(outer.y))
                        .max(0),
                )
                .unwrap_or(usize::MAX),
            ),
            Rect::new(
                outer.x,
                client.y,
                usize::try_from(
                    i128::from(client.x)
                        .saturating_sub(i128::from(outer.x))
                        .max(0),
                )
                .unwrap_or(usize::MAX),
                client.height,
            ),
            Rect::new(
                i64::try_from(client_right).unwrap_or(i64::MAX),
                client.y,
                usize::try_from(outer_right.saturating_sub(client_right).max(0))
                    .unwrap_or(usize::MAX),
                client.height,
            ),
            Rect::new(
                outer.x,
                i64::try_from(client_bottom).unwrap_or(i64::MAX),
                outer.width,
                usize::try_from(outer_bottom.saturating_sub(client_bottom).max(0))
                    .unwrap_or(usize::MAX),
            ),
        ];
        for strip in strips {
            if let Some(strip) = intersect_rect(strip, visible) {
                self.queue_rect_damage(strip);
            }
        }
    }

    fn prepare_output(
        state: &mut RenderState,
        output: FramebufferConfig,
    ) -> Result<(), CompositorError> {
        if state.output == Some(output) {
            return Ok(());
        }
        let width =
            usize::try_from(output.width).map_err(|_| CompositorError::ArithmeticOverflow)?;
        let height =
            usize::try_from(output.height).map_err(|_| CompositorError::ArithmeticOverflow)?;
        let scene_len = width
            .checked_mul(height)
            .ok_or(CompositorError::ArithmeticOverflow)?;
        if state.scene.capacity() < scene_len {
            state
                .scene
                .try_reserve_exact(scene_len - state.scene.len())
                .map_err(|_| CompositorError::OutOfMemory)?;
            state.metrics.storage_allocations = state.metrics.storage_allocations.saturating_add(1);
        }
        state.scene.resize(scene_len, DESKTOP_BACKGROUND);
        state.scene.fill(DESKTOP_BACKGROUND);
        state.output = Some(output);
        state.output_width = width;
        state.output_height = height;
        state.damage.mark_full();
        Ok(())
    }

    fn select_buffers<H: WindowManagerApi + ?Sized>(
        windows: &[WindowConfig],
        handles: &H,
        pending: Option<(usize, WindowPresentation)>,
        state: &mut RenderState,
    ) -> Result<(), CompositorError> {
        if state.selected_buffers.capacity() < windows.len() {
            state
                .selected_buffers
                .try_reserve_exact(windows.len() - state.selected_buffers.len())
                .map_err(|_| CompositorError::OutOfMemory)?;
            state.metrics.storage_allocations = state.metrics.storage_allocations.saturating_add(1);
        }
        state.selected_buffers.resize(windows.len(), None);
        state.selected_buffers.fill(None);

        for (index, window) in windows.iter().enumerate() {
            let displayed = handles.displayed(window.manager)?;
            let selection = if pending.is_some_and(|(pending_index, _)| index == pending_index) {
                Some(SelectedBuffer {
                    presentation: pending.expect("pending index disappeared").1,
                    pending: true,
                    had_displayed: displayed.is_some(),
                })
            } else {
                displayed.map(|presentation| SelectedBuffer {
                    presentation,
                    pending: false,
                    had_displayed: true,
                })
            };
            if selection.is_some() {
                let required = window.source_layout.required_bytes()?;
                let actual = handles.buffer_len(window.manager)?;
                if actual < required {
                    return Err(CompositorError::ConfiguredBufferTooSmall {
                        window_id: window.id,
                        required,
                        actual,
                    });
                }
            }
            state.selected_buffers[index] = selection;
        }
        Ok(())
    }

    fn select_pending_batch<F>(
        windows: &[WindowConfig],
        handles: &HandleTable,
        state: &mut RenderState,
        damage_for: &mut F,
    ) -> Result<usize, CompositorError>
    where
        F: FnMut(WindowId, WindowPresentation) -> SurfaceDamage,
    {
        if state.selected_buffers.capacity() < windows.len() {
            state
                .selected_buffers
                .try_reserve_exact(windows.len() - state.selected_buffers.len())
                .map_err(|_| CompositorError::OutOfMemory)?;
            state.metrics.storage_allocations = state.metrics.storage_allocations.saturating_add(1);
        }
        state.selected_buffers.resize(windows.len(), None);
        state.selected_buffers.fill(None);
        let mut pending_count = 0;
        for (index, window) in windows.iter().enumerate() {
            let displayed = handles.displayed(window.manager)?;
            let selection = match handles.pending(window.manager) {
                Ok(presentation) => {
                    pending_count += 1;
                    Some(SelectedBuffer {
                        presentation,
                        pending: true,
                        had_displayed: displayed.is_some(),
                    })
                }
                Err(IpcError::ShouldWait | IpcError::PeerClosed) => {
                    displayed.map(|presentation| SelectedBuffer {
                        presentation,
                        pending: false,
                        had_displayed: true,
                    })
                }
                Err(error) => return Err(error.into()),
            };
            if selection.is_some() {
                let required = window.source_layout.required_bytes()?;
                let actual = handles.buffer_len(window.manager)?;
                if actual < required {
                    return Err(CompositorError::ConfiguredBufferTooSmall {
                        window_id: window.id,
                        required,
                        actual,
                    });
                }
            }
            state.selected_buffers[index] = selection;
        }

        for index in 0..windows.len() {
            let Some(selection) =
                state.selected_buffers[index].filter(|selection| selection.pending)
            else {
                continue;
            };
            let damage = damage_for(windows[index].id, selection.presentation);
            let mut queued = false;
            if !selection.had_displayed || damage.as_slice().is_empty() {
                queued = Self::queue_source_damage(
                    windows,
                    index,
                    Rect::new(
                        0,
                        0,
                        windows[index].source_layout.width,
                        windows[index].source_layout.height,
                    ),
                    state,
                )?;
            } else {
                for rect in damage.as_slice() {
                    queued |= Self::queue_source_damage(windows, index, *rect, state)?;
                }
            }
            if !queued && windows[index].placement.visible.is_some() {
                state.metrics.occluded_presentations =
                    state.metrics.occluded_presentations.saturating_add(1);
            }
        }
        Ok(pending_count)
    }

    fn queue_source_damage(
        windows: &[WindowConfig],
        target: usize,
        source: Rect,
        state: &mut RenderState,
    ) -> Result<bool, CompositorError> {
        let window = windows[target];
        let Some(visible) = window.placement.visible else {
            return Ok(false);
        };
        let mapping = client_mapping(window)?;
        let Some(output) = map_source_rect(source, mapping) else {
            return Ok(false);
        };
        let Some(output) = intersect_rect(output, visible) else {
            return Ok(false);
        };
        let Some(output) = clip_rect_to_output(output, state.output_width, state.output_height)
        else {
            return Ok(false);
        };
        if rect_fully_occluded(windows, &state.selected_buffers, target, output)? {
            return Ok(false);
        }
        state
            .damage
            .add(output, state.output_width, state.output_height);
        Ok(true)
    }

    fn render<H: WindowManagerApi + ?Sized>(
        windows: &[WindowConfig],
        handles: &H,
        framebuffer: &mut FramebufferWriter<'_>,
        state: &mut RenderState,
    ) -> Result<(), CompositorError> {
        let width = state.output_width;
        let height = state.output_height;
        if state.damage.count() == 0 {
            return Ok(());
        }

        let fast_path = fullscreen_fast_path(windows, &state.selected_buffers, width, height)?;
        if let Some(index) = fast_path {
            Self::render_fullscreen_rows(
                windows[index],
                state.selected_buffers[index].unwrap(),
                handles,
                state,
            )?;
            state.metrics.fullscreen_fast_paths =
                state.metrics.fullscreen_fast_paths.saturating_add(1);
        } else if Self::render_general(windows, handles, state)? {
            state.metrics.scaled_frames = state.metrics.scaled_frames.saturating_add(1);
        }

        for damage_index in 0..state.damage.count() {
            let damage = state
                .damage
                .rect(damage_index, width, height)
                .ok_or(CompositorError::ArithmeticOverflow)?;
            let x = usize::try_from(damage.x).map_err(|_| CompositorError::ArithmeticOverflow)?;
            let y = usize::try_from(damage.y).map_err(|_| CompositorError::ArithmeticOverflow)?;
            if !framebuffer.write_xrgb8888_scene_region(
                &state.scene,
                width,
                x,
                y,
                damage.width,
                damage.height,
            ) {
                return Err(CompositorError::DestinationWrite { x, y });
            }
            let pixels = damage.width.saturating_mul(damage.height) as u64;
            state.metrics.damaged_pixels = state.metrics.damaged_pixels.saturating_add(pixels);
            state.metrics.published_pixels = state.metrics.published_pixels.saturating_add(pixels);
        }
        Ok(())
    }

    fn render_fullscreen_rows<H: WindowManagerApi + ?Sized>(
        window: WindowConfig,
        selection: SelectedBuffer,
        handles: &H,
        state: &mut RenderState,
    ) -> Result<(), CompositorError> {
        let width = state.output_width;
        for damage_index in 0..state.damage.count() {
            let damage = state
                .damage
                .rect(damage_index, width, state.output_height)
                .ok_or(CompositorError::ArithmeticOverflow)?;
            let left = damage.x as usize;
            let right = left + damage.width;
            for y in damage.y as usize..damage.y as usize + damage.height {
                let copy_bytes = damage
                    .width
                    .checked_mul(4)
                    .ok_or(CompositorError::ArithmeticOverflow)?;
                let offset = y
                    .checked_mul(window.source_layout.stride)
                    .and_then(|row| {
                        left.checked_mul(4)
                            .and_then(|column| row.checked_add(column))
                    })
                    .ok_or(CompositorError::ArithmeticOverflow)?;
                let source = state
                    .source_row
                    .get_mut(..copy_bytes)
                    .ok_or(CompositorError::ArithmeticOverflow)?;
                copy_selected(handles, window.manager, selection, offset, source)?;
                let row_start = y
                    .checked_mul(width)
                    .ok_or(CompositorError::ArithmeticOverflow)?;
                let destination = &mut state.scene[row_start + left..row_start + right];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        source.as_ptr(),
                        destination.as_mut_ptr().cast::<u8>(),
                        copy_bytes,
                    );
                }
                state.metrics.direct_copy_rows = state.metrics.direct_copy_rows.saturating_add(1);
            }
        }
        Ok(())
    }

    fn render_general<H: WindowManagerApi + ?Sized>(
        windows: &[WindowConfig],
        handles: &H,
        state: &mut RenderState,
    ) -> Result<bool, CompositorError> {
        let width = state.output_width;
        let height = state.output_height;
        let mut scaled = false;
        for damage_index in 0..state.damage.count() {
            let damage = state
                .damage
                .rect(damage_index, width, height)
                .ok_or(CompositorError::ArithmeticOverflow)?;
            let damage_left = damage.x as usize;
            let damage_right = damage_left + damage.width;
            for destination_y in damage.y as usize..damage.y as usize + damage.height {
                let row_start = destination_y
                    .checked_mul(width)
                    .ok_or(CompositorError::ArithmeticOverflow)?;
                let scene_row = state
                    .scene
                    .get_mut(row_start..row_start + width)
                    .ok_or(CompositorError::ArithmeticOverflow)?;
                scene_row[damage_left..damage_right].fill(DESKTOP_BACKGROUND);

                for (index, window) in windows.iter().copied().enumerate() {
                    let Some(selection) = state.selected_buffers[index] else {
                        continue;
                    };
                    let Some(visible) = window.placement.visible else {
                        continue;
                    };
                    draw_frame_row(
                        scene_row,
                        destination_y,
                        window.placement,
                        visible,
                        damage_left,
                        damage_right,
                    );
                    let mapping = client_mapping(window)?;
                    draw_letterbox_row(
                        scene_row,
                        destination_y,
                        window.placement.client,
                        visible,
                        mapping.destination,
                        damage_left,
                        damage_right,
                    );
                    let Some((left, right)) = mapped_row_span(
                        mapping.destination,
                        visible,
                        destination_y,
                        damage_left,
                        damage_right,
                    ) else {
                        continue;
                    };
                    let mut any_visible = false;
                    let mut fully_visible = true;
                    for x in left..right {
                        if pixel_occluded(
                            windows,
                            &state.selected_buffers,
                            index,
                            x,
                            destination_y,
                        )? {
                            fully_visible = false;
                        } else {
                            any_visible = true;
                        }
                    }
                    if !any_visible {
                        continue;
                    }

                    let source_y = map_destination_axis(
                        destination_y,
                        mapping.destination.y,
                        mapping.destination.height,
                        mapping.source_height,
                    )?;
                    let source_left = map_destination_axis(
                        left,
                        mapping.destination.x,
                        mapping.destination.width,
                        mapping.source_width,
                    )?;
                    let source_right = map_destination_axis(
                        right - 1,
                        mapping.destination.x,
                        mapping.destination.width,
                        mapping.source_width,
                    )?
                    .saturating_add(1);
                    let source_width = source_right - source_left;
                    let copy_bytes = source_width
                        .checked_mul(4)
                        .ok_or(CompositorError::ArithmeticOverflow)?;
                    let offset = source_y
                        .checked_mul(window.source_layout.stride)
                        .and_then(|row| {
                            source_left
                                .checked_mul(4)
                                .and_then(|column| row.checked_add(column))
                        })
                        .ok_or(CompositorError::ArithmeticOverflow)?;
                    let source = state
                        .source_row
                        .get_mut(..copy_bytes)
                        .ok_or(CompositorError::ArithmeticOverflow)?;
                    copy_selected(handles, window.manager, selection, offset, source)?;

                    let direct = mapping.destination.width == mapping.source_width
                        && mapping.destination.height == mapping.source_height
                        && window.source_layout.format == PixelFormat::Xrgb8888;
                    if direct && fully_visible {
                        let destination = &mut scene_row[left..right];
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                source.as_ptr(),
                                destination.as_mut_ptr().cast::<u8>(),
                                copy_bytes,
                            );
                        }
                        state.metrics.direct_copy_rows =
                            state.metrics.direct_copy_rows.saturating_add(1);
                        continue;
                    }
                    if !direct {
                        scaled = true;
                    }
                    for x in left..right {
                        if pixel_occluded(
                            windows,
                            &state.selected_buffers,
                            index,
                            x,
                            destination_y,
                        )? {
                            continue;
                        }
                        let source_x = map_destination_axis(
                            x,
                            mapping.destination.x,
                            mapping.destination.width,
                            mapping.source_width,
                        )?;
                        let byte = (source_x - source_left) * 4;
                        let pixel = SurfacePixel::new(
                            source[byte + 2],
                            source[byte + 1],
                            source[byte],
                            source[byte + 3],
                        );
                        blend_source_over(&mut scene_row[x], pixel, window.source_layout.format);
                    }
                }
            }
        }
        Ok(scaled)
    }
}

impl Default for Compositor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
struct ClientMapping {
    destination: Rect,
    source_width: usize,
    source_height: usize,
}

fn client_mapping(window: WindowConfig) -> Result<ClientMapping, CompositorError> {
    let source_width = window.source_layout.width;
    let source_height = window.source_layout.height;
    let client = window.placement.client;
    if source_width == 0 || source_height == 0 || client.width == 0 || client.height == 0 {
        return Err(CompositorError::ArithmeticOverflow);
    }

    let scale = (client.width / source_width).min(client.height / source_height);
    let (width, height) = if (source_width == client.width && source_height == client.height)
        || (window.source_logical_width == client.width
            && window.source_logical_height == client.height)
    {
        (client.width, client.height)
    } else if scale >= 1 {
        (
            source_width
                .checked_mul(scale)
                .ok_or(CompositorError::ArithmeticOverflow)?,
            source_height
                .checked_mul(scale)
                .ok_or(CompositorError::ArithmeticOverflow)?,
        )
    } else if (client.width as u128).saturating_mul(source_height as u128)
        <= (client.height as u128).saturating_mul(source_width as u128)
    {
        (
            client.width,
            usize::try_from(
                (source_height as u128)
                    .saturating_mul(client.width as u128)
                    .checked_div(source_width as u128)
                    .unwrap_or(0)
                    .max(1),
            )
            .map_err(|_| CompositorError::ArithmeticOverflow)?,
        )
    } else {
        (
            usize::try_from(
                (source_width as u128)
                    .saturating_mul(client.height as u128)
                    .checked_div(source_height as u128)
                    .unwrap_or(0)
                    .max(1),
            )
            .map_err(|_| CompositorError::ArithmeticOverflow)?,
            client.height,
        )
    };
    let destination = Rect::new(
        client.x
            + i64::try_from((client.width - width) / 2)
                .map_err(|_| CompositorError::ArithmeticOverflow)?,
        client.y
            + i64::try_from((client.height - height) / 2)
                .map_err(|_| CompositorError::ArithmeticOverflow)?,
        width,
        height,
    );
    Ok(ClientMapping {
        destination,
        source_width,
        source_height,
    })
}

fn map_source_rect(source: Rect, mapping: ClientMapping) -> Option<Rect> {
    let source_left = i128::from(source.x)
        .max(0)
        .min(mapping.source_width as i128);
    let source_top = i128::from(source.y)
        .max(0)
        .min(mapping.source_height as i128);
    let source_right = (i128::from(source.x) + source.width as i128)
        .max(0)
        .min(mapping.source_width as i128);
    let source_bottom = (i128::from(source.y) + source.height as i128)
        .max(0)
        .min(mapping.source_height as i128);
    if source_left >= source_right || source_top >= source_bottom {
        return None;
    }
    let left = i128::from(mapping.destination.x)
        + source_left * mapping.destination.width as i128 / mapping.source_width as i128;
    let top = i128::from(mapping.destination.y)
        + source_top * mapping.destination.height as i128 / mapping.source_height as i128;
    let right = i128::from(mapping.destination.x)
        + (source_right * mapping.destination.width as i128 + mapping.source_width as i128 - 1)
            / mapping.source_width as i128;
    let bottom = i128::from(mapping.destination.y)
        + (source_bottom * mapping.destination.height as i128 + mapping.source_height as i128 - 1)
            / mapping.source_height as i128;
    Some(Rect::new(
        i64::try_from(left).ok()?,
        i64::try_from(top).ok()?,
        usize::try_from(right - left).ok()?,
        usize::try_from(bottom - top).ok()?,
    ))
}

fn intersect_rect(first: Rect, second: Rect) -> Option<Rect> {
    let left = i128::from(first.x).max(i128::from(second.x));
    let top = i128::from(first.y).max(i128::from(second.y));
    let right = (i128::from(first.x) + first.width as i128)
        .min(i128::from(second.x) + second.width as i128);
    let bottom = (i128::from(first.y) + first.height as i128)
        .min(i128::from(second.y) + second.height as i128);
    if left >= right || top >= bottom {
        return None;
    }
    Some(Rect::new(
        i64::try_from(left).ok()?,
        i64::try_from(top).ok()?,
        usize::try_from(right - left).ok()?,
        usize::try_from(bottom - top).ok()?,
    ))
}

fn rect_contains(outer: Rect, inner: Rect) -> bool {
    let outer_left = i128::from(outer.x);
    let outer_top = i128::from(outer.y);
    let inner_left = i128::from(inner.x);
    let inner_top = i128::from(inner.y);
    inner_left >= outer_left
        && inner_top >= outer_top
        && inner_left + inner.width as i128 <= outer_left + outer.width as i128
        && inner_top + inner.height as i128 <= outer_top + outer.height as i128
}

fn rect_fully_occluded(
    windows: &[WindowConfig],
    selected: &[Option<SelectedBuffer>],
    target: usize,
    rect: Rect,
) -> Result<bool, CompositorError> {
    for index in target + 1..windows.len() {
        if selected[index].is_none() {
            continue;
        }
        let window = &windows[index];
        let Some(visible) = window.placement.visible else {
            continue;
        };
        if window.source_layout.format == PixelFormat::Xrgb8888 {
            let opaque_area = if window.placement.decorated {
                window.placement.outer
            } else {
                window.placement.client
            };
            if intersect_rect(opaque_area, visible)
                .is_some_and(|opaque| rect_contains(opaque, rect))
            {
                return Ok(true);
            }
        }
    }

    let Some(clipped) = clip_rect_to_output(rect, usize::MAX, usize::MAX) else {
        return Ok(false);
    };
    for y in clipped.y as usize..clipped.y as usize + clipped.height {
        for x in clipped.x as usize..clipped.x as usize + clipped.width {
            if !pixel_occluded(windows, selected, target, x, y)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn pixel_occluded(
    windows: &[WindowConfig],
    selected: &[Option<SelectedBuffer>],
    target: usize,
    x: usize,
    y: usize,
) -> Result<bool, CompositorError> {
    let x = x as i128;
    let y = y as i128;
    for index in target + 1..windows.len() {
        if selected[index].is_none() {
            continue;
        }
        let window = &windows[index];
        let placement = window.placement;
        let Some(visible) = placement.visible else {
            continue;
        };
        if !visible.contains(x, y) {
            continue;
        }
        if placement.decorated && placement.outer.contains(x, y) && !placement.client.contains(x, y)
        {
            return Ok(true);
        }
        if !placement.client.contains(x, y) {
            continue;
        }
        let mapping = client_mapping(*window)?;
        if !mapping.destination.contains(x, y)
            || window.source_layout.format == PixelFormat::Xrgb8888
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn fullscreen_fast_path(
    windows: &[WindowConfig],
    selected: &[Option<SelectedBuffer>],
    output_width: usize,
    output_height: usize,
) -> Result<Option<usize>, CompositorError> {
    let Some(index) = selected.iter().rposition(Option::is_some) else {
        return Ok(None);
    };
    let window = windows[index];
    let output = Rect::new(0, 0, output_width, output_height);
    let mapping = client_mapping(window)?;
    Ok((window.source_layout.format == PixelFormat::Xrgb8888
        && window.placement.visible == Some(output)
        && window.placement.client == output
        && mapping.destination == output
        && mapping.source_width == output_width
        && mapping.source_height == output_height)
        .then_some(index))
}

fn copy_selected<H: WindowManagerApi + ?Sized>(
    handles: &H,
    manager: Handle,
    selection: SelectedBuffer,
    offset: usize,
    output: &mut [u8],
) -> Result<(), CompositorError> {
    if selection.pending {
        handles.copy_pending(manager, selection.presentation, offset, output)?;
    } else {
        handles.copy_displayed(manager, selection.presentation, offset, output)?;
    }
    Ok(())
}

fn mapped_row_span(
    destination: Rect,
    visible: Rect,
    y: usize,
    damage_left: usize,
    damage_right: usize,
) -> Option<(usize, usize)> {
    if !destination.contains(destination.x as i128, y as i128) {
        return None;
    }
    let left = i128::from(destination.x)
        .max(i128::from(visible.x))
        .max(damage_left as i128)
        .max(0);
    let right = (i128::from(destination.x) + destination.width as i128)
        .min(i128::from(visible.x) + visible.width as i128)
        .min(damage_right as i128);
    (left < right).then(|| (left as usize, right as usize))
}

fn map_destination_axis(
    destination: usize,
    destination_start: i64,
    destination_length: usize,
    source_length: usize,
) -> Result<usize, CompositorError> {
    let relative = destination as i128 - i128::from(destination_start);
    if relative < 0 || relative >= destination_length as i128 {
        return Err(CompositorError::ArithmeticOverflow);
    }
    usize::try_from(relative * source_length as i128 / destination_length as i128)
        .map_err(|_| CompositorError::ArithmeticOverflow)
}

fn draw_letterbox_row(
    destination: &mut [SurfacePixel],
    destination_y: usize,
    client: Rect,
    visible: Rect,
    content: Rect,
    damage_left: usize,
    damage_right: usize,
) {
    if client == content || !client.contains(client.x as i128, destination_y as i128) {
        return;
    }
    let left = i128::from(client.x)
        .max(i128::from(visible.x))
        .max(damage_left as i128)
        .max(0) as usize;
    let right = (i128::from(client.x) + client.width as i128)
        .min(i128::from(visible.x) + visible.width as i128)
        .min(damage_right as i128)
        .min(destination.len() as i128) as usize;
    for (x, pixel) in destination.iter_mut().enumerate().take(right).skip(left) {
        if !content.contains(x as i128, destination_y as i128) {
            *pixel = LETTERBOX_COLOR;
        }
    }
}

fn clip_rect_to_output(rect: Rect, output_width: usize, output_height: usize) -> Option<Rect> {
    let left = i128::from(rect.x).max(0).min(output_width as i128);
    let top = i128::from(rect.y).max(0).min(output_height as i128);
    let right = (i128::from(rect.x) + rect.width as i128)
        .max(0)
        .min(output_width as i128);
    let bottom = (i128::from(rect.y) + rect.height as i128)
        .max(0)
        .min(output_height as i128);
    if left >= right || top >= bottom {
        return None;
    }
    Some(Rect::new(
        left as i64,
        top as i64,
        (right - left) as usize,
        (bottom - top) as usize,
    ))
}

fn damage_rects_merge(first: Rect, second: Rect) -> bool {
    let first_left = i128::from(first.x);
    let first_top = i128::from(first.y);
    let first_right = first_left + first.width as i128;
    let first_bottom = first_top + first.height as i128;
    let second_left = i128::from(second.x);
    let second_top = i128::from(second.y);
    let second_right = second_left + second.width as i128;
    let second_bottom = second_top + second.height as i128;

    let horizontal_overlap = first_left < second_right && second_left < first_right;
    let vertical_overlap = first_top < second_bottom && second_top < first_bottom;
    let horizontal_touch = first_left <= second_right && second_left <= first_right;
    let vertical_touch = first_top <= second_bottom && second_top <= first_bottom;
    (horizontal_overlap && vertical_touch) || (vertical_overlap && horizontal_touch)
}

fn union_rects(first: Rect, second: Rect) -> Rect {
    let left = i128::from(first.x).min(i128::from(second.x));
    let top = i128::from(first.y).min(i128::from(second.y));
    let right = (i128::from(first.x) + first.width as i128)
        .max(i128::from(second.x) + second.width as i128);
    let bottom = (i128::from(first.y) + first.height as i128)
        .max(i128::from(second.y) + second.height as i128);
    Rect::new(
        left as i64,
        top as i64,
        (right - left) as usize,
        (bottom - top) as usize,
    )
}

fn draw_frame_row(
    destination: &mut [SurfacePixel],
    destination_y: usize,
    placement: WindowPlacement,
    visible: Rect,
    damage_left: usize,
    damage_right: usize,
) {
    if !placement.decorated {
        return;
    }

    let y = destination_y as i128;
    let outer_top = i128::from(placement.outer.y);
    let visible_top = i128::from(visible.y);
    if y < outer_top.max(visible_top)
        || y >= (outer_top + placement.outer.height as i128)
            .min(visible_top + visible.height as i128)
    {
        return;
    }

    let Some((left, right)) = clipped_output_axis(
        placement.outer.x,
        placement.outer.width,
        visible.x,
        visible.width,
        destination.len(),
    ) else {
        return;
    };
    let (title, border) = if placement.focused {
        (FOCUSED_TITLE_COLOR, FOCUSED_BORDER_COLOR)
    } else {
        (UNFOCUSED_TITLE_COLOR, UNFOCUSED_BORDER_COLOR)
    };
    let frame_color = if y < i128::from(placement.client.y) {
        title
    } else {
        border
    };

    let left = left.max(damage_left);
    let right = right.min(damage_right);
    for (x, pixel) in destination.iter_mut().enumerate().take(right).skip(left) {
        if !placement.client.contains(x as i128, y) {
            *pixel = frame_color;
        }
    }
}

/// Clips one output-space axis against a visible range and the framebuffer.
fn clipped_output_axis(
    area_start: i64,
    area_length: usize,
    visible_start: i64,
    visible_length: usize,
    destination_length: usize,
) -> Option<(usize, usize)> {
    let area_start = i128::from(area_start);
    let visible_start = i128::from(visible_start);
    let left = 0_i128.max(area_start).max(visible_start);
    let right = (area_start + area_length as i128)
        .min(visible_start + visible_length as i128)
        .min(destination_length as i128);
    if left >= right {
        return None;
    }
    Some((usize::try_from(left).ok()?, usize::try_from(right).ok()?))
}

fn blend_source_over(destination: &mut SurfacePixel, source: SurfacePixel, format: PixelFormat) {
    let alpha = match format {
        PixelFormat::Xrgb8888 => u8::MAX,
        PixelFormat::Argb8888 => source.alpha_or_unused,
    };
    if alpha == 0 {
        return;
    }
    if alpha == u8::MAX {
        destination.red = source.red;
        destination.green = source.green;
        destination.blue = source.blue;
        return;
    }

    let blend = |source: u8, destination: u8| {
        let alpha = u32::from(alpha);
        ((u32::from(source) * alpha + u32::from(destination) * (255 - alpha) + 127) / 255) as u8
    };
    destination.red = blend(source.red, destination.red);
    destination.green = blend(source.green, destination.green);
    destination.blue = blend(source.blue, destination.blue);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::vec;
    use core::cell::Cell;

    use super::*;
    use crate::shared_memory::test_support::TestSharedMemoryContext;
    use ginkgo_graphics::FramebufferConfig;

    fn layout(width: usize, height: usize, format: PixelFormat) -> SurfaceLayout {
        SurfaceLayout::new(width, height, width * 4, format)
    }

    fn full_window(id: WindowId, manager: Handle, source_layout: SurfaceLayout) -> WindowConfig {
        let area = Rect::new(0, 0, source_layout.width, source_layout.height);
        WindowConfig::new(
            id,
            manager,
            source_layout,
            WindowPlacement::undecorated(area, Some(area), false),
        )
    }

    fn raw_color(pixel: SurfacePixel) -> u32 {
        u32::from(pixel.red) << 16 | u32::from(pixel.green) << 8 | u32::from(pixel.blue)
    }

    fn create_window(
        shared_memory: &mut TestSharedMemoryContext,
        handles: &mut HandleTable,
        first: &[u8],
        second: &[u8],
    ) -> (Handle, Handle, Handle) {
        assert_eq!(first.len(), second.len());
        let memory = shared_memory
            .factory()
            .create_handle(handles, first.len() * 2)
            .unwrap();
        handles.shared_memory_write(memory, 0, first).unwrap();
        handles
            .shared_memory_write(memory, first.len(), second)
            .unwrap();
        let (client, manager) = handles.window_create(memory).unwrap();
        (memory, client, manager)
    }

    fn standard_framebuffer(
        bytes: &mut [u8],
        width: usize,
        height: usize,
    ) -> FramebufferWriter<'_> {
        framebuffer_with_shifts(bytes, width, height, 16, 8, 0)
    }

    fn framebuffer_with_shifts(
        bytes: &mut [u8],
        width: usize,
        height: usize,
        red_shift: u8,
        green_shift: u8,
        blue_shift: u8,
    ) -> FramebufferWriter<'_> {
        let config = FramebufferConfig {
            address: bytes.as_mut_ptr(),
            width: width as u64,
            height: height as u64,
            pitch: (width * 4) as u64,
            bits_per_pixel: 32,
            memory_model: 1,
            red_mask_size: 8,
            red_mask_shift: red_shift,
            green_mask_size: 8,
            green_mask_shift: green_shift,
            blue_mask_size: 8,
            blue_mask_shift: blue_shift,
        };
        unsafe { FramebufferWriter::from_raw(config) }.expect("valid host framebuffer")
    }

    fn pixels(values: &[u32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|pixel| pixel.to_le_bytes())
            .collect()
    }

    struct FailingCopy<'a> {
        handles: &'a HandleTable,
    }

    impl WindowManagerApi for FailingCopy<'_> {
        fn pending(&self, manager: Handle) -> Result<WindowPresentation, IpcError> {
            self.handles.window_manager_pending(manager)
        }

        fn displayed(&self, manager: Handle) -> Result<Option<WindowPresentation>, IpcError> {
            self.handles.window_manager_displayed(manager)
        }

        fn buffer_len(&self, manager: Handle) -> Result<usize, IpcError> {
            self.handles.window_buffer_len(manager)
        }

        fn copy_pending(
            &self,
            _manager: Handle,
            _presentation: WindowPresentation,
            _offset: usize,
            _output: &mut [u8],
        ) -> Result<(), IpcError> {
            Err(IpcError::InvalidMessage)
        }

        fn copy_displayed(
            &self,
            manager: Handle,
            presentation: WindowPresentation,
            offset: usize,
            output: &mut [u8],
        ) -> Result<(), IpcError> {
            self.handles
                .window_manager_copy_displayed(manager, presentation, offset, output)
        }

        fn complete(
            &self,
            manager: Handle,
            presentation: WindowPresentation,
            successful: bool,
        ) -> Result<(), IpcError> {
            self.handles
                .window_manager_complete(manager, presentation, successful)
        }
    }

    struct CountingCopy<'a> {
        handles: &'a HandleTable,
        pending_copies: Cell<usize>,
    }

    impl WindowManagerApi for CountingCopy<'_> {
        fn pending(&self, manager: Handle) -> Result<WindowPresentation, IpcError> {
            self.handles.window_manager_pending(manager)
        }

        fn displayed(&self, manager: Handle) -> Result<Option<WindowPresentation>, IpcError> {
            self.handles.window_manager_displayed(manager)
        }

        fn buffer_len(&self, manager: Handle) -> Result<usize, IpcError> {
            self.handles.window_buffer_len(manager)
        }

        fn copy_pending(
            &self,
            manager: Handle,
            presentation: WindowPresentation,
            offset: usize,
            output: &mut [u8],
        ) -> Result<(), IpcError> {
            self.pending_copies.set(self.pending_copies.get() + 1);
            self.handles
                .window_manager_copy_pending(manager, presentation, offset, output)
        }

        fn copy_displayed(
            &self,
            manager: Handle,
            presentation: WindowPresentation,
            offset: usize,
            output: &mut [u8],
        ) -> Result<(), IpcError> {
            self.handles
                .window_manager_copy_displayed(manager, presentation, offset, output)
        }

        fn complete(
            &self,
            manager: Handle,
            presentation: WindowPresentation,
            successful: bool,
        ) -> Result<(), IpcError> {
            self.handles
                .window_manager_complete(manager, presentation, successful)
        }
    }

    struct FailingComplete<'a> {
        handles: &'a HandleTable,
    }

    impl WindowManagerApi for FailingComplete<'_> {
        fn pending(&self, manager: Handle) -> Result<WindowPresentation, IpcError> {
            self.handles.window_manager_pending(manager)
        }

        fn displayed(&self, manager: Handle) -> Result<Option<WindowPresentation>, IpcError> {
            self.handles.window_manager_displayed(manager)
        }

        fn buffer_len(&self, manager: Handle) -> Result<usize, IpcError> {
            self.handles.window_buffer_len(manager)
        }

        fn copy_pending(
            &self,
            manager: Handle,
            presentation: WindowPresentation,
            offset: usize,
            output: &mut [u8],
        ) -> Result<(), IpcError> {
            self.handles
                .window_manager_copy_pending(manager, presentation, offset, output)
        }

        fn copy_displayed(
            &self,
            manager: Handle,
            presentation: WindowPresentation,
            offset: usize,
            output: &mut [u8],
        ) -> Result<(), IpcError> {
            self.handles
                .window_manager_copy_displayed(manager, presentation, offset, output)
        }

        fn complete(
            &self,
            _manager: Handle,
            _presentation: WindowPresentation,
            _successful: bool,
        ) -> Result<(), IpcError> {
            Err(IpcError::InvalidMessage)
        }
    }

    #[test]
    fn damage_region_clips_merges_deterministically_and_falls_back_to_full() {
        let mut damage = DamageRegion::new();
        damage.add(Rect::new(-2, -1, 4, 3), 8, 4);
        assert_eq!(damage.len, 1);
        assert_eq!(damage.rects[0], Rect::new(0, 0, 2, 2));

        damage.clear();
        damage.add(Rect::new(0, 0, 1, 1), 8, 4);
        damage.add(Rect::new(2, 0, 1, 1), 8, 4);
        damage.add(Rect::new(1, 0, 1, 1), 8, 4);
        assert_eq!(damage.len, 1);
        assert_eq!(damage.rects[0], Rect::new(0, 0, 3, 1));

        damage.clear();
        for index in 0..DAMAGE_RECT_CAPACITY {
            damage.add(Rect::new((index * 2) as i64, 0, 1, 1), 32, 4);
        }
        assert!(!damage.full);
        assert_eq!(damage.len, DAMAGE_RECT_CAPACITY);
        damage.add(Rect::new((DAMAGE_RECT_CAPACITY * 2) as i64, 0, 1, 1), 32, 4);
        assert!(damage.full);
        assert_eq!(damage.rect(0, 32, 4), Some(Rect::new(0, 0, 32, 4)));
    }

    #[test]
    fn steady_state_composition_does_not_grow_persistent_storage() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let red = pixels(&[0x00FF_0000, 0x00FF_0000]);
        let green = pixels(&[0x0000_FF00, 0x0000_FF00]);
        let (_, client, manager) = create_window(&mut shared_memory, &mut handles, &red, &green);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(1, manager, layout(2, 1, PixelFormat::Xrgb8888)))
            .unwrap();
        let mut bytes = [0_u8; 8];
        let mut framebuffer = standard_framebuffer(&mut bytes, 2, 1);

        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();
        let before = {
            let state = &compositor.render_state;
            (
                state.scene.capacity(),
                state.scene.as_ptr(),
                state.source_row.capacity(),
                state.source_row.as_ptr(),
                state.selected_buffers.capacity(),
                state.selected_buffers.as_ptr(),
            )
        };

        handles.window_present(client, 1, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();
        compositor.redraw(&handles, &mut framebuffer).unwrap();
        let after = {
            let state = &compositor.render_state;
            (
                state.scene.capacity(),
                state.scene.as_ptr(),
                state.source_row.capacity(),
                state.source_row.as_ptr(),
                state.selected_buffers.capacity(),
                state.selected_buffers.as_ptr(),
            )
        };
        assert_eq!(after, before);
    }

    #[test]
    fn partial_damage_preserves_untouched_framebuffer_pixels() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let red = pixels(&[0x00FF_0000]);
        let green = pixels(&[0x0000_FF00]);
        let (_, client, manager) = create_window(&mut shared_memory, &mut handles, &red, &green);
        let placement =
            WindowPlacement::undecorated(Rect::new(1, 0, 1, 1), Some(Rect::new(1, 0, 1, 1)), false);
        let mut compositor = Compositor::new();
        compositor
            .register_window(WindowConfig::new(
                1,
                manager,
                layout(1, 1, PixelFormat::Xrgb8888),
                placement,
            ))
            .unwrap();
        let mut bytes = [0_u8; 12];
        let mut framebuffer = standard_framebuffer(&mut bytes, 3, 1);

        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();
        framebuffer.write_raw_pixel(0, 0, 0x0012_3456);
        framebuffer.write_raw_pixel(2, 0, 0x0065_4321);

        handles.window_present(client, 1, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();
        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x0012_3456));
        assert_eq!(framebuffer.read_raw_pixel(1, 0), Some(0x0000_FF00));
        assert_eq!(framebuffer.read_raw_pixel(2, 0), Some(0x0065_4321));
    }

    #[test]
    fn first_partial_present_composes_the_complete_surface() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let source = pixels(&[0x00ff_0000, 0x0000_ff00]);
        let (_, client, manager) =
            create_window(&mut shared_memory, &mut handles, &source, &source);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(1, manager, layout(2, 1, PixelFormat::Xrgb8888)))
            .unwrap();
        let mut bytes = [0_u8; 8];
        let mut framebuffer = standard_framebuffer(&mut bytes, 2, 1);
        compositor.redraw(&handles, &mut framebuffer).unwrap();

        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending_damage(&handles, &mut framebuffer, 1, &[Rect::new(0, 0, 1, 1)])
            .unwrap();

        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x00ff_0000));
        assert_eq!(framebuffer.read_raw_pixel(1, 0), Some(0x0000_ff00));
    }

    #[test]
    fn first_partial_present_in_a_batch_composes_the_complete_surface() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let source = pixels(&[0x00ff_0000, 0x0000_ff00]);
        let (_, client, manager) =
            create_window(&mut shared_memory, &mut handles, &source, &source);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(1, manager, layout(2, 1, PixelFormat::Xrgb8888)))
            .unwrap();
        let mut bytes = [0_u8; 8];
        let mut framebuffer = standard_framebuffer(&mut bytes, 2, 1);
        compositor.redraw(&handles, &mut framebuffer).unwrap();

        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending_batch(&handles, &mut framebuffer, |_, _| {
                SurfaceDamage::from_slice(&[Rect::new(0, 0, 1, 1)])
            })
            .unwrap();

        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x00ff_0000));
        assert_eq!(framebuffer.read_raw_pixel(1, 0), Some(0x0000_ff00));
    }

    #[test]
    fn pending_batch_builds_and_publishes_one_combined_scene() {
        let mut shared_memory = TestSharedMemoryContext::new(128);
        let mut handles = HandleTable::new();
        let red = pixels(&[0x00ff_0000]);
        let blue = pixels(&[0x0000_00ff]);
        let (_, red_client, red_manager) =
            create_window(&mut shared_memory, &mut handles, &red, &red);
        let (_, blue_client, blue_manager) =
            create_window(&mut shared_memory, &mut handles, &blue, &blue);
        let mut compositor = Compositor::new();
        compositor
            .register_window(WindowConfig::new(
                1,
                red_manager,
                layout(1, 1, PixelFormat::Xrgb8888),
                WindowPlacement::undecorated(
                    Rect::new(0, 0, 1, 1),
                    Some(Rect::new(0, 0, 1, 1)),
                    false,
                ),
            ))
            .unwrap();
        compositor
            .register_window(WindowConfig::new(
                2,
                blue_manager,
                layout(1, 1, PixelFormat::Xrgb8888),
                WindowPlacement::undecorated(
                    Rect::new(1, 0, 1, 1),
                    Some(Rect::new(1, 0, 1, 1)),
                    false,
                ),
            ))
            .unwrap();
        handles.window_present(red_client, 0, 1).unwrap();
        handles.window_present(blue_client, 0, 1).unwrap();
        let mut bytes = [0_u8; 8];
        let mut framebuffer = standard_framebuffer(&mut bytes, 2, 1);

        assert_eq!(
            compositor
                .compose_pending_batch(&handles, &mut framebuffer, |_, _| SurfaceDamage::FULL)
                .unwrap(),
            2
        );
        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x00ff_0000));
        assert_eq!(framebuffer.read_raw_pixel(1, 0), Some(0x0000_00ff));
        assert_eq!(compositor.metrics().composed_frames, 2);
        assert_eq!(compositor.metrics().published_pixels, 2);
    }

    #[test]
    fn source_local_damage_updates_only_the_mapped_pixels() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let first = pixels(&[0x00FF_0000, 0x00FF_0000, 0x00FF_0000, 0x00FF_0000]);
        let second = pixels(&[0x00FF_0000, 0x0000_FF00, 0x00FF_0000, 0x00FF_0000]);
        let (_, client, manager) = create_window(&mut shared_memory, &mut handles, &first, &second);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(1, manager, layout(4, 1, PixelFormat::Xrgb8888)))
            .unwrap();
        let mut bytes = [0_u8; 16];
        let mut framebuffer = standard_framebuffer(&mut bytes, 4, 1);

        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();
        handles.window_present(client, 1, 1).unwrap();
        compositor
            .compose_pending_damage(&handles, &mut framebuffer, 1, &[Rect::new(1, 0, 1, 1)])
            .unwrap();

        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x00FF_0000));
        assert_eq!(framebuffer.read_raw_pixel(1, 0), Some(0x0000_FF00));
        assert_eq!(framebuffer.read_raw_pixel(2, 0), Some(0x00FF_0000));
        assert_eq!(compositor.metrics().published_pixels, 5);
    }

    #[test]
    fn fractional_scale_rounding_fills_the_configured_logical_client() {
        let mut shared_memory = TestSharedMemoryContext::new(256);
        let mut handles = HandleTable::new();
        let source = pixels(&[
            0x00ff_0000,
            0x00ff_0000,
            0x00ff_0000,
            0x00ff_0000,
            0x00ff_0000,
            0x0000_ff00,
            0x0000_ff00,
            0x0000_ff00,
            0x0000_ff00,
            0x0000_ff00,
            0x0000_00ff,
            0x0000_00ff,
            0x0000_00ff,
            0x0000_00ff,
            0x0000_00ff,
        ]);
        let (_, client, manager) =
            create_window(&mut shared_memory, &mut handles, &source, &source);
        let area = Rect::new(0, 0, 3, 2);
        let mut compositor = Compositor::new();
        compositor
            .register_window(
                WindowConfig::new(
                    1,
                    manager,
                    layout(5, 3, PixelFormat::Xrgb8888),
                    WindowPlacement::undecorated(area, Some(area), false),
                )
                .with_source_logical_size(3, 2),
            )
            .unwrap();
        let mut bytes = [0_u8; 24];
        let mut framebuffer = standard_framebuffer(&mut bytes, 3, 2);

        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();

        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x00ff_0000));
        assert_eq!(framebuffer.read_raw_pixel(2, 0), Some(0x00ff_0000));
        assert_eq!(framebuffer.read_raw_pixel(0, 1), Some(0x0000_ff00));
        assert_eq!(framebuffer.read_raw_pixel(2, 1), Some(0x0000_ff00));
    }

    #[test]
    fn same_size_output_replacement_forces_a_complete_redraw() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let red = pixels(&[0x00FF_0000, 0x00FF_0000]);
        let (_, client, manager) = create_window(&mut shared_memory, &mut handles, &red, &red);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(1, manager, layout(2, 1, PixelFormat::Xrgb8888)))
            .unwrap();
        let mut first_bytes = [0_u8; 8];
        let mut first = standard_framebuffer(&mut first_bytes, 2, 1);
        handles.window_present(client, 0, 1).unwrap();
        compositor.compose_pending(&handles, &mut first, 1).unwrap();

        let mut second_bytes = [0_u8; 8];
        let mut second = standard_framebuffer(&mut second_bytes, 2, 1);
        compositor.redraw(&handles, &mut second).unwrap();
        assert_eq!(second.read_raw_pixel(0, 0), Some(0x00FF_0000));
        assert_eq!(second.read_raw_pixel(1, 0), Some(0x00FF_0000));
    }

    #[test]
    fn fully_occluded_pending_surface_completes_without_source_reads_or_writes() {
        let mut shared_memory = TestSharedMemoryContext::new(128);
        let mut handles = HandleTable::new();
        let red = pixels(&[0x00FF_0000; 2]);
        let green = pixels(&[0x0000_FF00; 2]);
        let blue = pixels(&[0x0000_00FF; 2]);
        let (_, lower_client, lower_manager) =
            create_window(&mut shared_memory, &mut handles, &red, &green);
        let (_, upper_client, upper_manager) =
            create_window(&mut shared_memory, &mut handles, &blue, &blue);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(
                1,
                lower_manager,
                layout(2, 1, PixelFormat::Xrgb8888),
            ))
            .unwrap();
        compositor
            .register_window(full_window(
                2,
                upper_manager,
                layout(2, 1, PixelFormat::Xrgb8888),
            ))
            .unwrap();
        let mut bytes = [0_u8; 8];
        let mut framebuffer = standard_framebuffer(&mut bytes, 2, 1);
        handles.window_present(lower_client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();
        handles.window_present(upper_client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 2)
            .unwrap();

        let pending = handles.window_present(lower_client, 1, 1).unwrap();
        let counting = CountingCopy {
            handles: &handles,
            pending_copies: Cell::new(0),
        };
        assert_eq!(
            compositor
                .compose_pending_with(&counting, &mut framebuffer, 1, &[])
                .unwrap(),
            pending
        );
        assert_eq!(counting.pending_copies.get(), 0);
        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x0000_00FF));
        assert_eq!(compositor.metrics().occluded_presentations, 1);
    }

    #[test]
    fn integer_nearest_neighbor_scaling_preserves_aspect_and_letterboxes() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let source = pixels(&[0x00FF_0000, 0x0000_00FF]);
        let (_, client, manager) =
            create_window(&mut shared_memory, &mut handles, &source, &source);
        let placement = WindowPlacement::fullscreen(Rect::new(0, 0, 6, 5), true);
        let mut compositor = Compositor::new();
        compositor
            .register_window(WindowConfig::new(
                1,
                manager,
                layout(2, 1, PixelFormat::Xrgb8888),
                placement,
            ))
            .unwrap();
        let mut bytes = [0_u8; 6 * 5 * 4];
        let mut framebuffer = standard_framebuffer(&mut bytes, 6, 5);
        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();

        for x in 0..6 {
            assert_eq!(
                framebuffer.read_raw_pixel(x, 0),
                Some(raw_color(LETTERBOX_COLOR))
            );
            assert_eq!(
                framebuffer.read_raw_pixel(x, 4),
                Some(raw_color(LETTERBOX_COLOR))
            );
        }
        for y in 1..4 {
            for x in 0..3 {
                assert_eq!(framebuffer.read_raw_pixel(x, y), Some(0x00FF_0000));
            }
            for x in 3..6 {
                assert_eq!(framebuffer.read_raw_pixel(x, y), Some(0x0000_00FF));
            }
        }
        assert_eq!(compositor.hit_test_client(Point::new(5, 4)), Some(1));
    }

    #[test]
    fn nearest_neighbor_downscale_preserves_aspect_and_letterboxes() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let source = pixels(&[
            0x00ff_0000,
            0x0000_ff00,
            0x0000_00ff,
            0x00ff_ffff,
            0x00ff_0000,
            0x0000_ff00,
            0x0000_00ff,
            0x00ff_ffff,
        ]);
        let (_, client, manager) =
            create_window(&mut shared_memory, &mut handles, &source, &source);
        let placement = WindowPlacement::fullscreen(Rect::new(0, 0, 2, 3), true);
        let mut compositor = Compositor::new();
        compositor
            .register_window(WindowConfig::new(
                1,
                manager,
                layout(4, 2, PixelFormat::Xrgb8888),
                placement,
            ))
            .unwrap();
        let mut bytes = [0_u8; 2 * 3 * 4];
        let mut framebuffer = standard_framebuffer(&mut bytes, 2, 3);
        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();

        for x in 0..2 {
            assert_eq!(
                framebuffer.read_raw_pixel(x, 0),
                Some(raw_color(LETTERBOX_COLOR))
            );
            assert_eq!(
                framebuffer.read_raw_pixel(x, 2),
                Some(raw_color(LETTERBOX_COLOR))
            );
        }
        assert_eq!(framebuffer.read_raw_pixel(0, 1), Some(0x00ff_0000));
        assert_eq!(framebuffer.read_raw_pixel(1, 1), Some(0x0000_00ff));
        assert_eq!(compositor.metrics().scaled_frames, 1);
    }

    #[test]
    fn undecorated_outer_area_does_not_occlude_outside_the_client() {
        let mut shared_memory = TestSharedMemoryContext::new(128);
        let mut handles = HandleTable::new();
        let red = pixels(&[0x00ff_0000; 3]);
        let green = pixels(&[0x0000_ff00; 3]);
        let blue = pixels(&[0x0000_00ff]);
        let (_, lower_client, lower_manager) =
            create_window(&mut shared_memory, &mut handles, &red, &green);
        let (_, upper_client, upper_manager) =
            create_window(&mut shared_memory, &mut handles, &blue, &blue);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(
                1,
                lower_manager,
                layout(3, 1, PixelFormat::Xrgb8888),
            ))
            .unwrap();
        compositor
            .register_window(WindowConfig::new(
                2,
                upper_manager,
                layout(1, 1, PixelFormat::Xrgb8888),
                WindowPlacement::new(
                    Rect::new(0, 0, 3, 1),
                    Rect::new(1, 0, 1, 1),
                    Some(Rect::new(0, 0, 3, 1)),
                    false,
                    false,
                ),
            ))
            .unwrap();
        let mut bytes = [0_u8; 12];
        let mut framebuffer = standard_framebuffer(&mut bytes, 3, 1);
        handles.window_present(lower_client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();
        handles.window_present(upper_client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 2)
            .unwrap();

        handles.window_present(lower_client, 1, 1).unwrap();
        let counting = CountingCopy {
            handles: &handles,
            pending_copies: Cell::new(0),
        };
        compositor
            .compose_pending_with(&counting, &mut framebuffer, 1, &[Rect::new(0, 0, 1, 1)])
            .unwrap();
        assert!(counting.pending_copies.get() != 0);
        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x0000_ff00));
        assert_eq!(framebuffer.read_raw_pixel(1, 0), Some(0x0000_00ff));
    }

    #[test]
    fn matching_fullscreen_xrgb_uses_the_direct_fast_path() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let source = pixels(&[0x00FF_0000, 0x0000_00FF]);
        let (_, client, manager) =
            create_window(&mut shared_memory, &mut handles, &source, &source);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(1, manager, layout(2, 1, PixelFormat::Xrgb8888)))
            .unwrap();
        let mut bytes = [0_u8; 8];
        let mut framebuffer = standard_framebuffer(&mut bytes, 2, 1);
        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();
        assert_eq!(compositor.metrics().fullscreen_fast_paths, 1);
        assert_eq!(compositor.metrics().direct_copy_rows, 1);
    }

    #[test]
    fn ordinary_matching_xrgb_rows_use_direct_scene_copies() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let source = pixels(&[0x00ff_0000, 0x0000_00ff]);
        let (_, client, manager) =
            create_window(&mut shared_memory, &mut handles, &source, &source);
        let placement =
            WindowPlacement::undecorated(Rect::new(1, 0, 2, 1), Some(Rect::new(1, 0, 2, 1)), false);
        let mut compositor = Compositor::new();
        compositor
            .register_window(WindowConfig::new(
                1,
                manager,
                layout(2, 1, PixelFormat::Xrgb8888),
                placement,
            ))
            .unwrap();
        let mut bytes = [0_u8; 12];
        let mut framebuffer = standard_framebuffer(&mut bytes, 3, 1);

        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();

        assert_eq!(framebuffer.read_raw_pixel(1, 0), Some(0x00ff_0000));
        assert_eq!(framebuffer.read_raw_pixel(2, 0), Some(0x0000_00ff));
        assert_eq!(compositor.metrics().direct_copy_rows, 1);
    }

    #[test]
    fn failed_completion_keeps_damage_for_display_state_repair() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let red = pixels(&[0x00FF_0000]);
        let green = pixels(&[0x0000_FF00]);
        let (_, client, manager) = create_window(&mut shared_memory, &mut handles, &red, &green);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(1, manager, layout(1, 1, PixelFormat::Xrgb8888)))
            .unwrap();
        let mut bytes = [0_u8; 4];
        let mut framebuffer = standard_framebuffer(&mut bytes, 1, 1);
        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();
        let pending = handles.window_present(client, 1, 1).unwrap();
        let failing = FailingComplete { handles: &handles };
        assert_eq!(
            compositor.compose_pending_with(&failing, &mut framebuffer, 1, &[]),
            Err(CompositorError::Ipc(IpcError::InvalidMessage))
        );
        assert_eq!(handles.window_manager_pending(manager), Ok(pending));
        assert!(compositor.render_state.damage.count() != 0);
        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x0000_FF00));

        compositor.redraw(&handles, &mut framebuffer).unwrap();
        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x00FF_0000));
    }

    #[test]
    fn geometry_changes_queue_bounded_output_damage() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let red = pixels(&[0x00FF_0000]);
        let (_, client, manager) = create_window(&mut shared_memory, &mut handles, &red, &red);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(1, manager, layout(1, 1, PixelFormat::Xrgb8888)))
            .unwrap();
        assert!(compositor.render_state.damage.full);

        let mut bytes = [0_u8; 12];
        let mut framebuffer = standard_framebuffer(&mut bytes, 3, 1);
        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();
        framebuffer.write_raw_pixel(2, 0, 0x0012_3456);

        let moved =
            WindowPlacement::undecorated(Rect::new(1, 0, 1, 1), Some(Rect::new(1, 0, 1, 1)), false);
        compositor.update_placement(1, moved).unwrap();
        assert!(!compositor.render_state.damage.full);
        assert_eq!(
            compositor.render_state.damage.rects[0],
            Rect::new(0, 0, 2, 1)
        );
        compositor.redraw(&handles, &mut framebuffer).unwrap();
        assert_eq!(
            framebuffer.read_raw_pixel(0, 0),
            Some(raw_color(DESKTOP_BACKGROUND))
        );
        assert_eq!(framebuffer.read_raw_pixel(1, 0), Some(0x00FF_0000));
        assert_eq!(framebuffer.read_raw_pixel(2, 0), Some(0x0012_3456));

        compositor.set_focused(1, true).unwrap();
        assert_eq!(compositor.render_state.damage.count(), 0);

        compositor
            .register_window(WindowConfig::new(
                2,
                manager,
                layout(1, 1, PixelFormat::Xrgb8888),
                WindowPlacement::undecorated(
                    Rect::new(2, 0, 1, 1),
                    Some(Rect::new(2, 0, 1, 1)),
                    false,
                ),
            ))
            .unwrap();
        assert_eq!(
            compositor.render_state.damage.rects[0],
            Rect::new(2, 0, 1, 1)
        );
        compositor.render_state.damage.clear();

        compositor.set_z_order(2, 0).unwrap();
        assert_eq!(
            compositor.render_state.damage.rects[0],
            Rect::new(1, 0, 2, 1)
        );
        compositor.render_state.damage.clear();

        assert_eq!(compositor.remove_window(2).map(|window| window.id), Some(2));
        assert_eq!(
            compositor.render_state.damage.rects[0],
            Rect::new(2, 0, 1, 1)
        );
    }

    #[test]
    fn clips_source_visible_and_destination_edges_and_converts_xrgb() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let source = pixels(&[
            0x00FF_0000,
            0x0000_FF00,
            0x0000_00FF,
            0x00FF_FFFF,
            0x00FF_FF00,
            0x0000_FFFF,
        ]);
        let (_, client, manager) =
            create_window(&mut shared_memory, &mut handles, &source, &source);
        handles.window_present(client, 0, 1).unwrap();

        let mut compositor = Compositor::new();
        let mut window = full_window(1, manager, layout(3, 2, PixelFormat::Xrgb8888));
        let client = Rect::new(-1, 1, 3, 2);
        window.placement = WindowPlacement::undecorated(client, Some(client), false);
        compositor.register_window(window).unwrap();

        let mut bytes = [0_u8; 16];
        let mut framebuffer = framebuffer_with_shifts(&mut bytes, 2, 2, 0, 8, 16);
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();

        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x0020_140E));
        assert_eq!(framebuffer.read_raw_pixel(1, 0), Some(0x0020_140E));
        assert_eq!(framebuffer.read_raw_pixel(0, 1), Some(0x0000_FF00));
        assert_eq!(framebuffer.read_raw_pixel(1, 1), Some(0x00FF_0000));
    }

    #[test]
    fn blends_argb_zero_full_and_intermediate_alpha() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let background = pixels(&[0x00FF_0000; 3]);
        let source = pixels(&[0x00FF_FFFF, 0xFF00_FF00, 0x8000_00FF]);
        let (_, background_client, background_manager) =
            create_window(&mut shared_memory, &mut handles, &background, &background);
        let (_, client, manager) =
            create_window(&mut shared_memory, &mut handles, &source, &source);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(
                0,
                background_manager,
                layout(3, 1, PixelFormat::Xrgb8888),
            ))
            .unwrap();
        compositor
            .register_window(full_window(1, manager, layout(3, 1, PixelFormat::Argb8888)))
            .unwrap();

        let mut bytes = [0_u8; 12];
        let mut framebuffer = standard_framebuffer(&mut bytes, 3, 1);
        handles.window_present(background_client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 0)
            .unwrap();
        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();

        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x00FF_0000));
        assert_eq!(framebuffer.read_raw_pixel(1, 0), Some(0x0000_FF00));
        assert_eq!(framebuffer.read_raw_pixel(2, 0), Some(0x007F_0080));
    }

    #[test]
    fn decorations_are_drawn_only_outside_the_client_area() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let source = pixels(&[0x00FF_0000; 4]);
        let (_, client, manager) =
            create_window(&mut shared_memory, &mut handles, &source, &source);
        handles.window_present(client, 0, 1).unwrap();

        let outer = Rect::new(0, 0, 6, 4);
        let placement = WindowPlacement::new(outer, Rect::new(1, 2, 4, 1), Some(outer), true, true);
        let mut compositor = Compositor::new();
        compositor
            .register_window(WindowConfig::new(
                1,
                manager,
                layout(4, 1, PixelFormat::Xrgb8888),
                placement,
            ))
            .unwrap();

        let mut bytes = [0_u8; 6 * 4 * 4];
        let mut framebuffer = standard_framebuffer(&mut bytes, 6, 4);
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();

        let title = raw_color(FOCUSED_TITLE_COLOR);
        let border = raw_color(FOCUSED_BORDER_COLOR);
        for x in 0..6 {
            assert_eq!(framebuffer.read_raw_pixel(x, 0), Some(title));
            assert_eq!(framebuffer.read_raw_pixel(x, 1), Some(title));
            assert_eq!(framebuffer.read_raw_pixel(x, 3), Some(border));
        }
        assert_eq!(framebuffer.read_raw_pixel(0, 2), Some(border));
        for x in 1..5 {
            assert_eq!(framebuffer.read_raw_pixel(x, 2), Some(0x00FF_0000));
        }
        assert_eq!(framebuffer.read_raw_pixel(5, 2), Some(border));
    }

    #[test]
    fn decoration_clipping_and_focus_change_appearance() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let source = pixels(&[0x0000_FF00; 4]);
        let (_, client, manager) =
            create_window(&mut shared_memory, &mut handles, &source, &source);
        handles.window_present(client, 0, 1).unwrap();

        let placement = WindowPlacement::new(
            Rect::new(-2, -1, 7, 5),
            Rect::new(-1, 1, 4, 1),
            Some(Rect::new(0, 0, 3, 3)),
            true,
            true,
        );
        let mut compositor = Compositor::new();
        compositor
            .register_window(WindowConfig::new(
                1,
                manager,
                layout(4, 1, PixelFormat::Xrgb8888),
                placement,
            ))
            .unwrap();

        let mut bytes = [0_u8; 4 * 4 * 4];
        let mut framebuffer = standard_framebuffer(&mut bytes, 4, 4);
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();
        assert_eq!(
            framebuffer.read_raw_pixel(0, 0),
            Some(raw_color(FOCUSED_TITLE_COLOR))
        );
        assert_eq!(framebuffer.read_raw_pixel(0, 1), Some(0x0000_FF00));
        assert_eq!(
            framebuffer.read_raw_pixel(0, 2),
            Some(raw_color(FOCUSED_BORDER_COLOR))
        );
        let background = Some(raw_color(DESKTOP_BACKGROUND));
        assert_eq!(framebuffer.read_raw_pixel(3, 0), background);
        assert_eq!(framebuffer.read_raw_pixel(0, 3), background);

        compositor.set_focused(1, false).unwrap();
        compositor.redraw(&handles, &mut framebuffer).unwrap();
        assert_eq!(
            framebuffer.read_raw_pixel(0, 0),
            Some(raw_color(UNFOCUSED_TITLE_COLOR))
        );
        assert_eq!(
            framebuffer.read_raw_pixel(0, 2),
            Some(raw_color(UNFOCUSED_BORDER_COLOR))
        );
        assert_ne!(
            raw_color(FOCUSED_TITLE_COLOR),
            raw_color(UNFOCUSED_TITLE_COLOR)
        );
    }

    #[test]
    fn client_copy_never_reaches_into_frame_sized_storage() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let source = pixels(&[0x0000_00FF; 2]);
        let (_, client, manager) =
            create_window(&mut shared_memory, &mut handles, &source, &source);
        handles.window_present(client, 0, 1).unwrap();

        let outer = Rect::new(0, 0, 7, 3);
        let mut compositor = Compositor::new();
        compositor
            .register_window(WindowConfig::new(
                1,
                manager,
                layout(2, 1, PixelFormat::Xrgb8888),
                WindowPlacement::new(outer, Rect::new(2, 1, 4, 1), Some(outer), true, true),
            ))
            .unwrap();

        let mut bytes = [0_u8; 7 * 3 * 4];
        let mut framebuffer = standard_framebuffer(&mut bytes, 7, 3);
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();

        assert_eq!(
            framebuffer.read_raw_pixel(2, 1),
            Some(raw_color(LETTERBOX_COLOR))
        );
        assert_eq!(framebuffer.read_raw_pixel(3, 1), Some(0x0000_00FF));
        assert_eq!(framebuffer.read_raw_pixel(4, 1), Some(0x0000_00FF));
        assert_eq!(
            framebuffer.read_raw_pixel(5, 1),
            Some(raw_color(LETTERBOX_COLOR))
        );
        assert_eq!(
            framebuffer.read_raw_pixel(6, 1),
            Some(raw_color(FOCUSED_BORDER_COLOR))
        );
    }

    #[test]
    fn undecorated_and_fullscreen_placements_draw_no_frame() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let transparent = pixels(&[0x0000_0000]);
        let (_, client, manager) =
            create_window(&mut shared_memory, &mut handles, &transparent, &transparent);
        handles.window_present(client, 0, 1).unwrap();

        let outer = Rect::new(0, 0, 3, 3);
        let mut compositor = Compositor::new();
        compositor
            .register_window(WindowConfig::new(
                1,
                manager,
                layout(1, 1, PixelFormat::Argb8888),
                WindowPlacement::new(outer, Rect::new(1, 1, 1, 1), Some(outer), true, false),
            ))
            .unwrap();

        let mut bytes = [0_u8; 3 * 3 * 4];
        let mut framebuffer = standard_framebuffer(&mut bytes, 3, 3);
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();
        let background = Some(raw_color(DESKTOP_BACKGROUND));
        for y in 0..3 {
            for x in 0..3 {
                assert_eq!(framebuffer.read_raw_pixel(x, y), background);
            }
        }

        compositor
            .update_placement(1, WindowPlacement::fullscreen(Rect::new(0, 0, 1, 1), true))
            .unwrap();
        compositor.redraw(&handles, &mut framebuffer).unwrap();
        assert_eq!(framebuffer.read_raw_pixel(0, 0), background);
    }

    #[test]
    fn z_order_controls_composition_and_client_hit_testing() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let red = pixels(&[0x00FF_0000]);
        let blue = pixels(&[0x0000_00FF]);
        let (_, red_client, red_manager) =
            create_window(&mut shared_memory, &mut handles, &red, &red);
        let (_, blue_client, blue_manager) =
            create_window(&mut shared_memory, &mut handles, &blue, &blue);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(
                10,
                red_manager,
                layout(1, 1, PixelFormat::Xrgb8888),
            ))
            .unwrap();
        compositor
            .register_window(full_window(
                20,
                blue_manager,
                layout(1, 1, PixelFormat::Xrgb8888),
            ))
            .unwrap();

        handles.window_present(red_client, 0, 1).unwrap();
        let mut bytes = [0_u8; 4];
        let mut framebuffer = standard_framebuffer(&mut bytes, 1, 1);
        compositor
            .compose_pending(&handles, &mut framebuffer, 10)
            .unwrap();
        handles.window_present(blue_client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 20)
            .unwrap();
        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x0000_00FF));
        assert_eq!(compositor.hit_test_client(Point::new(0, 0)), Some(20));

        compositor.set_z_order(20, 0).unwrap();
        compositor.redraw(&handles, &mut framebuffer).unwrap();
        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x00FF_0000));
        assert_eq!(compositor.hit_test_client(Point::new(0, 0)), Some(10));

        compositor
            .update_placement(
                10,
                WindowPlacement::new(
                    Rect::new(0, 0, 2, 1),
                    Rect::new(1, 0, 1, 1),
                    Some(Rect::new(0, 0, 1, 1)),
                    false,
                    false,
                ),
            )
            .unwrap();
        assert_eq!(compositor.hit_test_client(Point::new(0, 0)), Some(20));
        assert_eq!(
            compositor.remove_window(20).map(|window| window.id),
            Some(20)
        );
        assert_eq!(compositor.hit_test_client(Point::new(0, 0)), None);
    }

    #[test]
    fn successful_presents_release_only_the_previously_displayed_buffer() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let red = pixels(&[0x00FF_0000]);
        let green = pixels(&[0x0000_FF00]);
        let (_, client, manager) = create_window(&mut shared_memory, &mut handles, &red, &green);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(7, manager, layout(1, 1, PixelFormat::Xrgb8888)))
            .unwrap();
        let mut bytes = [0_u8; 4];
        let mut framebuffer = standard_framebuffer(&mut bytes, 1, 1);

        let first = handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 7)
            .unwrap();
        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x00FF_0000));
        assert_eq!(
            handles.window_read_release(client),
            Err(IpcError::ShouldWait)
        );

        let second = handles.window_present(client, 1, 1).unwrap();
        assert_eq!(
            handles.window_read_release(client),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x00FF_0000));
        compositor
            .compose_pending(&handles, &mut framebuffer, 7)
            .unwrap();
        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x0000_FF00));
        let release = handles.window_read_release(client).unwrap();
        assert_eq!(release.buffer_index, first.buffer_index);
        assert_eq!(release.presentation_serial, first.presentation_serial);
        assert_eq!(handles.window_manager_displayed(manager), Ok(Some(second)));
    }

    #[test]
    #[ignore = "manual 1920x1080 compositor bandwidth benchmark"]
    fn benchmark_1080p_full_frame_against_small_damage() {
        use std::time::Instant;

        const WIDTH: usize = 1920;
        const HEIGHT: usize = 1080;
        const FRAMES: usize = 60;
        let surface_bytes = WIDTH * HEIGHT * 4;
        let mut first = vec![0_u8; surface_bytes];
        let mut second = vec![0_u8; surface_bytes];
        for pixel in first.chunks_exact_mut(4) {
            pixel.copy_from_slice(&0x0014_283c_u32.to_le_bytes());
        }
        for pixel in second.chunks_exact_mut(4) {
            pixel.copy_from_slice(&0x003c_2814_u32.to_le_bytes());
        }

        let mut shared_memory = TestSharedMemoryContext::new(8192);
        let mut handles = HandleTable::new();
        let (_, client, manager) = create_window(&mut shared_memory, &mut handles, &first, &second);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(
                1,
                manager,
                layout(WIDTH, HEIGHT, PixelFormat::Xrgb8888),
            ))
            .unwrap();
        let mut framebuffer_bytes = vec![0_u8; surface_bytes];
        let mut framebuffer = standard_framebuffer(&mut framebuffer_bytes, WIDTH, HEIGHT);
        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();

        let full_started = Instant::now();
        for frame in 0..FRAMES {
            let buffer = 1 - frame % 2;
            handles.window_present(client, buffer as u32, 1).unwrap();
            compositor
                .compose_pending(&handles, &mut framebuffer, 1)
                .unwrap();
            handles.window_read_release(client).unwrap();
        }
        let full_elapsed = full_started.elapsed();

        let damage = [Rect::new(WIDTH as i64 / 2, HEIGHT as i64 / 2, 64, 64)];
        let damage_started = Instant::now();
        for frame in 0..FRAMES {
            let buffer = 1 - frame % 2;
            handles.window_present(client, buffer as u32, 1).unwrap();
            compositor
                .compose_pending_damage(&handles, &mut framebuffer, 1, &damage)
                .unwrap();
            handles.window_read_release(client).unwrap();
        }
        let damage_elapsed = damage_started.elapsed();

        std::println!(
            "compositor-bench: 1920x1080 frames={FRAMES} full_us={} damage_64x64_us={} full_bytes={} damage_bytes={}",
            full_elapsed.as_micros(),
            damage_elapsed.as_micros(),
            surface_bytes * FRAMES,
            64 * 64 * 4 * FRAMES,
        );
    }

    #[test]
    fn failed_configuration_or_copy_does_not_release_pending() {
        let mut shared_memory = TestSharedMemoryContext::new(64);
        let mut handles = HandleTable::new();
        let red = pixels(&[0x00FF_0000]);
        let green = pixels(&[0x0000_FF00]);
        let (_, client, manager) = create_window(&mut shared_memory, &mut handles, &red, &green);
        let mut compositor = Compositor::new();
        compositor
            .register_window(full_window(1, manager, layout(1, 1, PixelFormat::Xrgb8888)))
            .unwrap();
        let mut bytes = [0_u8; 4];
        let mut framebuffer = standard_framebuffer(&mut bytes, 1, 1);
        handles.window_present(client, 0, 1).unwrap();
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();
        let pending = handles.window_present(client, 1, 1).unwrap();

        compositor
            .update_window(full_window(1, manager, layout(2, 1, PixelFormat::Xrgb8888)))
            .unwrap();
        assert_eq!(
            compositor.compose_pending(&handles, &mut framebuffer, 1),
            Err(CompositorError::ConfiguredBufferTooSmall {
                window_id: 1,
                required: 8,
                actual: 4,
            })
        );
        assert_eq!(handles.window_manager_pending(manager), Ok(pending));
        assert_eq!(
            handles.window_read_release(client),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x00FF_0000));

        compositor
            .update_window(full_window(1, manager, layout(1, 1, PixelFormat::Xrgb8888)))
            .unwrap();
        let failing_copy = FailingCopy { handles: &handles };
        assert_eq!(
            compositor.compose_pending_with(&failing_copy, &mut framebuffer, 1, &[]),
            Err(CompositorError::Ipc(IpcError::InvalidMessage))
        );
        assert_eq!(handles.window_manager_pending(manager), Ok(pending));
        assert_eq!(
            handles.window_read_release(client),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0x00FF_0000));
    }
}
