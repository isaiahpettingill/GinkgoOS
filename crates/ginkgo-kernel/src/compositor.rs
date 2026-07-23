//! Host-testable software composition over protected window buffers.

use alloc::vec::Vec;

use ginkgo_graphics::{FramebufferWriter, PixelFormat, SurfaceError, SurfaceLayout, SurfacePixel};
use ginkgo_ipc::{Handle, HandleTable, IpcError, WindowPresentation};

/// Stable identity assigned to a compositor window.
pub type WindowId = u64;

const DESKTOP_BACKGROUND: SurfacePixel = SurfacePixel::xrgb(14, 20, 32);
const FOCUSED_TITLE_COLOR: SurfacePixel = SurfacePixel::xrgb(46, 106, 176);
const FOCUSED_BORDER_COLOR: SurfacePixel = SurfacePixel::xrgb(24, 58, 96);
const UNFOCUSED_TITLE_COLOR: SurfacePixel = SurfacePixel::xrgb(96, 101, 112);
const UNFOCUSED_BORDER_COLOR: SurfacePixel = SurfacePixel::xrgb(58, 61, 68);

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
            placement,
        }
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

#[derive(Clone, Copy)]
struct SelectedBuffer {
    presentation: WindowPresentation,
    pending: bool,
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
/// after every framebuffer pixel has been written.
pub struct Compositor {
    windows: Vec<WindowConfig>,
}

impl Compositor {
    pub const fn new() -> Self {
        Self {
            windows: Vec::new(),
        }
    }

    /// Returns windows in bottom-to-top z-order.
    pub fn windows(&self) -> &[WindowConfig] {
        &self.windows
    }

    pub fn window(&self, id: WindowId) -> Option<&WindowConfig> {
        self.windows.iter().find(|window| window.id == id)
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
        self.windows.push(window);
        Ok(())
    }

    /// Replaces registration data without changing the window's z-order.
    pub fn update_window(&mut self, window: WindowConfig) -> Result<(), CompositorError> {
        window.source_layout.required_bytes()?;
        let index = self
            .window_index(window.id)
            .ok_or(CompositorError::UnknownWindow(window.id))?;
        self.windows[index] = window;
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
        self.windows[index].placement = placement;
        Ok(())
    }

    /// Updates only focus appearance for placement brokers handling a focus delta.
    pub fn set_focused(&mut self, id: WindowId, focused: bool) -> Result<(), CompositorError> {
        let index = self
            .window_index(id)
            .ok_or(CompositorError::UnknownWindow(id))?;
        self.windows[index].placement.focused = focused;
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
            let window = self.windows.remove(index);
            self.windows.insert(z_index, window);
        }
        Ok(())
    }

    pub fn remove_window(&mut self, id: WindowId) -> Option<WindowConfig> {
        self.window_index(id)
            .map(|index| self.windows.remove(index))
    }

    /// Returns the topmost visible window whose client pixels contain `point`.
    /// Server-side decoration is deliberately excluded.
    pub fn hit_test_client(&self, point: Point) -> Option<WindowId> {
        let screen_x = i128::from(point.x);
        let screen_y = i128::from(point.y);
        self.windows.iter().rev().find_map(|window| {
            let placement = window.placement;
            let visible = placement.visible?;
            let source_x = screen_x - i128::from(placement.client.x);
            let source_y = screen_y - i128::from(placement.client.y);
            let inside_source = source_x >= 0
                && source_y >= 0
                && source_x < window.source_layout.width as i128
                && source_y < window.source_layout.height as i128;
            (inside_source
                && visible.contains(screen_x, screen_y)
                && placement.client.contains(screen_x, screen_y))
            .then_some(window.id)
        })
    }

    /// Redraws the scene with one window's pending buffer and all other
    /// windows' retained displayed buffers.
    pub fn compose_pending(
        &self,
        handles: &HandleTable,
        framebuffer: &mut FramebufferWriter<'_>,
        id: WindowId,
    ) -> Result<WindowPresentation, CompositorError> {
        self.compose_pending_with(handles, framebuffer, id)
    }

    fn compose_pending_with<H: WindowManagerApi + ?Sized>(
        &self,
        handles: &H,
        framebuffer: &mut FramebufferWriter<'_>,
        id: WindowId,
    ) -> Result<WindowPresentation, CompositorError> {
        let target = self
            .window_index(id)
            .ok_or(CompositorError::UnknownWindow(id))?;
        let pending = handles.pending(self.windows[target].manager)?;
        let selected = self.select_buffers(handles, Some((target, pending)))?;
        self.render(handles, framebuffer, &selected)?;
        handles.complete(self.windows[target].manager, pending, true)?;
        Ok(pending)
    }

    /// Redraws all retained displayed buffers without changing ownership.
    pub fn redraw(
        &self,
        handles: &HandleTable,
        framebuffer: &mut FramebufferWriter<'_>,
    ) -> Result<(), CompositorError> {
        let selected = self.select_buffers(handles, None)?;
        self.render(handles, framebuffer, &selected)
    }

    fn window_index(&self, id: WindowId) -> Option<usize> {
        self.windows.iter().position(|window| window.id == id)
    }

    fn select_buffers<H: WindowManagerApi + ?Sized>(
        &self,
        handles: &H,
        pending: Option<(usize, WindowPresentation)>,
    ) -> Result<Vec<Option<SelectedBuffer>>, CompositorError> {
        let mut selected = Vec::new();
        selected
            .try_reserve_exact(self.windows.len())
            .map_err(|_| CompositorError::OutOfMemory)?;

        for (index, window) in self.windows.iter().enumerate() {
            let selection = if let Some((pending_index, presentation)) = pending {
                if index == pending_index {
                    Some(SelectedBuffer {
                        presentation,
                        pending: true,
                    })
                } else {
                    handles
                        .displayed(window.manager)?
                        .map(|presentation| SelectedBuffer {
                            presentation,
                            pending: false,
                        })
                }
            } else {
                handles
                    .displayed(window.manager)?
                    .map(|presentation| SelectedBuffer {
                        presentation,
                        pending: false,
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
            selected.push(selection);
        }
        Ok(selected)
    }

    fn render<H: WindowManagerApi + ?Sized>(
        &self,
        handles: &H,
        framebuffer: &mut FramebufferWriter<'_>,
        selected: &[Option<SelectedBuffer>],
    ) -> Result<(), CompositorError> {
        let width = framebuffer.width();
        let height = framebuffer.height();
        let source_bytes = width
            .checked_mul(PixelFormat::Xrgb8888.bytes_per_pixel())
            .ok_or(CompositorError::ArithmeticOverflow)?;

        let scene_len = width
            .checked_mul(height)
            .ok_or(CompositorError::ArithmeticOverflow)?;
        let mut scene = Vec::new();
        scene
            .try_reserve_exact(scene_len)
            .map_err(|_| CompositorError::OutOfMemory)?;
        scene.resize(scene_len, DESKTOP_BACKGROUND);

        let mut source_row = Vec::new();
        source_row
            .try_reserve_exact(source_bytes)
            .map_err(|_| CompositorError::OutOfMemory)?;
        source_row.resize(source_bytes, 0);

        for destination_y in 0..height {
            let row_start = destination_y
                .checked_mul(width)
                .ok_or(CompositorError::ArithmeticOverflow)?;
            let scene_row = scene
                .get_mut(row_start..row_start + width)
                .ok_or(CompositorError::ArithmeticOverflow)?;

            for (window, selection) in self.windows.iter().zip(selected) {
                let Some(selection) = selection else {
                    continue;
                };
                let placement = window.placement;
                let Some(visible) = placement.visible else {
                    continue;
                };

                draw_frame_row(scene_row, destination_y, placement, visible);

                let Some((source_top, source_bottom)) = clipped_client_axis(
                    placement.client.y,
                    placement.client.height,
                    visible.y,
                    visible.height,
                    window.source_layout.height,
                    height,
                ) else {
                    continue;
                };
                let source_y = i128::from(destination_y as u64) - i128::from(placement.client.y);
                if source_y < source_top as i128 || source_y >= source_bottom as i128 {
                    continue;
                }
                let source_y =
                    usize::try_from(source_y).map_err(|_| CompositorError::ArithmeticOverflow)?;

                let Some((source_left, source_right)) = clipped_client_axis(
                    placement.client.x,
                    placement.client.width,
                    visible.x,
                    visible.width,
                    window.source_layout.width,
                    width,
                ) else {
                    continue;
                };
                let copy_width = source_right - source_left;
                let copy_bytes = copy_width
                    .checked_mul(window.source_layout.format.bytes_per_pixel())
                    .ok_or(CompositorError::ArithmeticOverflow)?;
                let offset = source_y
                    .checked_mul(window.source_layout.stride)
                    .and_then(|row| {
                        source_left
                            .checked_mul(window.source_layout.format.bytes_per_pixel())
                            .and_then(|column| row.checked_add(column))
                    })
                    .ok_or(CompositorError::ArithmeticOverflow)?;
                let row = source_row
                    .get_mut(..copy_bytes)
                    .ok_or(CompositorError::ArithmeticOverflow)?;
                if selection.pending {
                    handles.copy_pending(window.manager, selection.presentation, offset, row)?;
                } else {
                    handles.copy_displayed(window.manager, selection.presentation, offset, row)?;
                }

                let destination_left = i128::from(placement.client.x) + source_left as i128;
                let destination_left = usize::try_from(destination_left)
                    .map_err(|_| CompositorError::ArithmeticOverflow)?;
                if window.source_layout.format == PixelFormat::Xrgb8888 {
                    let destination = scene_row
                        .get_mut(destination_left..destination_left + copy_width)
                        .ok_or(CompositorError::ArithmeticOverflow)?;
                    // SurfacePixel and XRGB8888 share the documented B,G,R,X byte order.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            row.as_ptr(),
                            destination.as_mut_ptr().cast::<u8>(),
                            copy_bytes,
                        );
                    }
                } else {
                    for (column, bytes) in row.chunks_exact(4).enumerate() {
                        let source = SurfacePixel::new(bytes[2], bytes[1], bytes[0], bytes[3]);
                        blend_source_over(
                            &mut scene_row[destination_left + column],
                            source,
                            window.source_layout.format,
                        );
                    }
                }
            }
        }

        if !framebuffer.write_xrgb8888_scene(&scene) {
            return Err(CompositorError::DestinationWrite { x: 0, y: 0 });
        }
        Ok(())
    }
}

impl Default for Compositor {
    fn default() -> Self {
        Self::new()
    }
}

fn draw_frame_row(
    destination: &mut [SurfacePixel],
    destination_y: usize,
    placement: WindowPlacement,
    visible: Rect,
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

    for (x, pixel) in destination.iter_mut().enumerate().take(right).skip(left) {
        if !placement.client.contains(x as i128, y) {
            *pixel = frame_color;
        }
    }
}

/// Clips an application-provided client-buffer axis against the client area,
/// its visible output range, and the framebuffer destination.
fn clipped_client_axis(
    client_start: i64,
    client_length: usize,
    visible_start: i64,
    visible_length: usize,
    source_length: usize,
    destination_length: usize,
) -> Option<(usize, usize)> {
    let client_start = i128::from(client_start);
    let visible_start = i128::from(visible_start);
    let left = 0_i128.max(visible_start - client_start).max(-client_start);
    let right = (source_length as i128)
        .min(client_length as i128)
        .min(visible_start + visible_length as i128 - client_start)
        .min(destination_length as i128 - client_start);
    if left >= right {
        return None;
    }
    Some((usize::try_from(left).ok()?, usize::try_from(right).ok()?))
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

        assert_eq!(framebuffer.read_raw_pixel(2, 1), Some(0x0000_00FF));
        assert_eq!(framebuffer.read_raw_pixel(3, 1), Some(0x0000_00FF));
        let background = Some(raw_color(DESKTOP_BACKGROUND));
        assert_eq!(framebuffer.read_raw_pixel(4, 1), background);
        assert_eq!(framebuffer.read_raw_pixel(5, 1), background);
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
            compositor.compose_pending_with(&failing_copy, &mut framebuffer, 1),
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
