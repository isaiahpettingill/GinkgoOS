//! Host-testable software composition over protected window buffers.

use alloc::vec::Vec;

use ginkgo_graphics::{
    FramebufferWriter, PixelFormat, Rgb, SurfaceError, SurfaceLayout, SurfacePixel,
};
use ginkgo_ipc::{Handle, HandleTable, IpcError, WindowPresentation};

/// Stable identity assigned to a compositor window.
pub type WindowId = u64;

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

/// Registration data for one window.
///
/// `placement` locates surface coordinate `(0, 0)` on the screen. `client_area`
/// and `visible_area` are both expressed in surface-local coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowConfig {
    pub id: WindowId,
    pub manager: Handle,
    pub source_layout: SurfaceLayout,
    pub placement: Point,
    pub client_area: Rect,
    pub visible_area: Rect,
}

impl WindowConfig {
    pub const fn new(
        id: WindowId,
        manager: Handle,
        source_layout: SurfaceLayout,
        placement: Point,
        client_area: Rect,
        visible_area: Rect,
    ) -> Self {
        Self {
            id,
            manager,
            source_layout,
            placement,
            client_area,
            visible_area,
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

    pub fn update_geometry(
        &mut self,
        id: WindowId,
        placement: Point,
        client_area: Rect,
        visible_area: Rect,
    ) -> Result<(), CompositorError> {
        let index = self
            .window_index(id)
            .ok_or(CompositorError::UnknownWindow(id))?;
        self.windows[index].placement = placement;
        self.windows[index].client_area = client_area;
        self.windows[index].visible_area = visible_area;
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

    /// Returns the topmost visible window whose client area contains `point`.
    pub fn hit_test_client(&self, point: Point) -> Option<WindowId> {
        let screen_x = i128::from(point.x);
        let screen_y = i128::from(point.y);
        self.windows.iter().rev().find_map(|window| {
            let local_x = screen_x - i128::from(window.placement.x);
            let local_y = screen_y - i128::from(window.placement.y);
            let inside_surface = local_x >= 0
                && local_y >= 0
                && local_x < window.source_layout.width as i128
                && local_y < window.source_layout.height as i128;
            (inside_surface
                && window.visible_area.contains(local_x, local_y)
                && window.client_area.contains(local_x, local_y))
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

        let mut scene_row = Vec::new();
        scene_row
            .try_reserve_exact(width)
            .map_err(|_| CompositorError::OutOfMemory)?;
        scene_row.resize(width, SurfacePixel::xrgb(0, 0, 0));

        let mut source_row = Vec::new();
        source_row
            .try_reserve_exact(source_bytes)
            .map_err(|_| CompositorError::OutOfMemory)?;
        source_row.resize(source_bytes, 0);

        for destination_y in 0..height {
            scene_row.fill(SurfacePixel::xrgb(0, 0, 0));

            for (window, selection) in self.windows.iter().zip(selected) {
                let Some(selection) = selection else {
                    continue;
                };
                let Some((source_top, source_bottom)) = clipped_axis(
                    window.placement.y,
                    window.visible_area.y,
                    window.visible_area.height,
                    window.source_layout.height,
                    height,
                ) else {
                    continue;
                };
                let source_y = i128::from(destination_y as u64) - i128::from(window.placement.y);
                if source_y < source_top as i128 || source_y >= source_bottom as i128 {
                    continue;
                }
                let source_y =
                    usize::try_from(source_y).map_err(|_| CompositorError::ArithmeticOverflow)?;

                let Some((source_left, source_right)) = clipped_axis(
                    window.placement.x,
                    window.visible_area.x,
                    window.visible_area.width,
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

                let destination_left = i128::from(window.placement.x) + source_left as i128;
                let destination_left = usize::try_from(destination_left)
                    .map_err(|_| CompositorError::ArithmeticOverflow)?;
                for (column, bytes) in row.chunks_exact(4).enumerate() {
                    let source = SurfacePixel::new(bytes[2], bytes[1], bytes[0], bytes[3]);
                    blend_source_over(
                        &mut scene_row[destination_left + column],
                        source,
                        window.source_layout.format,
                    );
                }
            }

            for (x, pixel) in scene_row.iter().enumerate() {
                if !framebuffer.write_rgb_pixel(
                    x,
                    destination_y,
                    Rgb::new(pixel.red, pixel.green, pixel.blue),
                ) {
                    return Err(CompositorError::DestinationWrite {
                        x,
                        y: destination_y,
                    });
                }
            }
        }
        Ok(())
    }
}

impl Default for Compositor {
    fn default() -> Self {
        Self::new()
    }
}

/// Clips one source axis against its visible range and the destination axis.
fn clipped_axis(
    placement: i64,
    visible_start: i64,
    visible_length: usize,
    source_length: usize,
    destination_length: usize,
) -> Option<(usize, usize)> {
    let placement = i128::from(placement);
    let left = 0_i128.max(i128::from(visible_start)).max(-placement);
    let right = (source_length as i128)
        .min(i128::from(visible_start) + visible_length as i128)
        .min(destination_length as i128 - placement);
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
    use ginkgo_graphics::FramebufferConfig;

    fn layout(width: usize, height: usize, format: PixelFormat) -> SurfaceLayout {
        SurfaceLayout::new(width, height, width * 4, format)
    }

    fn full_window(id: WindowId, manager: Handle, source_layout: SurfaceLayout) -> WindowConfig {
        WindowConfig::new(
            id,
            manager,
            source_layout,
            Point::new(0, 0),
            Rect::new(0, 0, source_layout.width, source_layout.height),
            Rect::new(0, 0, source_layout.width, source_layout.height),
        )
    }

    fn create_window(
        handles: &mut HandleTable,
        first: &[u8],
        second: &[u8],
    ) -> (Handle, Handle, Handle) {
        assert_eq!(first.len(), second.len());
        let memory = handles.shared_memory_create(first.len() * 2).unwrap();
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
        let mut handles = HandleTable::new();
        let source = pixels(&[
            0x00FF_0000,
            0x0000_FF00,
            0x0000_00FF,
            0x00FF_FFFF,
            0x00FF_FF00,
            0x0000_FFFF,
        ]);
        let (_, client, manager) = create_window(&mut handles, &source, &source);
        handles.window_present(client, 0, 1).unwrap();

        let mut compositor = Compositor::new();
        let mut window = full_window(1, manager, layout(3, 2, PixelFormat::Xrgb8888));
        window.placement = Point::new(-1, 1);
        compositor.register_window(window).unwrap();

        let mut bytes = [0_u8; 16];
        let mut framebuffer = framebuffer_with_shifts(&mut bytes, 2, 2, 0, 8, 16);
        compositor
            .compose_pending(&handles, &mut framebuffer, 1)
            .unwrap();

        assert_eq!(framebuffer.read_raw_pixel(0, 0), Some(0));
        assert_eq!(framebuffer.read_raw_pixel(1, 0), Some(0));
        assert_eq!(framebuffer.read_raw_pixel(0, 1), Some(0x0000_FF00));
        assert_eq!(framebuffer.read_raw_pixel(1, 1), Some(0x00FF_0000));
    }

    #[test]
    fn blends_argb_zero_full_and_intermediate_alpha() {
        let mut handles = HandleTable::new();
        let background = pixels(&[0x00FF_0000; 3]);
        let source = pixels(&[0x00FF_FFFF, 0xFF00_FF00, 0x8000_00FF]);
        let (_, background_client, background_manager) =
            create_window(&mut handles, &background, &background);
        let (_, client, manager) = create_window(&mut handles, &source, &source);
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
    fn z_order_controls_composition_and_client_hit_testing() {
        let mut handles = HandleTable::new();
        let red = pixels(&[0x00FF_0000]);
        let blue = pixels(&[0x0000_00FF]);
        let (_, red_client, red_manager) = create_window(&mut handles, &red, &red);
        let (_, blue_client, blue_manager) = create_window(&mut handles, &blue, &blue);
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
            .update_geometry(
                10,
                Point::new(0, 0),
                Rect::new(1, 0, 1, 1),
                Rect::new(0, 0, 1, 1),
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
        let mut handles = HandleTable::new();
        let red = pixels(&[0x00FF_0000]);
        let green = pixels(&[0x0000_FF00]);
        let (_, client, manager) = create_window(&mut handles, &red, &green);
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
        let mut handles = HandleTable::new();
        let red = pixels(&[0x00FF_0000]);
        let green = pixels(&[0x0000_FF00]);
        let (_, client, manager) = create_window(&mut handles, &red, &green);
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
