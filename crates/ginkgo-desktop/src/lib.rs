#![no_std]

//! Transport- and runtime-independent desktop service policy.
//!
//! [`Desktop`] owns window identity and state, applies scrolling-layout policy,
//! and translates window protocol requests into [`DesktopAction`] values. It
//! deliberately does not allocate shared surfaces, send messages, composite
//! pixels, or invoke syscalls. A future runtime is responsible for executing
//! the returned actions.

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::min;

use ginkgo_scroll_layout::{
    Direction, Insets, Layout, LayoutError, Proportion, Rect as LayoutRect, Size as LayoutSize,
    WindowId as LayoutWindowId,
};
use ginkgo_window::{
    BufferId, Generation, KeyboardEvent, PixelFormat, Point, PointerEvent, PointerEventKind, Rect,
    RequestId, ScaleFactor, ServerErrorCode, Size, SurfaceConfiguration, WindowId, WindowOptions,
    WireRequest, MIN_BUFFER_SLOTS, PROTOCOL_VERSION,
};

/// Identity assigned by the runtime to one protocol connection or client.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClientId(u64);

impl ClientId {
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Desktop-controlled surface and scrolling policy.
///
/// The defaults use fractional 3/2 scaling, fixed `Xrgb8888` surfaces, two
/// buffers, 60%-wide scrolling columns, and server-side decoration insets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DesktopPolicy {
    pub scale: ScaleFactor,
    pub format: PixelFormat,
    pub buffer_count: u8,
    pub default_width: Proportion,
    pub decorations: Insets,
}

impl Default for DesktopPolicy {
    fn default() -> Self {
        Self {
            scale: ScaleFactor::new(3, 2).expect("3/2 is a valid scale factor"),
            format: PixelFormat::Xrgb8888,
            buffer_count: MIN_BUFFER_SLOTS,
            default_width: Proportion::new(600).expect("600 per-mille is non-zero"),
            decorations: Insets::new(4, 24, 4, 4),
        }
    }
}

/// Public state retained for a window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowInfo {
    pub id: WindowId,
    pub owner: ClientId,
    pub options: WindowOptions,
    pub configuration: Option<SurfaceConfiguration>,
}

/// Effective geometry published to the compositor/runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowPlacement {
    pub window_id: WindowId,
    pub outer: LayoutRect,
    /// The rectangle occupied by client content. Configured sizes always refer
    /// to this rectangle, never to `outer`.
    pub client: LayoutRect,
    pub visible: Option<LayoutRect>,
    pub focused: bool,
    pub decorated: bool,
}

/// Result of client-area hit testing in output logical coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HitTest {
    pub client_id: ClientId,
    pub window_id: WindowId,
    pub local_position: Point,
}

/// Explicit work for a channel, kernel, allocator, or compositor runtime.
///
/// `Configure` intentionally carries no attachment index or surface handle.
/// The runtime must allocate the surface pool, attach it to a `Configured`
/// wire event, and send that event to `client_id`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DesktopAction {
    WindowCreated {
        client_id: ClientId,
        protocol_version: u16,
        request_id: RequestId,
        window_id: WindowId,
    },
    Configure {
        client_id: ClientId,
        window_id: WindowId,
        configuration: SurfaceConfiguration,
    },
    DestroyWindow {
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
    },
    RequestFailed {
        client_id: ClientId,
        request_id: RequestId,
        code: ServerErrorCode,
    },
    /// Replaces the runtime's complete active-output placement set.
    SetPlacements { placements: Vec<WindowPlacement> },
    FocusChanged {
        client_id: ClientId,
        window_id: WindowId,
        focused: bool,
    },
    Present {
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
        generation: Generation,
        buffer_id: BufferId,
        damage: Vec<Rect>,
    },
    ForwardPointer {
        client_id: ClientId,
        window_id: WindowId,
        event: PointerEvent,
    },
    ForwardKeyboard {
        client_id: ClientId,
        window_id: WindowId,
        event: KeyboardEvent,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesktopError {
    EmptyOutput,
    InvalidBufferCount,
    InvalidColumnWidth,
    Layout(LayoutError),
    OutOfResources,
    UnknownWindow,
}

impl From<LayoutError> for DesktopError {
    fn from(error: LayoutError) -> Self {
        Self::Layout(error)
    }
}

/// Stateful desktop request translator and scrolling policy core.
#[derive(Debug)]
pub struct Desktop {
    layout: Layout,
    policy: DesktopPolicy,
    windows: Vec<WindowInfo>,
    next_window_id: u64,
    announced_focus: Option<WindowId>,
}

impl Desktop {
    pub fn new(output: Size) -> Result<Self, DesktopError> {
        Self::with_policy(output, DesktopPolicy::default())
    }

    pub fn with_policy(output: Size, policy: DesktopPolicy) -> Result<Self, DesktopError> {
        validate_output(output, policy)?;
        let mut layout = Layout::new(to_layout_size(output));
        layout.set_decorations(policy.decorations);
        Ok(Self {
            layout,
            policy,
            windows: Vec::new(),
            next_window_id: 1,
            announced_focus: None,
        })
    }

    pub const fn policy(&self) -> DesktopPolicy {
        self.policy
    }

    pub fn output_size(&self) -> Size {
        from_layout_size(self.layout.output_size())
    }

    pub fn windows(&self) -> impl ExactSizeIterator<Item = &WindowInfo> {
        self.windows.iter()
    }

    pub fn window(&self, window_id: WindowId) -> Option<&WindowInfo> {
        self.window_index(window_id)
            .map(|index| &self.windows[index])
    }

    pub fn focused_window(&self) -> Option<WindowId> {
        self.layout.focused_window().map(from_layout_window_id)
    }

    pub fn fullscreen_window(&self) -> Option<WindowId> {
        self.layout.fullscreen_window().map(from_layout_window_id)
    }

    pub fn viewport(&self) -> i64 {
        self.layout.viewport()
    }

    pub fn placements(&self) -> Vec<WindowPlacement> {
        self.effective_placements()
    }

    /// Handles one already-decoded request from a runtime-identified client.
    pub fn handle_request(
        &mut self,
        client_id: ClientId,
        request: WireRequest,
    ) -> Vec<DesktopAction> {
        match request {
            WireRequest::CreateWindow {
                protocol_version,
                request_id,
                options,
            } => self.create_window(client_id, protocol_version, request_id, options),
            WireRequest::DestroyWindow {
                request_id,
                window_id,
            } => self.destroy_window(client_id, request_id, window_id),
            WireRequest::RequestSize {
                request_id,
                window_id,
                preferred_size,
            } => self.request_size(client_id, request_id, window_id, preferred_size),
            WireRequest::SetMinimumSize {
                request_id,
                window_id,
                minimum_size,
            } => self.set_minimum_size(client_id, request_id, window_id, minimum_size),
            WireRequest::SetMaximumSize {
                request_id,
                window_id,
                maximum_size,
            } => self.set_maximum_size(client_id, request_id, window_id, maximum_size),
            WireRequest::SetFullscreen {
                request_id,
                window_id,
                fullscreen,
            } => self.set_fullscreen(client_id, request_id, window_id, fullscreen),
            WireRequest::ToggleFullscreen {
                request_id,
                window_id,
            } => {
                let fullscreen = self.fullscreen_window() != Some(window_id);
                self.set_fullscreen(client_id, request_id, window_id, fullscreen)
            }
            WireRequest::Present {
                request_id,
                window_id,
                generation,
                buffer_id,
                damage,
            } => self.present(
                client_id, request_id, window_id, generation, buffer_id, damage,
            ),
        }
    }

    pub fn focus_window(
        &mut self,
        window_id: WindowId,
    ) -> Result<Vec<DesktopAction>, DesktopError> {
        self.layout.focus(to_layout_window_id(window_id))?;
        self.reconcile(None)
    }

    pub fn focus_left(&mut self) -> Result<Vec<DesktopAction>, DesktopError> {
        self.focus_relative(Direction::Previous)
    }

    pub fn focus_right(&mut self) -> Result<Vec<DesktopAction>, DesktopError> {
        self.focus_relative(Direction::Next)
    }

    pub fn move_focused_left(&mut self) -> Result<Vec<DesktopAction>, DesktopError> {
        self.move_focused(Direction::Previous)
    }

    pub fn move_focused_right(&mut self) -> Result<Vec<DesktopAction>, DesktopError> {
        self.move_focused(Direction::Next)
    }

    pub fn set_window_width(
        &mut self,
        window_id: WindowId,
        width: Proportion,
    ) -> Result<Vec<DesktopAction>, DesktopError> {
        self.layout
            .set_width(to_layout_window_id(window_id), width)?;
        self.reconcile(Some(window_id))
    }

    /// Applies a hotplug/mode/scale change and configures affected clients.
    pub fn output_changed(
        &mut self,
        output: Size,
        scale: ScaleFactor,
    ) -> Result<Vec<DesktopAction>, DesktopError> {
        let mut policy = self.policy;
        policy.scale = scale;
        validate_output(output, policy)?;
        self.policy = policy;
        self.layout.set_output_size(to_layout_size(output));
        self.reconcile(None)
    }

    pub fn set_decorations(
        &mut self,
        decorations: Insets,
    ) -> Result<Vec<DesktopAction>, DesktopError> {
        self.policy.decorations = decorations;
        self.layout.set_decorations(decorations);
        self.reconcile(None)
    }

    /// Finds the topmost client content rectangle at `position`.
    pub fn hit_test(&self, position: Point) -> Option<HitTest> {
        let x = i64::from(position.x);
        let y = i64::from(position.y);
        self.effective_placements()
            .into_iter()
            .rev()
            .find(|placement| contains(placement.client, x, y))
            .and_then(|placement| {
                let window = self.window(placement.window_id)?;
                Some(HitTest {
                    client_id: window.owner,
                    window_id: window.id,
                    local_position: Point::new(
                        i32::try_from(x.saturating_sub(placement.client.x)).ok()?,
                        i32::try_from(y.saturating_sub(placement.client.y)).ok()?,
                    ),
                })
            })
    }

    /// Hit-tests pointer input, focuses its target, and returns a client-local
    /// forwarding action. Input on server decorations is not forwarded.
    pub fn pointer_input(
        &mut self,
        position: Point,
        kind: PointerEventKind,
    ) -> Result<Vec<DesktopAction>, DesktopError> {
        let Some(hit) = self.hit_test(position) else {
            return Ok(Vec::new());
        };
        let mut actions = if self.focused_window() == Some(hit.window_id) {
            Vec::new()
        } else {
            self.focus_window(hit.window_id)?
        };
        actions.push(DesktopAction::ForwardPointer {
            client_id: hit.client_id,
            window_id: hit.window_id,
            event: PointerEvent {
                position: hit.local_position,
                kind,
            },
        });
        Ok(actions)
    }

    pub fn keyboard_input(&self, event: KeyboardEvent) -> Vec<DesktopAction> {
        let Some(window_id) = self.focused_window() else {
            return Vec::new();
        };
        let Some(window) = self.window(window_id) else {
            return Vec::new();
        };
        alloc::vec![DesktopAction::ForwardKeyboard {
            client_id: window.owner,
            window_id,
            event,
        }]
    }

    fn create_window(
        &mut self,
        client_id: ClientId,
        protocol_version: u16,
        request_id: RequestId,
        options: WindowOptions,
    ) -> Vec<DesktopAction> {
        if protocol_version != PROTOCOL_VERSION {
            return failed(client_id, request_id, ServerErrorCode::Unsupported);
        }
        if options.validate().is_err() {
            return failed(client_id, request_id, ServerErrorCode::InvalidRequest);
        }
        if !options.preferred_formats.contains(&self.policy.format) {
            return failed(client_id, request_id, ServerErrorCode::Unsupported);
        }
        let Some(raw_id) = self.allocate_window_id() else {
            return failed(client_id, request_id, ServerErrorCode::OutOfResources);
        };
        let window_id = WindowId::new(raw_id).expect("allocated window IDs are non-zero");
        let fullscreen = options.fullscreen;
        self.windows.push(WindowInfo {
            id: window_id,
            owner: client_id,
            options,
            configuration: None,
        });

        if self
            .layout
            .insert(to_layout_window_id(window_id), self.policy.default_width)
            .is_err()
            || (fullscreen
                && self
                    .layout
                    .enter_fullscreen(to_layout_window_id(window_id))
                    .is_err())
        {
            self.windows.pop();
            let _ = self.layout.remove(to_layout_window_id(window_id));
            return failed(client_id, request_id, ServerErrorCode::OutOfResources);
        }

        let mut actions = alloc::vec![DesktopAction::WindowCreated {
            client_id,
            protocol_version: PROTOCOL_VERSION,
            request_id,
            window_id,
        }];
        match self.append_reconcile(&mut actions, Some(window_id)) {
            Ok(()) => actions,
            Err(_) => {
                let _ = self.layout.remove(to_layout_window_id(window_id));
                self.windows.pop();
                failed(client_id, request_id, ServerErrorCode::OutOfResources)
            }
        }
    }

    fn destroy_window(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
    ) -> Vec<DesktopAction> {
        let Some(index) = self.owned_window_index(client_id, window_id) else {
            return failed(client_id, request_id, ServerErrorCode::WindowGone);
        };
        if self.layout.remove(to_layout_window_id(window_id)).is_err() {
            return failed(client_id, request_id, ServerErrorCode::WindowGone);
        }
        self.windows.remove(index);
        let mut actions = alloc::vec![DesktopAction::DestroyWindow {
            client_id,
            request_id,
            window_id,
        }];
        if self.append_reconcile(&mut actions, None).is_err() {
            actions.push(DesktopAction::RequestFailed {
                client_id,
                request_id,
                code: ServerErrorCode::OutOfResources,
            });
        }
        actions
    }

    fn request_size(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
        preferred_size: Size,
    ) -> Vec<DesktopAction> {
        if preferred_size.is_empty() {
            return failed(client_id, request_id, ServerErrorCode::InvalidRequest);
        }
        let Some(index) = self.owned_window_index(client_id, window_id) else {
            return failed(client_id, request_id, ServerErrorCode::WindowGone);
        };
        self.windows[index].options.preferred_size = preferred_size;
        self.request_reconfigure(client_id, request_id, window_id)
    }

    fn set_minimum_size(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
        minimum_size: Option<Size>,
    ) -> Vec<DesktopAction> {
        if minimum_size.is_some_and(Size::is_empty) {
            return failed(client_id, request_id, ServerErrorCode::InvalidRequest);
        }
        let Some(index) = self.owned_window_index(client_id, window_id) else {
            return failed(client_id, request_id, ServerErrorCode::WindowGone);
        };
        if constraints_inverted(minimum_size, self.windows[index].options.maximum_size) {
            return failed(client_id, request_id, ServerErrorCode::InvalidRequest);
        }
        self.windows[index].options.minimum_size = minimum_size;
        self.request_reconfigure(client_id, request_id, window_id)
    }

    fn set_maximum_size(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
        maximum_size: Option<Size>,
    ) -> Vec<DesktopAction> {
        if maximum_size.is_some_and(Size::is_empty) {
            return failed(client_id, request_id, ServerErrorCode::InvalidRequest);
        }
        let Some(index) = self.owned_window_index(client_id, window_id) else {
            return failed(client_id, request_id, ServerErrorCode::WindowGone);
        };
        if constraints_inverted(self.windows[index].options.minimum_size, maximum_size) {
            return failed(client_id, request_id, ServerErrorCode::InvalidRequest);
        }
        self.windows[index].options.maximum_size = maximum_size;
        self.request_reconfigure(client_id, request_id, window_id)
    }

    fn request_reconfigure(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
    ) -> Vec<DesktopAction> {
        match self.reconcile(Some(window_id)) {
            Ok(actions) => actions,
            Err(_) => failed(client_id, request_id, ServerErrorCode::OutOfResources),
        }
    }

    fn set_fullscreen(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
        fullscreen: bool,
    ) -> Vec<DesktopAction> {
        if self.owned_window_index(client_id, window_id).is_none() {
            return failed(client_id, request_id, ServerErrorCode::WindowGone);
        }
        let current = self.fullscreen_window();
        let result = if fullscreen {
            if current == Some(window_id) {
                Ok(())
            } else {
                self.layout.enter_fullscreen(to_layout_window_id(window_id))
            }
        } else if current == Some(window_id) {
            self.layout.exit_fullscreen();
            Ok(())
        } else {
            Ok(())
        };
        if result.is_err() {
            return failed(client_id, request_id, ServerErrorCode::WindowGone);
        }
        match self.reconcile(Some(window_id)) {
            Ok(actions) => actions,
            Err(_) => failed(client_id, request_id, ServerErrorCode::OutOfResources),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn present(
        &self,
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
        generation: Generation,
        buffer_id: BufferId,
        damage: Vec<Rect>,
    ) -> Vec<DesktopAction> {
        let Some(index) = self.owned_window_index(client_id, window_id) else {
            return failed(client_id, request_id, ServerErrorCode::WindowGone);
        };
        let Some(configuration) = self.windows[index].configuration else {
            return failed(client_id, request_id, ServerErrorCode::InvalidRequest);
        };
        if configuration.generation != generation || buffer_id.get() >= configuration.buffer_count {
            return failed(client_id, request_id, ServerErrorCode::InvalidRequest);
        }
        alloc::vec![DesktopAction::Present {
            client_id,
            request_id,
            window_id,
            generation,
            buffer_id,
            damage,
        }]
    }

    fn focus_relative(&mut self, direction: Direction) -> Result<Vec<DesktopAction>, DesktopError> {
        if !self.layout.focus_relative(direction) {
            return Ok(Vec::new());
        }
        self.reconcile(None)
    }

    fn move_focused(&mut self, direction: Direction) -> Result<Vec<DesktopAction>, DesktopError> {
        if !self.layout.move_focused(direction) {
            return Ok(Vec::new());
        }
        self.reconcile(None)
    }

    fn reconcile(
        &mut self,
        force_configuration: Option<WindowId>,
    ) -> Result<Vec<DesktopAction>, DesktopError> {
        let mut actions = Vec::new();
        self.append_reconcile(&mut actions, force_configuration)?;
        Ok(actions)
    }

    fn append_reconcile(
        &mut self,
        actions: &mut Vec<DesktopAction>,
        force_configuration: Option<WindowId>,
    ) -> Result<(), DesktopError> {
        let fullscreen = self.fullscreen_window();
        for window in &mut self.windows {
            window.options.fullscreen = Some(window.id) == fullscreen;
        }

        let placements = self.effective_placements();
        for placement in &placements {
            let index = self
                .window_index(placement.window_id)
                .ok_or(DesktopError::UnknownWindow)?;
            let logical_size = Size::new(placement.client.width, placement.client.height);
            let old = self.windows[index].configuration;
            let desired = configuration_without_generation(logical_size, self.policy)?;
            let changed = old.is_none_or(|configuration| {
                !same_configuration_except_generation(configuration, desired)
            });
            if changed || force_configuration == Some(placement.window_id) {
                let next_generation = old.map_or(Some(1), |configuration| {
                    configuration.generation.get().checked_add(1)
                });
                let generation =
                    Generation::new(next_generation.ok_or(DesktopError::OutOfResources)?)
                        .ok_or(DesktopError::OutOfResources)?;
                let configuration = SurfaceConfiguration {
                    generation,
                    ..desired
                };
                self.windows[index].configuration = Some(configuration);
                actions.push(DesktopAction::Configure {
                    client_id: self.windows[index].owner,
                    window_id: placement.window_id,
                    configuration,
                });
            }
        }

        let focused = self.focused_window();
        if self.announced_focus != focused {
            if let Some(window_id) = self.announced_focus {
                if let Some(window) = self.window(window_id) {
                    actions.push(DesktopAction::FocusChanged {
                        client_id: window.owner,
                        window_id,
                        focused: false,
                    });
                }
            }
            if let Some(window_id) = focused {
                if let Some(window) = self.window(window_id) {
                    actions.push(DesktopAction::FocusChanged {
                        client_id: window.owner,
                        window_id,
                        focused: true,
                    });
                }
            }
            self.announced_focus = focused;
        }
        actions.push(DesktopAction::SetPlacements { placements });
        Ok(())
    }

    fn effective_placements(&self) -> Vec<WindowPlacement> {
        self.layout
            .placements()
            .into_iter()
            .filter_map(|placement| {
                let window_id = from_layout_window_id(placement.window);
                let window = self.window(window_id)?;
                let fullscreen = self.fullscreen_window() == Some(window_id);
                let decorated = window.options.decorations && !fullscreen;
                let base_client = if decorated {
                    placement.client
                } else {
                    placement.outer
                };
                let client_size = constrain_client_size(
                    LayoutSize::new(base_client.width, base_client.height),
                    window.options.minimum_size,
                    window.options.maximum_size,
                );
                let client = LayoutRect::new(
                    base_client.x,
                    base_client.y,
                    client_size.width,
                    client_size.height,
                );
                Some(WindowPlacement {
                    window_id,
                    outer: placement.outer,
                    client,
                    visible: placement.visible,
                    focused: placement.focused,
                    decorated,
                })
            })
            .collect()
    }

    fn allocate_window_id(&mut self) -> Option<u64> {
        let id = self.next_window_id;
        self.next_window_id = self.next_window_id.checked_add(1)?;
        Some(id)
    }

    fn window_index(&self, window_id: WindowId) -> Option<usize> {
        self.windows
            .iter()
            .position(|window| window.id == window_id)
    }

    fn owned_window_index(&self, client_id: ClientId, window_id: WindowId) -> Option<usize> {
        self.windows
            .iter()
            .position(|window| window.id == window_id && window.owner == client_id)
    }
}

fn validate_output(output: Size, policy: DesktopPolicy) -> Result<(), DesktopError> {
    if output.is_empty() {
        return Err(DesktopError::EmptyOutput);
    }
    if policy.buffer_count < MIN_BUFFER_SLOTS {
        return Err(DesktopError::InvalidBufferCount);
    }
    if policy.default_width.per_mille() == 0 {
        return Err(DesktopError::InvalidColumnWidth);
    }
    configuration_without_generation(output, policy)?;
    Ok(())
}

fn configuration_without_generation(
    logical_size: Size,
    policy: DesktopPolicy,
) -> Result<SurfaceConfiguration, DesktopError> {
    let pixel_size = policy
        .scale
        .scale_size(logical_size)
        .ok_or(DesktopError::OutOfResources)?;
    let stride = policy
        .format
        .minimum_stride(pixel_size.width)
        .ok_or(DesktopError::OutOfResources)?;
    let configuration = SurfaceConfiguration {
        logical_size,
        pixel_size,
        stride,
        format: policy.format,
        scale: policy.scale,
        generation: Generation::new(1).expect("one is non-zero"),
        buffer_count: policy.buffer_count,
    };
    configuration
        .validate()
        .map_err(|_| DesktopError::OutOfResources)?;
    Ok(configuration)
}

fn same_configuration_except_generation(
    left: SurfaceConfiguration,
    right: SurfaceConfiguration,
) -> bool {
    left.logical_size == right.logical_size
        && left.pixel_size == right.pixel_size
        && left.stride == right.stride
        && left.format == right.format
        && left.scale == right.scale
        && left.buffer_count == right.buffer_count
}

fn constrain_client_size(
    available: LayoutSize,
    minimum: Option<Size>,
    maximum: Option<Size>,
) -> LayoutSize {
    let minimum = minimum.unwrap_or(Size::new(1, 1));
    let maximum = maximum.unwrap_or(Size::new(u32::MAX, u32::MAX));
    // A client constraint cannot make content exceed its policy-assigned column.
    // Minimums are honored whenever the available rectangle permits them.
    let width = min(available.width, maximum.width).max(min(minimum.width, available.width));
    let height = min(available.height, maximum.height).max(min(minimum.height, available.height));
    LayoutSize::new(width, height)
}

fn constraints_inverted(minimum: Option<Size>, maximum: Option<Size>) -> bool {
    matches!((minimum, maximum), (Some(minimum), Some(maximum))
        if minimum.width > maximum.width || minimum.height > maximum.height)
}

fn contains(rect: LayoutRect, x: i64, y: i64) -> bool {
    x >= rect.x && y >= rect.y && x < rect.right() && y < rect.bottom()
}

fn failed(client_id: ClientId, request_id: RequestId, code: ServerErrorCode) -> Vec<DesktopAction> {
    alloc::vec![DesktopAction::RequestFailed {
        client_id,
        request_id,
        code,
    }]
}

const fn to_layout_window_id(window_id: WindowId) -> LayoutWindowId {
    LayoutWindowId(window_id.get())
}

fn from_layout_window_id(window_id: LayoutWindowId) -> WindowId {
    WindowId::new(window_id.0).expect("desktop layout IDs are non-zero")
}

const fn to_layout_size(size: Size) -> LayoutSize {
    LayoutSize::new(size.width, size.height)
}

const fn from_layout_size(size: LayoutSize) -> Size {
    Size::new(size.width, size.height)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec};

    use ginkgo_window::{ButtonState, Modifiers, PointerButton, WireEvent};

    use super::*;

    fn client(value: u64) -> ClientId {
        ClientId::new(value).unwrap()
    }

    fn request(value: u64) -> RequestId {
        RequestId::new(value).unwrap()
    }

    fn options(title: &str) -> WindowOptions {
        WindowOptions {
            title: String::from(title),
            preferred_size: Size::new(320, 200),
            ..WindowOptions::default()
        }
    }

    fn create(
        desktop: &mut Desktop,
        owner: ClientId,
        request_value: u64,
        options: WindowOptions,
    ) -> (WindowId, Vec<DesktopAction>) {
        let actions = desktop.handle_request(
            owner,
            WireRequest::CreateWindow {
                protocol_version: PROTOCOL_VERSION,
                request_id: request(request_value),
                options,
            },
        );
        let window_id = actions
            .iter()
            .find_map(|action| match action {
                DesktopAction::WindowCreated { window_id, .. } => Some(*window_id),
                _ => None,
            })
            .unwrap();
        (window_id, actions)
    }

    fn configured(actions: &[DesktopAction], window_id: WindowId) -> SurfaceConfiguration {
        actions
            .iter()
            .find_map(|action| match action {
                DesktopAction::Configure {
                    window_id: configured,
                    configuration,
                    ..
                } if *configured == window_id => Some(*configuration),
                _ => None,
            })
            .unwrap()
    }

    fn request_failed(actions: &[DesktopAction], code: ServerErrorCode) -> bool {
        actions.iter().any(|action| {
            matches!(action, DesktopAction::RequestFailed { code: actual, .. } if *actual == code)
        })
    }

    #[test]
    fn creation_emits_identity_configuration_and_client_only_placement() {
        let mut desktop = Desktop::new(Size::new(1000, 600)).unwrap();
        let (window, actions) = create(&mut desktop, client(1), 1, options("first"));

        assert!(matches!(
            actions.first(),
            Some(DesktopAction::WindowCreated {
                client_id,
                protocol_version,
                request_id,
                window_id,
            }) if *client_id == client(1)
                && *protocol_version == PROTOCOL_VERSION
                && *request_id == request(1)
                && *window_id == window
        ));
        let configuration = configured(&actions, window);
        assert_eq!(configuration.logical_size, Size::new(592, 572));
        assert_eq!(configuration.pixel_size, Size::new(888, 858));
        assert_eq!(configuration.format, PixelFormat::Xrgb8888);
        assert_eq!(configuration.scale, ScaleFactor::new(3, 2).unwrap());
        assert_eq!(configuration.buffer_count, 2);
        assert_eq!(configuration.stride, 3552);

        let placement = desktop.placements()[0];
        assert_eq!(placement.outer, LayoutRect::new(0, 0, 600, 600));
        assert_eq!(placement.client, LayoutRect::new(4, 24, 592, 572));
        assert!(placement.decorated);
        assert_eq!(desktop.window(window).unwrap().options.title, "first");

        let wire_event = match actions.first().unwrap() {
            DesktopAction::WindowCreated {
                protocol_version,
                request_id,
                window_id,
                ..
            } => WireEvent::WindowCreated {
                protocol_version: *protocol_version,
                request_id: *request_id,
                window_id: *window_id,
            },
            action => panic!("expected WindowCreated action, got {action:?}"),
        };
        assert_eq!(
            wire_event,
            WireEvent::WindowCreated {
                protocol_version: PROTOCOL_VERSION,
                request_id: request(1),
                window_id: window,
            }
        );
    }

    #[test]
    fn mismatched_create_version_is_rejected_without_mutating_state() {
        let mut desktop = Desktop::new(Size::new(1000, 600)).unwrap();
        let owner = client(9);
        let create_request = request(1);
        let actions = desktop.handle_request(
            owner,
            WireRequest::CreateWindow {
                protocol_version: PROTOCOL_VERSION.wrapping_add(1),
                request_id: create_request,
                options: options("wrong version"),
            },
        );

        assert_eq!(
            actions,
            vec![DesktopAction::RequestFailed {
                client_id: owner,
                request_id: create_request,
                code: ServerErrorCode::Unsupported,
            }]
        );
        assert_eq!(desktop.windows().len(), 0);
        assert_eq!(desktop.focused_window(), None);
        assert_eq!(desktop.fullscreen_window(), None);
        assert_eq!(desktop.viewport(), 0);
        assert!(desktop.placements().is_empty());

        let (window, actions) = create(&mut desktop, owner, 2, options("supported"));
        assert_eq!(
            window.get(),
            1,
            "a rejected handshake must not consume an ID"
        );
        assert!(matches!(
            actions.first(),
            Some(DesktopAction::WindowCreated {
                protocol_version: PROTOCOL_VERSION,
                ..
            })
        ));
    }

    #[test]
    fn policy_accepts_all_protocol_valid_configurable_buffer_counts() {
        let output = Size::new(1000, 600);
        let mut policy = DesktopPolicy::default();
        policy.buffer_count = MIN_BUFFER_SLOTS - 1;
        assert_eq!(
            Desktop::with_policy(output, policy).unwrap_err(),
            DesktopError::InvalidBufferCount
        );

        policy.buffer_count = MIN_BUFFER_SLOTS + 1;
        let mut desktop = Desktop::with_policy(output, policy).unwrap();
        let (window, actions) = create(&mut desktop, client(1), 1, options("three buffers"));
        let configuration = configured(&actions, window);
        assert_eq!(configuration.buffer_count, MIN_BUFFER_SLOTS + 1);
        assert_eq!(configuration.validate(), Ok(()));

        let present = desktop.handle_request(
            client(1),
            WireRequest::Present {
                request_id: request(2),
                window_id: window,
                generation: configuration.generation,
                buffer_id: BufferId::new(MIN_BUFFER_SLOTS),
                damage: Vec::new(),
            },
        );
        assert!(matches!(
            present.as_slice(),
            [DesktopAction::Present { .. }]
        ));
    }

    #[test]
    fn requested_size_is_remembered_but_actual_size_is_policy_controlled() {
        let mut desktop = Desktop::new(Size::new(1000, 600)).unwrap();
        let (window, initial) = create(&mut desktop, client(1), 1, options("sized"));
        let first_generation = configured(&initial, window).generation;

        let actions = desktop.handle_request(
            client(1),
            WireRequest::RequestSize {
                request_id: request(2),
                window_id: window,
                preferred_size: Size::new(111, 99),
            },
        );
        let actual = configured(&actions, window);
        assert_eq!(
            desktop.window(window).unwrap().options.preferred_size,
            Size::new(111, 99)
        );
        assert_eq!(actual.logical_size, Size::new(592, 572));
        assert!(actual.generation > first_generation);

        let actions = desktop.handle_request(
            client(1),
            WireRequest::SetMaximumSize {
                request_id: request(3),
                window_id: window,
                maximum_size: Some(Size::new(400, 300)),
            },
        );
        assert_eq!(
            configured(&actions, window).logical_size,
            Size::new(400, 300)
        );
        assert_eq!(
            desktop.placements()[0].client.size(),
            LayoutSize::new(400, 300)
        );

        let actions = desktop.handle_request(
            client(1),
            WireRequest::SetMinimumSize {
                request_id: request(4),
                window_id: window,
                minimum_size: Some(Size::new(500, 200)),
            },
        );
        assert!(request_failed(&actions, ServerErrorCode::InvalidRequest));
        assert_eq!(desktop.window(window).unwrap().options.minimum_size, None);
    }

    #[test]
    fn undecorated_clients_receive_the_full_column_as_client_size() {
        let mut desktop = Desktop::new(Size::new(1000, 600)).unwrap();
        let mut undecorated = options("plain");
        undecorated.decorations = false;
        let (window, actions) = create(&mut desktop, client(1), 1, undecorated);

        assert_eq!(
            configured(&actions, window).logical_size,
            Size::new(600, 600)
        );
        let placement = desktop.placements()[0];
        assert_eq!(placement.client, placement.outer);
        assert!(!placement.decorated);
    }

    #[test]
    fn ownership_is_enforced_without_leaking_other_clients_windows() {
        let mut desktop = Desktop::new(Size::new(1000, 600)).unwrap();
        let (window, initial) = create(&mut desktop, client(1), 1, options("owned"));
        let configuration = configured(&initial, window);

        let attempts = [
            WireRequest::DestroyWindow {
                request_id: request(10),
                window_id: window,
            },
            WireRequest::RequestSize {
                request_id: request(11),
                window_id: window,
                preferred_size: Size::new(200, 100),
            },
            WireRequest::SetMinimumSize {
                request_id: request(12),
                window_id: window,
                minimum_size: Some(Size::new(10, 10)),
            },
            WireRequest::SetMaximumSize {
                request_id: request(13),
                window_id: window,
                maximum_size: Some(Size::new(500, 500)),
            },
            WireRequest::SetFullscreen {
                request_id: request(14),
                window_id: window,
                fullscreen: true,
            },
            WireRequest::ToggleFullscreen {
                request_id: request(15),
                window_id: window,
            },
            WireRequest::Present {
                request_id: request(16),
                window_id: window,
                generation: configuration.generation,
                buffer_id: BufferId::new(0),
                damage: Vec::new(),
            },
        ];
        for attempt in attempts {
            let actions = desktop.handle_request(client(2), attempt);
            assert!(request_failed(&actions, ServerErrorCode::WindowGone));
        }
        assert_eq!(desktop.windows().len(), 1);
        assert_eq!(desktop.window(window).unwrap().owner, client(1));
        assert_eq!(desktop.fullscreen_window(), None);
    }

    #[test]
    fn fullscreen_uses_layout_restore_for_order_width_focus_and_viewport() {
        let mut desktop = Desktop::new(Size::new(1000, 600)).unwrap();
        let (a, _) = create(&mut desktop, client(1), 1, options("a"));
        let (b, _) = create(&mut desktop, client(1), 2, options("b"));
        let (_c, _) = create(&mut desktop, client(1), 3, options("c"));
        desktop.focus_window(b).unwrap();
        desktop
            .set_window_width(b, Proportion::new(750).unwrap())
            .unwrap();
        let before = desktop.placements();
        let viewport = desktop.viewport();

        let entered = desktop.handle_request(
            client(1),
            WireRequest::SetFullscreen {
                request_id: request(4),
                window_id: b,
                fullscreen: true,
            },
        );
        assert_eq!(desktop.fullscreen_window(), Some(b));
        assert_eq!(
            desktop.placements(),
            vec![WindowPlacement {
                window_id: b,
                outer: LayoutRect::new(0, 0, 1000, 600),
                client: LayoutRect::new(0, 0, 1000, 600),
                visible: Some(LayoutRect::new(0, 0, 1000, 600)),
                focused: true,
                decorated: false,
            }]
        );
        assert_eq!(configured(&entered, b).logical_size, Size::new(1000, 600));

        let exited = desktop.handle_request(
            client(1),
            WireRequest::ToggleFullscreen {
                request_id: request(5),
                window_id: b,
            },
        );
        assert_eq!(desktop.fullscreen_window(), None);
        assert_eq!(desktop.focused_window(), Some(b));
        assert_eq!(desktop.viewport(), viewport);
        assert_eq!(desktop.placements(), before);
        assert_eq!(configured(&exited, b).logical_size, Size::new(742, 572));
        assert!(desktop
            .placements()
            .iter()
            .any(|placement| placement.window_id == a));
    }

    #[test]
    fn present_is_routed_only_for_the_current_generation_and_buffer_pool() {
        let mut desktop = Desktop::new(Size::new(800, 480)).unwrap();
        let (window, initial) = create(&mut desktop, client(7), 1, options("present"));
        let configuration = configured(&initial, window);
        let damage = vec![Rect::new(Point::new(2, 3), Size::new(10, 20))];

        let actions = desktop.handle_request(
            client(7),
            WireRequest::Present {
                request_id: request(2),
                window_id: window,
                generation: configuration.generation,
                buffer_id: BufferId::new(1),
                damage: damage.clone(),
            },
        );
        assert_eq!(
            actions,
            vec![DesktopAction::Present {
                client_id: client(7),
                request_id: request(2),
                window_id: window,
                generation: configuration.generation,
                buffer_id: BufferId::new(1),
                damage,
            }]
        );

        let stale = desktop.handle_request(
            client(7),
            WireRequest::Present {
                request_id: request(3),
                window_id: window,
                generation: Generation::new(configuration.generation.get() + 1).unwrap(),
                buffer_id: BufferId::new(0),
                damage: Vec::new(),
            },
        );
        assert!(request_failed(&stale, ServerErrorCode::InvalidRequest));
        let invalid_buffer = desktop.handle_request(
            client(7),
            WireRequest::Present {
                request_id: request(4),
                window_id: window,
                generation: configuration.generation,
                buffer_id: BufferId::new(2),
                damage: Vec::new(),
            },
        );
        assert!(request_failed(
            &invalid_buffer,
            ServerErrorCode::InvalidRequest
        ));
    }

    #[test]
    fn multiple_clients_get_unique_ids_and_correctly_routed_actions() {
        let mut desktop = Desktop::new(Size::new(1000, 600)).unwrap();
        let (first, first_actions) = create(&mut desktop, client(11), 1, options("one"));
        let (second, second_actions) = create(&mut desktop, client(22), 1, options("two"));
        assert_ne!(first, second);
        assert_eq!(desktop.window(first).unwrap().owner, client(11));
        assert_eq!(desktop.window(second).unwrap().owner, client(22));
        assert!(matches!(
            first_actions.first(),
            Some(DesktopAction::WindowCreated { client_id, .. }) if *client_id == client(11)
        ));
        assert!(matches!(
            second_actions.first(),
            Some(DesktopAction::WindowCreated { client_id, .. }) if *client_id == client(22)
        ));

        let destroyed = desktop.handle_request(
            client(11),
            WireRequest::DestroyWindow {
                request_id: request(2),
                window_id: first,
            },
        );
        assert!(matches!(
            destroyed.first(),
            Some(DesktopAction::DestroyWindow { client_id, window_id, .. })
                if *client_id == client(11) && *window_id == first
        ));
        assert!(desktop.window(first).is_none());
        assert!(desktop.window(second).is_some());
    }

    #[test]
    fn focus_move_width_output_and_input_are_runtime_independent_actions() {
        let mut desktop = Desktop::new(Size::new(1000, 600)).unwrap();
        let (first, _) = create(&mut desktop, client(1), 1, options("one"));
        let (second, _) = create(&mut desktop, client(2), 2, options("two"));
        desktop.focus_left().unwrap();
        assert_eq!(desktop.focused_window(), Some(first));
        desktop.move_focused_right().unwrap();
        assert_eq!(desktop.placements()[1].window_id, first);
        desktop
            .set_window_width(first, Proportion::new(500).unwrap())
            .unwrap();

        let output_actions = desktop
            .output_changed(Size::new(1200, 700), ScaleFactor::new(5, 4).unwrap())
            .unwrap();
        let configuration = configured(&output_actions, first);
        assert_eq!(configuration.scale, ScaleFactor::new(5, 4).unwrap());
        assert_eq!(configuration.logical_size.height, 672);

        let placement = desktop
            .placements()
            .into_iter()
            .find(|placement| placement.window_id == first)
            .unwrap();
        let pointer = desktop
            .pointer_input(
                Point::new(
                    (placement.client.x + 10) as i32,
                    (placement.client.y + 12) as i32,
                ),
                PointerEventKind::Button {
                    button: PointerButton::Primary,
                    state: ButtonState::Pressed,
                },
            )
            .unwrap();
        assert!(matches!(
            pointer.last(),
            Some(DesktopAction::ForwardPointer {
                client_id,
                window_id,
                event: PointerEvent { position, .. },
            }) if *client_id == client(1)
                && *window_id == first
                && *position == Point::new(10, 12)
        ));

        let keyboard = KeyboardEvent {
            usage: 4,
            state: ButtonState::Pressed,
            repeat: false,
            modifiers: Modifiers::default(),
        };
        assert_eq!(
            desktop.keyboard_input(keyboard),
            vec![DesktopAction::ForwardKeyboard {
                client_id: client(1),
                window_id: first,
                event: keyboard,
            }]
        );
        assert_ne!(first, second);
    }

    trait RectSize {
        fn size(self) -> LayoutSize;
    }

    impl RectSize for LayoutRect {
        fn size(self) -> LayoutSize {
            LayoutSize::new(self.width, self.height)
        }
    }
}
