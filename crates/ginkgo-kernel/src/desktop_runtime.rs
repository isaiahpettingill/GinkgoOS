//! Kernel-side broker for the protected userspace desktop runtime.
//!
//! The broker owns the privileged handles for every surface pool. The desktop
//! service receives only writable, mappable shared-memory capabilities; frame
//! submission and manager authority remain in the kernel. Packet processing and
//! composition are deliberately separate so callers control when framebuffer
//! writes occur.

use alloc::vec::Vec;

use ginkgo_desktop::{
    AttachmentIndex, ClientId, PresentationResult, RuntimeMessage, RuntimePacket, RuntimePlacement,
    RuntimeSender, RuntimeValidationError,
};
use ginkgo_graphics::FramebufferWriter;
use ginkgo_ipc::ginkgo_sysapi::{CHANNEL_MAX_BYTES, CHANNEL_MAX_HANDLES};
use ginkgo_ipc::{
    channel_create_between, handle_move_between, Handle, HandleDisposition,
    HandleOperationDisposition, HandleTable, IpcError, ObjectType, Rights, WindowPresentation,
    WindowRelease, CHANNEL_QUEUE_CAPACITY,
};
use ginkgo_window::{
    BufferId, ConfigurationError, Generation, KeyboardEvent, Point as InputPoint, PointerEventKind,
    RequestId, ServerErrorCode, SurfaceConfiguration, WindowId,
};

use crate::{
    compositor::{
        Compositor, CompositorError, CompositorMetrics, Rect, SurfaceDamage, WindowConfig,
        WindowPlacement as CompositorPlacement, DAMAGE_RECT_CAPACITY,
    },
    shared_memory::SharedMemoryFactory,
};

/// Rights installed on a surface-memory attachment received by the desktop.
///
/// `TRANSFER` lets the desktop forward the memory to its client. `MANAGE` and
/// `DUPLICATE` are intentionally absent, so neither endpoint can manufacture a
/// privileged window pool or retain extra aliases while forwarding it.
pub const DESKTOP_SURFACE_RIGHTS: Rights = Rights::from_bits_retain(
    Rights::READ.bits() | Rights::WRITE.bits() | Rights::MAP.bits() | Rights::TRANSFER.bits(),
);

/// Rights installed on a newly connected client channel transferred to the
/// desktop service.
pub const DESKTOP_CLIENT_CHANNEL_RIGHTS: Rights =
    Rights::from_bits_retain(Rights::READ.bits() | Rights::WRITE.bits() | Rights::WAIT.bits());

/// A broker protocol, capability, lifecycle, or composition failure.
#[derive(Debug)]
pub enum DesktopBrokerError {
    Ipc(IpcError),
    Decode(ginkgo_desktop::RuntimeDecodeError),
    Encode(ginkgo_desktop::RuntimeEncodeError),
    Validation(RuntimeValidationError),
    Configuration(ConfigurationError),
    Compositor(CompositorError),
    RuntimeChannelType(ObjectType),
    RuntimeChannelRights {
        required: Rights,
        actual: Rights,
    },
    RuntimeChannelAttachment,
    DuplicateClient(ClientId),
    UnknownClient(ClientId),
    UnknownWindow(WindowId),
    WindowOwnerMismatch {
        window_id: WindowId,
        expected: ClientId,
        actual: ClientId,
    },
    UnexpectedGeneration {
        window_id: WindowId,
        expected: u32,
        actual: u32,
    },
    PendingComposition(WindowId),
    WindowNotPlaced(WindowId),
    PlacementSizeMismatch {
        window_id: WindowId,
        expected_width: u32,
        expected_height: u32,
        actual_width: u32,
        actual_height: u32,
    },
    DamageOutsideSurface(WindowId),
    DuplicatePresentRequest(RequestId),
    UnknownPresentationSerial {
        window_id: WindowId,
        serial: u64,
    },
    ArithmeticOverflow,
    OutOfMemory,
}

impl From<IpcError> for DesktopBrokerError {
    fn from(error: IpcError) -> Self {
        Self::Ipc(error)
    }
}

impl From<ginkgo_desktop::RuntimeDecodeError> for DesktopBrokerError {
    fn from(error: ginkgo_desktop::RuntimeDecodeError) -> Self {
        Self::Decode(error)
    }
}

impl From<ginkgo_desktop::RuntimeEncodeError> for DesktopBrokerError {
    fn from(error: ginkgo_desktop::RuntimeEncodeError) -> Self {
        Self::Encode(error)
    }
}

impl From<ConfigurationError> for DesktopBrokerError {
    fn from(error: ConfigurationError) -> Self {
        Self::Configuration(error)
    }
}

impl From<CompositorError> for DesktopBrokerError {
    fn from(error: CompositorError) -> Self {
        Self::Compositor(error)
    }
}

/// Observable result of processing one desktop-service packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DesktopRuntimeEvent {
    ServiceReady,
    LauncherVisibility(bool),
    LaunchRequested {
        requester: ClientId,
        app_id: alloc::string::String,
        startup: Handle,
    },
    SurfaceConfigured {
        client_id: ClientId,
        window_id: WindowId,
        generation: Generation,
    },
    WindowDestroyed {
        client_id: ClientId,
        window_id: WindowId,
    },
    PlacementsChanged {
        window_count: usize,
        focused_window: Option<WindowId>,
        focused_client: Option<ClientId>,
    },
    PresentationQueued {
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
        generation: Generation,
        buffer_id: BufferId,
        presentation_serial: u64,
    },
    PresentationRejected {
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
        generation: Generation,
        buffer_id: BufferId,
        code: ServerErrorCode,
    },
}

/// Default estimated display period used until a display backend supplies timing.
pub const DEFAULT_REFRESH_INTERVAL_NS: u64 = 16_666_667;

/// Confidence assigned to timing information for the active output.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DisplayTimingConfidence {
    /// Timing is inferred from a configured or conventional refresh rate.
    #[default]
    Estimated,
    /// Timing was measured from display completion events.
    Measured,
    /// Timing is synchronized to deadlines reported by the display hardware.
    HardwareSynchronized,
}

/// Controls whether framebuffer publication follows the frame clock.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FramePacingMode {
    /// Coalesce work and publish no more than once per refresh interval.
    #[default]
    Paced,
    /// Publish pending work on every call. Intended for tests and debugging.
    Immediate,
}

/// Display timing state used by the desktop broker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayFrameClock {
    refresh_interval_ns: u64,
    next_deadline_ns: Option<u64>,
    timing_confidence: DisplayTimingConfidence,
    mode: FramePacingMode,
}

impl DisplayFrameClock {
    /// Creates an estimated 60 Hz paced clock. The first deadline is selected
    /// from the first call to [`DesktopBroker::compose_due`].
    pub const fn estimated_60_hz() -> Self {
        Self {
            refresh_interval_ns: DEFAULT_REFRESH_INTERVAL_NS,
            next_deadline_ns: None,
            timing_confidence: DisplayTimingConfidence::Estimated,
            mode: FramePacingMode::Paced,
        }
    }

    /// Creates a paced clock, returning `None` for a zero refresh interval.
    pub const fn new(
        refresh_interval_ns: u64,
        timing_confidence: DisplayTimingConfidence,
    ) -> Option<Self> {
        if refresh_interval_ns == 0 {
            return None;
        }
        Some(Self {
            refresh_interval_ns,
            next_deadline_ns: None,
            timing_confidence,
            mode: FramePacingMode::Paced,
        })
    }

    pub const fn refresh_interval_ns(&self) -> u64 {
        self.refresh_interval_ns
    }

    pub const fn next_deadline_ns(&self) -> Option<u64> {
        self.next_deadline_ns
    }

    pub const fn timing_confidence(&self) -> DisplayTimingConfidence {
        self.timing_confidence
    }

    pub const fn mode(&self) -> FramePacingMode {
        self.mode
    }

    /// Changes the refresh period and reselects the deadline on the next paced call.
    /// Returns `false` and leaves the clock unchanged for a zero interval.
    pub fn set_refresh_interval_ns(&mut self, refresh_interval_ns: u64) -> bool {
        if refresh_interval_ns == 0 {
            return false;
        }
        self.refresh_interval_ns = refresh_interval_ns;
        self.next_deadline_ns = None;
        true
    }

    pub fn set_timing_confidence(&mut self, confidence: DisplayTimingConfidence) {
        self.timing_confidence = confidence;
    }

    /// Changes pacing mode. Returning to paced mode selects a fresh deadline.
    pub fn set_mode(&mut self, mode: FramePacingMode) {
        if self.mode != mode {
            self.mode = mode;
            self.next_deadline_ns = None;
        }
    }

    /// Selects `now_ns` as the next paced deadline.
    pub fn reset(&mut self, now_ns: u64) {
        self.next_deadline_ns = Some(now_ns);
    }

    fn select(&mut self, now_ns: u64) -> FrameDeadlineSelection {
        if self.mode == FramePacingMode::Immediate {
            return FrameDeadlineSelection {
                due: true,
                deadline_ns: None,
                late: false,
                missed_deadlines: 0,
            };
        }

        let deadline_ns = self.next_deadline_ns.unwrap_or(now_ns);
        if now_ns < deadline_ns {
            return FrameDeadlineSelection {
                due: false,
                deadline_ns: Some(deadline_ns),
                late: false,
                missed_deadlines: 0,
            };
        }

        let elapsed = now_ns.saturating_sub(deadline_ns);
        let missed_deadlines = elapsed / self.refresh_interval_ns;
        let steps = u128::from(missed_deadlines) + 1;
        let next = u128::from(deadline_ns)
            .saturating_add(steps.saturating_mul(u128::from(self.refresh_interval_ns)))
            .min(u128::from(u64::MAX)) as u64;
        self.next_deadline_ns = Some(next);
        FrameDeadlineSelection {
            due: true,
            deadline_ns: Some(deadline_ns),
            late: now_ns > deadline_ns,
            missed_deadlines,
        }
    }
}

impl Default for DisplayFrameClock {
    fn default() -> Self {
        Self::estimated_60_hz()
    }
}

#[derive(Clone, Copy)]
struct FrameDeadlineSelection {
    due: bool,
    deadline_ns: Option<u64>,
    late: bool,
    missed_deadlines: u64,
}

/// Broker counters. Duration fields are cumulative nanoseconds reported through
/// [`DesktopBroker::record_frame_durations`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DesktopBrokerMetrics {
    pub submitted_frames: u64,
    pub composed_frames: u64,
    pub coalesced_frames: u64,
    pub dropped_frames: u64,
    pub late_frames: u64,
    pub displayed_frames: u64,
    pub missed_deadlines: u64,
    pub composition_duration_ns: u64,
    pub publication_duration_ns: u64,
    pub compositor: CompositorMetrics,
}

/// Result of one frame-clock composition attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameCompositionOutcome {
    pub due: bool,
    pub deadline_ns: Option<u64>,
    pub next_deadline_ns: Option<u64>,
    pub composed_windows: usize,
    pub late: bool,
    pub missed_deadlines: u64,
}

/// Result of successfully composing one pending frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositionOutcome {
    pub client_id: ClientId,
    pub request_id: RequestId,
    pub window_id: WindowId,
    pub generation: Generation,
    pub buffer_id: BufferId,
    pub presentation_serial: u64,
    pub released_request_id: Option<RequestId>,
}

#[derive(Clone, Copy)]
struct SubmissionDamage {
    rects: [Rect; DAMAGE_RECT_CAPACITY],
    len: usize,
}

impl SubmissionDamage {
    const FULL: Self = Self {
        rects: [Rect::new(0, 0, 0, 0); DAMAGE_RECT_CAPACITY],
        len: 0,
    };

    fn as_slice(&self) -> &[Rect] {
        &self.rects[..self.len]
    }

    fn union(self, other: Self) -> Self {
        if self.len == 0 || other.len == 0 || self.len + other.len > DAMAGE_RECT_CAPACITY {
            return Self::FULL;
        }
        let mut combined = self;
        for rect in &other.rects[..other.len] {
            combined.rects[combined.len] = *rect;
            combined.len += 1;
        }
        combined
    }
}

#[derive(Clone, Copy)]
struct Submission {
    serial: u64,
    request_id: RequestId,
    buffer_id: BufferId,
    damage: SubmissionDamage,
}

struct QueuedPresentation {
    presentation: WindowPresentation,
    damage: SubmissionDamage,
    coalesced_release: Option<ReleaseNotice>,
}

struct BrokerWindow {
    client_id: ClientId,
    window_id: WindowId,
    configuration: SurfaceConfiguration,
    memory: Handle,
    client: Handle,
    manager: Handle,
    placement: Option<RuntimePlacement>,
    submissions: Vec<Submission>,
    transition: Option<PoolTransition>,
}

struct PoolTransition {
    configuration: SurfaceConfiguration,
    memory: Handle,
    client: Handle,
    manager: Handle,
    placement: Option<RuntimePlacement>,
    submissions: Vec<Submission>,
    compositor: Option<WindowConfig>,
}

#[derive(Clone, Copy)]
struct ReleaseNotice {
    client_id: ClientId,
    window_id: WindowId,
    generation: Generation,
    buffer_id: BufferId,
    request_id: RequestId,
}

#[derive(Clone, Copy)]
struct PresentResultNotice {
    client_id: ClientId,
    request_id: RequestId,
    window_id: WindowId,
    generation: Generation,
    buffer_id: BufferId,
    result: PresentationResult,
}

#[derive(Clone, Copy)]
enum DeferredNotice {
    Release(ReleaseNotice),
    PresentResult(PresentResultNotice),
}

/// Privileged kernel endpoint for one userspace desktop service.
///
/// All surface shared memory, protected client endpoints, and manager endpoints
/// live in `handles`. The compositor only receives manager handles from this
/// table. Call [`Self::poll_desktop`] to process protocol traffic and call
/// [`Self::compose_pending`] or [`Self::redraw`] explicitly when framebuffer
/// access is available.
pub struct DesktopBroker {
    handles: HandleTable,
    channel: Handle,
    compositor: Compositor,
    clients: Vec<ClientId>,
    windows: Vec<BrokerWindow>,
    service_ready: bool,
    launcher_visible: bool,
    focused_window: Option<WindowId>,
    frame_clock: DisplayFrameClock,
    metrics: DesktopBrokerMetrics,
    frame_now_ns: u64,
    deferred_notices: Vec<DeferredNotice>,
    deferred_notice_bound: usize,
    outbound_bytes: [u8; CHANNEL_MAX_BYTES],
}

impl DesktopBroker {
    /// Takes ownership of an existing broker handle table and runtime channel.
    pub fn new(handles: HandleTable, channel: Handle) -> Result<Self, DesktopBrokerError> {
        let object_type = handles.object_type(channel)?;
        if object_type != ObjectType::Channel {
            return Err(DesktopBrokerError::RuntimeChannelType(object_type));
        }
        let required = Rights::READ | Rights::WRITE;
        let actual = handles.handle_rights(channel)?;
        if !actual.contains(required) {
            return Err(DesktopBrokerError::RuntimeChannelRights { required, actual });
        }
        let mut deferred_notices = Vec::new();
        deferred_notices
            .try_reserve_exact(CHANNEL_QUEUE_CAPACITY.saturating_mul(2))
            .map_err(|_| DesktopBrokerError::OutOfMemory)?;
        Ok(Self {
            handles,
            channel,
            compositor: Compositor::new(),
            clients: Vec::new(),
            windows: Vec::new(),
            service_ready: false,
            launcher_visible: false,
            focused_window: None,
            frame_clock: DisplayFrameClock::estimated_60_hz(),
            metrics: DesktopBrokerMetrics::default(),
            frame_now_ns: 0,
            deferred_notices,
            deferred_notice_bound: CHANNEL_QUEUE_CAPACITY.saturating_mul(2),
            outbound_bytes: [0; CHANNEL_MAX_BYTES],
        })
    }

    /// Creates a runtime channel between a new broker and `desktop_handles`.
    ///
    /// The returned handle is the desktop service's endpoint in
    /// `desktop_handles`; the broker retains the opposite endpoint.
    pub fn create(desktop_handles: &mut HandleTable) -> Result<(Self, Handle), DesktopBrokerError> {
        let mut broker_handles = HandleTable::new();
        let (broker_channel, desktop_channel) =
            channel_create_between(&mut broker_handles, desktop_handles)?;
        Ok((Self::new(broker_handles, broker_channel)?, desktop_channel))
    }

    pub const fn channel(&self) -> Handle {
        self.channel
    }

    pub fn handles(&self) -> &HandleTable {
        &self.handles
    }

    /// Exposes the broker table for kernel integration such as creating a channel
    /// endpoint before passing it to [`Self::send_client_connected`].
    pub fn handles_mut(&mut self) -> &mut HandleTable {
        &mut self.handles
    }

    pub fn compositor(&self) -> &Compositor {
        &self.compositor
    }

    pub const fn frame_clock(&self) -> &DisplayFrameClock {
        &self.frame_clock
    }

    pub fn frame_clock_mut(&mut self) -> &mut DisplayFrameClock {
        &mut self.frame_clock
    }

    pub fn set_frame_pacing_mode(&mut self, mode: FramePacingMode) {
        self.frame_clock.set_mode(mode);
    }

    /// Supplies the monotonic time used when a new pending epoch begins.
    pub fn set_frame_time(&mut self, now_ns: u64) {
        self.frame_now_ns = now_ns;
    }

    pub fn next_presentation_deadline_ns(&self) -> Option<u64> {
        self.windows
            .iter()
            .any(|window| self.handles.window_manager_pending(window.manager).is_ok())
            .then(|| self.frame_clock.next_deadline_ns())
            .flatten()
    }

    /// Returns whether pending work should be published at `now_ns`.
    pub fn presentation_due(&mut self, now_ns: u64) -> bool {
        let pending = self
            .windows
            .iter()
            .any(|window| self.handles.window_manager_pending(window.manager).is_ok());
        if !pending {
            return false;
        }
        self.frame_clock.mode() == FramePacingMode::Immediate
            || self
                .frame_clock
                .next_deadline_ns()
                .is_none_or(|deadline| now_ns >= deadline)
    }

    /// Returns broker counters with a current snapshot of compositor counters.
    pub fn metrics(&self) -> DesktopBrokerMetrics {
        DesktopBrokerMetrics {
            compositor: self.compositor.metrics(),
            ..self.metrics
        }
    }

    /// Adds externally measured composition and framebuffer publication time.
    /// The broker takes timestamps for pacing but does not own a monotonic clock.
    pub fn record_frame_durations(
        &mut self,
        composition_duration_ns: u64,
        publication_duration_ns: u64,
    ) {
        self.metrics.composition_duration_ns = self
            .metrics
            .composition_duration_ns
            .saturating_add(composition_duration_ns);
        self.metrics.publication_duration_ns = self
            .metrics
            .publication_duration_ns
            .saturating_add(publication_duration_ns);
    }

    pub const fn service_ready(&self) -> bool {
        self.service_ready
    }

    pub const fn launcher_visible(&self) -> bool {
        self.launcher_visible
    }

    pub const fn focused_window(&self) -> Option<WindowId> {
        self.focused_window
    }

    pub fn window_count(&self) -> usize {
        self.windows.len()
    }

    pub fn window_configuration(&self, window_id: WindowId) -> Option<SurfaceConfiguration> {
        self.window_index(window_id)
            .map(|index| self.windows[index].configuration)
    }

    pub fn owns_client(&self, client_id: ClientId) -> bool {
        self.clients.contains(&client_id)
    }

    /// Reads and processes at most one packet from the desktop service.
    pub fn poll_desktop(
        &mut self,
        shared_memory: &mut SharedMemoryFactory<'_, '_>,
    ) -> Result<Option<DesktopRuntimeEvent>, DesktopBrokerError> {
        self.flush_deferred_notices()?;
        let mut bytes = [0_u8; CHANNEL_MAX_BYTES];
        let mut attachments = [Handle::INVALID; CHANNEL_MAX_HANDLES];
        let info = match self
            .handles
            .channel_read(self.channel, &mut bytes, &mut attachments)
        {
            Ok(info) => info,
            Err(IpcError::ShouldWait) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let byte_count = info.byte_count as usize;
        let handle_count = usize::from(info.handle_count);
        self.handle_desktop_bytes(
            &bytes[..byte_count],
            &attachments[..handle_count],
            shared_memory,
        )
        .map(Some)
    }

    /// Decodes, validates, and processes one desktop-service channel payload.
    ///
    /// Attachments have already entered the broker table after a channel read.
    /// This method closes every supplied attachment on both success and failure;
    /// currently every valid desktop-to-kernel message requires zero handles.
    pub fn handle_desktop_bytes(
        &mut self,
        bytes: &[u8],
        attachments: &[Handle],
        shared_memory: &mut SharedMemoryFactory<'_, '_>,
    ) -> Result<DesktopRuntimeEvent, DesktopBrokerError> {
        let packet =
            match RuntimePacket::decode(bytes, RuntimeSender::DesktopService, attachments.len()) {
                Ok(packet) => packet,
                Err(error) => {
                    self.close_attachments(attachments);
                    return Err(error.into());
                }
            };
        self.handle_desktop_packet(packet, attachments, shared_memory)
    }

    /// Validates and processes an already-decoded desktop-service packet.
    pub fn handle_desktop_packet(
        &mut self,
        packet: RuntimePacket,
        attachments: &[Handle],
        shared_memory: &mut SharedMemoryFactory<'_, '_>,
    ) -> Result<DesktopRuntimeEvent, DesktopBrokerError> {
        if let Err(error) = packet.validate(RuntimeSender::DesktopService, attachments.len()) {
            self.close_attachments(attachments);
            return Err(DesktopBrokerError::Validation(error));
        }
        if let RuntimeMessage::LaunchProgram {
            requester,
            app_id,
            startup_attachment,
        } = packet.message
        {
            let startup = attachments[usize::from(startup_attachment.get())];
            let object_type = self.handles.object_type(startup)?;
            if object_type != ObjectType::Channel {
                self.close_attachments(attachments);
                return Err(DesktopBrokerError::RuntimeChannelType(object_type));
            }
            let required = Rights::READ | Rights::WRITE | Rights::WAIT | Rights::TRANSFER;
            let actual = self.handles.handle_rights(startup)?;
            if !actual.contains(required) {
                self.close_attachments(attachments);
                return Err(DesktopBrokerError::RuntimeChannelRights { required, actual });
            }
            return Ok(DesktopRuntimeEvent::LaunchRequested {
                requester,
                app_id,
                startup,
            });
        }

        self.close_attachments(attachments);
        match packet.message {
            RuntimeMessage::ServiceReady { .. } => {
                self.service_ready = true;
                Ok(DesktopRuntimeEvent::ServiceReady)
            }
            RuntimeMessage::LauncherVisibility { visible } => {
                self.launcher_visible = visible;
                Ok(DesktopRuntimeEvent::LauncherVisibility(visible))
            }
            RuntimeMessage::Configure {
                client_id,
                window_id,
                configuration,
            } => self.configure(client_id, window_id, configuration, shared_memory),
            RuntimeMessage::DestroyWindow {
                client_id,
                window_id,
            } => self.destroy_window(client_id, window_id),
            RuntimeMessage::SetPlacements { placements } => self.set_placements(placements),
            RuntimeMessage::Present {
                client_id,
                request_id,
                window_id,
                generation,
                buffer_id,
                damage,
            } => self.present(
                client_id, request_id, window_id, generation, buffer_id, &damage,
            ),
            RuntimeMessage::LaunchProgram { .. } => {
                unreachable!("launch packets return before attachment cleanup")
            }
            _ => unreachable!("validated desktop packet had a kernel-only message"),
        }
    }

    /// Sends one validated kernel-originated packet without attachments.
    pub fn send_kernel_packet(&mut self, packet: RuntimePacket) -> Result<(), DesktopBrokerError> {
        packet
            .validate(RuntimeSender::KernelBroker, 0)
            .map_err(DesktopBrokerError::Validation)?;
        let bytes = packet.encode_validated_into(
            RuntimeSender::KernelBroker,
            0,
            &mut self.outbound_bytes,
        )?;
        self.handles.channel_write(self.channel, bytes, &[])?;
        Ok(())
    }

    pub fn send_toggle_launcher(&mut self) -> Result<(), DesktopBrokerError> {
        self.send_kernel_packet(RuntimePacket::new(RuntimeMessage::ToggleLauncher))
    }

    pub fn send_close_all_windows(&mut self) -> Result<(), DesktopBrokerError> {
        self.send_kernel_packet(RuntimePacket::new(RuntimeMessage::CloseAllWindows))
    }

    pub fn send_pointer_input(
        &mut self,
        position: InputPoint,
        kind: PointerEventKind,
    ) -> Result<(), DesktopBrokerError> {
        self.send_kernel_packet(RuntimePacket::new(RuntimeMessage::PointerInput {
            position,
            kind,
        }))
    }

    pub fn send_keyboard_input(&mut self, event: KeyboardEvent) -> Result<(), DesktopBrokerError> {
        self.send_kernel_packet(RuntimePacket::new(RuntimeMessage::KeyboardInput { event }))
    }

    /// Transfers a broker-owned client channel to the desktop with attenuated
    /// read/write/wait rights and announces its stable client identity.
    pub fn send_client_connected(
        &mut self,
        client_id: ClientId,
        client_channel: Handle,
    ) -> Result<(), DesktopBrokerError> {
        if self.clients.contains(&client_id) {
            return Err(DesktopBrokerError::DuplicateClient(client_id));
        }
        if client_channel == self.channel {
            return Err(DesktopBrokerError::RuntimeChannelAttachment);
        }
        let object_type = self.handles.object_type(client_channel)?;
        if object_type != ObjectType::Channel {
            return Err(DesktopBrokerError::RuntimeChannelType(object_type));
        }
        self.clients
            .try_reserve(1)
            .map_err(|_| DesktopBrokerError::OutOfMemory)?;

        let packet = RuntimePacket::new(RuntimeMessage::ClientConnected {
            client_id,
            channel_attachment: AttachmentIndex::new(0),
        });
        let bytes = packet.encode_validated(RuntimeSender::KernelBroker, 1)?;
        self.handles.channel_write_with_dispositions(
            self.channel,
            &bytes,
            &[HandleDisposition::new(
                client_channel,
                DESKTOP_CLIENT_CHANNEL_RIGHTS,
            )],
        )?;
        self.clients.push(client_id);
        Ok(())
    }

    /// Creates a client/server channel pair, transfers the server endpoint to
    /// the desktop, and returns the client endpoint in `client_handles`.
    pub fn connect_client(
        &mut self,
        client_id: ClientId,
        client_handles: &mut HandleTable,
    ) -> Result<Handle, DesktopBrokerError> {
        let (server, client) = channel_create_between(&mut self.handles, client_handles)?;
        if let Err(error) = self.send_client_connected(client_id, server) {
            let _ = self.handles.handle_close(server);
            let _ = client_handles.handle_close(client);
            return Err(error);
        }
        Ok(client)
    }

    /// Closes a broker-owned startup channel after a rejected launch.
    pub fn close_startup_channel(&mut self, startup: Handle) {
        let _ = self.handles.handle_close(startup);
    }

    /// Moves a broker-owned startup channel into a newly created process.
    pub fn move_startup_channel(
        &mut self,
        startup: Handle,
        destination: &mut HandleTable,
    ) -> Result<Handle, DesktopBrokerError> {
        let rights = Rights::READ | Rights::WRITE | Rights::WAIT;
        handle_move_between(&mut self.handles, destination, startup, rights).map_err(Into::into)
    }

    /// Removes all broker resources owned by a disconnected client.
    ///
    /// This operation is idempotent and does not depend on receiving individual
    /// `DestroyWindow` packets from a desktop service that may also be exiting.
    pub fn cleanup_client(&mut self, client_id: ClientId) -> Result<usize, DesktopBrokerError> {
        let mut removed = 0;
        let mut index = 0;
        while index < self.windows.len() {
            if self.windows[index].client_id == client_id {
                let window = self.windows.remove(index);
                self.compositor.remove_window(window.window_id.get());
                self.close_window_handles(window);
                removed += 1;
            } else {
                index += 1;
            }
        }
        self.clients.retain(|known| *known != client_id);
        if self
            .focused_window
            .is_some_and(|focused| self.window_index(focused).is_none())
        {
            self.focused_window = None;
        }
        Ok(removed)
    }

    /// Composes every pending window when the display frame clock is due.
    /// Early paced calls leave pending ownership untouched. Late calls advance
    /// directly to the first deadline after `now_ns` without an unbounded loop.
    pub fn compose_due(
        &mut self,
        framebuffer: &mut FramebufferWriter<'_>,
        now_ns: u64,
    ) -> Result<FrameCompositionOutcome, DesktopBrokerError> {
        let selection = self.frame_clock.select(now_ns);
        if !selection.due {
            return Ok(FrameCompositionOutcome {
                due: false,
                deadline_ns: selection.deadline_ns,
                next_deadline_ns: self.frame_clock.next_deadline_ns(),
                composed_windows: 0,
                late: false,
                missed_deadlines: 0,
            });
        }

        self.metrics.missed_deadlines = self
            .metrics
            .missed_deadlines
            .saturating_add(selection.missed_deadlines);
        let composed_windows = if self
            .windows
            .iter()
            .any(|window| window.transition.is_some())
        {
            let mut composed = 0;
            let mut index = 0;
            while index < self.windows.len() {
                match self
                    .handles
                    .window_manager_pending(self.windows[index].manager)
                {
                    Ok(_) => {
                        let window_id = self.windows[index].window_id;
                        self.compose_pending(framebuffer, window_id)?;
                        composed += 1;
                    }
                    Err(IpcError::ShouldWait | IpcError::PeerClosed) => {}
                    Err(error) => return Err(error.into()),
                }
                index += 1;
            }
            composed
        } else {
            let windows = &self.windows;
            let composed = self.compositor.compose_pending_batch(
                &self.handles,
                framebuffer,
                |id, presentation| {
                    windows
                        .iter()
                        .find(|window| window.window_id.get() == id)
                        .and_then(|window| {
                            window.submissions.iter().find(|submission| {
                                submission.serial == presentation.presentation_serial
                            })
                        })
                        .map(|submission| SurfaceDamage::from_slice(submission.damage.as_slice()))
                        .unwrap_or(SurfaceDamage::FULL)
                },
            )?;
            self.metrics.composed_frames =
                self.metrics.composed_frames.saturating_add(composed as u64);
            self.metrics.displayed_frames = self
                .metrics
                .displayed_frames
                .saturating_add(composed as u64);
            for index in 0..self.windows.len() {
                if let Some(release) = self.take_release(index)? {
                    self.send_release_or_defer(release)?;
                }
            }
            composed
        };
        if selection.late {
            self.metrics.late_frames = self
                .metrics
                .late_frames
                .saturating_add(composed_windows as u64);
        }

        Ok(FrameCompositionOutcome {
            due: true,
            deadline_ns: selection.deadline_ns,
            next_deadline_ns: self.frame_clock.next_deadline_ns(),
            composed_windows,
            late: selection.late,
            missed_deadlines: selection.missed_deadlines,
        })
    }

    /// Composes one pending presentation immediately and emits the release for
    /// the formerly displayed buffer, if any. This explicit path remains
    /// independent of frame pacing for tests and kernel-controlled publication.
    pub fn compose_pending(
        &mut self,
        framebuffer: &mut FramebufferWriter<'_>,
        window_id: WindowId,
    ) -> Result<CompositionOutcome, DesktopBrokerError> {
        let index = self
            .window_index(window_id)
            .ok_or(DesktopBrokerError::UnknownWindow(window_id))?;
        if self.windows[index].transition.is_some() {
            return self.compose_transition(framebuffer, index);
        }
        if self.compositor.window(window_id.get()).is_none() {
            return Err(DesktopBrokerError::WindowNotPlaced(window_id));
        }

        let pending = self
            .handles
            .window_manager_pending(self.windows[index].manager)?;
        let submission = self.windows[index]
            .submissions
            .iter()
            .find(|submission| submission.serial == pending.presentation_serial)
            .copied()
            .ok_or(DesktopBrokerError::UnknownPresentationSerial {
                window_id,
                serial: pending.presentation_serial,
            })?;
        let presentation = self.compositor.compose_pending_damage(
            &self.handles,
            framebuffer,
            window_id.get(),
            submission.damage.as_slice(),
        )?;
        debug_assert_eq!(presentation, pending);
        self.record_composed_frame();
        let released = self.take_release(index)?;
        if let Some(release) = released {
            self.send_release_or_defer(release)?;
        }

        Ok(CompositionOutcome {
            client_id: self.windows[index].client_id,
            request_id: submission.request_id,
            window_id,
            generation: self.windows[index].configuration.generation,
            buffer_id: submission.buffer_id,
            presentation_serial: presentation.presentation_serial,
            released_request_id: released.map(|release| release.request_id),
        })
    }

    fn compose_transition(
        &mut self,
        framebuffer: &mut FramebufferWriter<'_>,
        index: usize,
    ) -> Result<CompositionOutcome, DesktopBrokerError> {
        let window_id = self.windows[index].window_id;
        let placement = self.windows[index]
            .placement
            .ok_or(DesktopBrokerError::WindowNotPlaced(window_id))?;
        let pending = self
            .handles
            .window_manager_pending(self.windows[index].manager)?;
        let submission = self.windows[index]
            .submissions
            .iter()
            .find(|submission| submission.serial == pending.presentation_serial)
            .copied()
            .ok_or(DesktopBrokerError::UnknownPresentationSerial {
                window_id,
                serial: pending.presentation_serial,
            })?;
        let new_config = make_window_config(
            window_id,
            self.windows[index].manager,
            self.windows[index].configuration,
            placement,
        )?;
        let transition = self.windows[index]
            .transition
            .as_ref()
            .expect("transition disappeared before composition");
        debug_assert_eq!(
            transition.configuration.generation.get().checked_add(1),
            Some(self.windows[index].configuration.generation.get())
        );
        debug_assert!(transition.compositor.is_none() || transition.placement.is_some());
        let old_config = transition.compositor;

        if old_config.is_some() {
            self.compositor.update_window(new_config)?;
        } else {
            self.compositor.register_window(new_config)?;
        }

        let presentation = match self.compositor.compose_pending_damage(
            &self.handles,
            framebuffer,
            window_id.get(),
            submission.damage.as_slice(),
        ) {
            Ok(presentation) => presentation,
            Err(error) => {
                let restore = if let Some(old_config) = old_config {
                    self.compositor.update_window(old_config).map(|_| ())
                } else {
                    self.compositor.remove_window(window_id.get());
                    Ok(())
                };
                if let Err(restore_error) = restore {
                    return Err(restore_error.into());
                }
                return Err(error.into());
            }
        };

        debug_assert_eq!(presentation, pending);
        self.record_composed_frame();

        let old_manager = self.windows[index]
            .transition
            .as_ref()
            .expect("transition disappeared during composition")
            .manager;
        self.handles.window_manager_retire(old_manager)?;
        let released = self.take_transition_release(index)?;
        let transition = self.windows[index]
            .transition
            .take()
            .expect("transition disappeared during retirement");
        self.close_transition_handles(transition);
        if let Some(release) = released {
            self.send_release_or_defer(release)?;
        }

        Ok(CompositionOutcome {
            client_id: self.windows[index].client_id,
            request_id: submission.request_id,
            window_id,
            generation: self.windows[index].configuration.generation,
            buffer_id: submission.buffer_id,
            presentation_serial: presentation.presentation_serial,
            released_request_id: released.map(|release| release.request_id),
        })
    }

    fn record_composed_frame(&mut self) {
        self.metrics.composed_frames = self.metrics.composed_frames.saturating_add(1);
        self.metrics.displayed_frames = self.metrics.displayed_frames.saturating_add(1);
    }

    /// Alias emphasizing that composition is scoped to one window submission.
    pub fn compose_window(
        &mut self,
        framebuffer: &mut FramebufferWriter<'_>,
        window_id: WindowId,
    ) -> Result<CompositionOutcome, DesktopBrokerError> {
        self.compose_pending(framebuffer, window_id)
    }

    /// Redraws retained displayed buffers without changing ownership.
    pub fn redraw(
        &mut self,
        framebuffer: &mut FramebufferWriter<'_>,
    ) -> Result<(), DesktopBrokerError> {
        self.compositor.redraw(&self.handles, framebuffer)?;
        Ok(())
    }

    fn configure(
        &mut self,
        client_id: ClientId,
        window_id: WindowId,
        configuration: SurfaceConfiguration,
        shared_memory: &mut SharedMemoryFactory<'_, '_>,
    ) -> Result<DesktopRuntimeEvent, DesktopBrokerError> {
        if !self.clients.contains(&client_id) {
            return Err(DesktopBrokerError::UnknownClient(client_id));
        }
        configuration.validate()?;
        configuration.graphics_layout()?;
        let surface_bytes = configuration
            .required_surface_bytes()
            .ok_or(DesktopBrokerError::ArithmeticOverflow)?;

        let existing = self.window_index(window_id);
        if let Some(index) = existing {
            let window = &self.windows[index];
            if window.client_id != client_id {
                return Err(DesktopBrokerError::WindowOwnerMismatch {
                    window_id,
                    expected: window.client_id,
                    actual: client_id,
                });
            }
            let expected = window
                .configuration
                .generation
                .get()
                .checked_add(1)
                .ok_or(DesktopBrokerError::ArithmeticOverflow)?;
            let actual = configuration.generation.get();
            if actual != expected {
                return Err(DesktopBrokerError::UnexpectedGeneration {
                    window_id,
                    expected,
                    actual,
                });
            }
            if window.transition.is_some()
                || self.handles.window_manager_pending(window.manager).is_ok()
            {
                return Err(DesktopBrokerError::PendingComposition(window_id));
            }

            if let Some(release) = self.take_release(index)? {
                self.send_release_or_defer(release)?;
            }
        } else {
            self.windows
                .try_reserve(1)
                .map_err(|_| DesktopBrokerError::OutOfMemory)?;
        }

        let submissions = reserved_submission_queue(configuration.buffer_count)?;
        let notice_slots = usize::from(configuration.buffer_count).saturating_mul(2);
        self.deferred_notice_bound = self
            .deferred_notice_bound
            .checked_add(notice_slots)
            .ok_or(DesktopBrokerError::ArithmeticOverflow)?;
        if self.deferred_notices.capacity() < self.deferred_notice_bound {
            self.deferred_notices
                .try_reserve_exact(
                    self.deferred_notice_bound
                        .saturating_sub(self.deferred_notices.len()),
                )
                .map_err(|_| DesktopBrokerError::OutOfMemory)?;
        }
        let memory = shared_memory.create_handle(&mut self.handles, surface_bytes)?;
        let (client, manager) = match self.handles.window_create_with_generation_and_buffer_count(
            memory,
            u64::from(configuration.generation.get()),
            u32::from(configuration.buffer_count),
        ) {
            Ok(handles) => handles,
            Err(error) => {
                let _ = self.handles.handle_close(memory);
                return Err(error.into());
            }
        };

        if let Some(index) = existing {
            let old_compositor = self.compositor.window(window_id.get()).copied();
            let displayed = match self
                .handles
                .window_manager_displayed(self.windows[index].manager)
            {
                Ok(displayed) => displayed,
                Err(error) => {
                    self.close_pool(memory, client, manager);
                    return Err(error.into());
                }
            };
            if let Some(displayed) = displayed {
                if !self.windows[index]
                    .submissions
                    .iter()
                    .any(|submission| submission.serial == displayed.presentation_serial)
                {
                    self.close_pool(memory, client, manager);
                    return Err(DesktopBrokerError::UnknownPresentationSerial {
                        window_id,
                        serial: displayed.presentation_serial,
                    });
                }
            }
            let retain_old = displayed.is_some() || old_compositor.is_some();

            if retain_old {
                let transition = PoolTransition {
                    configuration: self.windows[index].configuration,
                    memory: self.windows[index].memory,
                    client: self.windows[index].client,
                    manager: self.windows[index].manager,
                    placement: self.windows[index].placement.take(),
                    submissions: core::mem::replace(
                        &mut self.windows[index].submissions,
                        submissions,
                    ),
                    compositor: old_compositor,
                };
                self.windows[index].configuration = configuration;
                self.windows[index].memory = memory;
                self.windows[index].client = client;
                self.windows[index].manager = manager;
                self.windows[index].transition = Some(transition);
                self.compositor.invalidate_output();
            } else {
                let old_memory = self.windows[index].memory;
                let old_client = self.windows[index].client;
                let old_manager = self.windows[index].manager;
                if let Err(error) = self.handles.window_manager_retire(old_manager) {
                    self.close_pool(memory, client, manager);
                    return Err(match error {
                        IpcError::ShouldWait => DesktopBrokerError::PendingComposition(window_id),
                        other => other.into(),
                    });
                }
                self.windows[index].configuration = configuration;
                self.windows[index].memory = memory;
                self.windows[index].client = client;
                self.windows[index].manager = manager;
                self.windows[index].placement = None;
                self.windows[index].submissions = submissions;
                self.close_pool(old_memory, old_client, old_manager);
            }
        } else {
            self.windows.push(BrokerWindow {
                client_id,
                window_id,
                configuration,
                memory,
                client,
                manager,
                placement: None,
                submissions,
                transition: None,
            });
        }

        self.send_surface_ready(client_id, window_id, configuration.generation, memory)?;
        Ok(DesktopRuntimeEvent::SurfaceConfigured {
            client_id,
            window_id,
            generation: configuration.generation,
        })
    }

    fn destroy_window(
        &mut self,
        client_id: ClientId,
        window_id: WindowId,
    ) -> Result<DesktopRuntimeEvent, DesktopBrokerError> {
        let index = self
            .window_index(window_id)
            .ok_or(DesktopBrokerError::UnknownWindow(window_id))?;
        if self.windows[index].client_id != client_id {
            return Err(DesktopBrokerError::WindowOwnerMismatch {
                window_id,
                expected: self.windows[index].client_id,
                actual: client_id,
            });
        }

        let manager = self.windows[index].manager;
        let release = match self.handles.window_manager_retire(manager) {
            Ok(()) => self.take_release(index)?,
            Err(IpcError::ShouldWait) => None,
            Err(error) => return Err(error.into()),
        };
        self.compositor.remove_window(window_id.get());
        let window = self.windows.remove(index);
        self.close_window_handles(window);
        if self.focused_window == Some(window_id) {
            self.focused_window = None;
        }
        if let Some(release) = release {
            self.send_release_or_defer(release)?;
        }
        Ok(DesktopRuntimeEvent::WindowDestroyed {
            client_id,
            window_id,
        })
    }

    fn set_placements(
        &mut self,
        placements: Vec<RuntimePlacement>,
    ) -> Result<DesktopRuntimeEvent, DesktopBrokerError> {
        let mut configs = Vec::new();
        configs
            .try_reserve_exact(placements.len())
            .map_err(|_| DesktopBrokerError::OutOfMemory)?;
        for placement in &placements {
            let index = self
                .window_index(placement.window_id)
                .ok_or(DesktopBrokerError::UnknownWindow(placement.window_id))?;
            let window = &self.windows[index];
            let expected = window.configuration.logical_size;
            if placement.client.width != expected.width
                || placement.client.height != expected.height
            {
                return Err(DesktopBrokerError::PlacementSizeMismatch {
                    window_id: placement.window_id,
                    expected_width: expected.width,
                    expected_height: expected.height,
                    actual_width: placement.client.width,
                    actual_height: placement.client.height,
                });
            }
            if window.transition.is_none() {
                configs.push(make_window_config(
                    window.window_id,
                    window.manager,
                    window.configuration,
                    *placement,
                )?);
            }
        }

        let mut removed = Vec::new();
        removed
            .try_reserve_exact(self.compositor.windows().len())
            .map_err(|_| DesktopBrokerError::OutOfMemory)?;
        for window in self.compositor.windows() {
            let transitioning = self.windows.iter().any(|broker_window| {
                broker_window.window_id.get() == window.id && broker_window.transition.is_some()
            });
            if !transitioning
                && !placements
                    .iter()
                    .any(|placement| placement.window_id.get() == window.id)
            {
                removed.push(window.id);
            }
        }
        for window_id in removed {
            self.compositor.remove_window(window_id);
        }

        for config in configs {
            if let Some(existing) = self.compositor.window(config.id).copied() {
                if focus_only_window_change(existing, config) {
                    self.compositor
                        .set_focused(config.id, config.placement.focused)?;
                } else {
                    self.compositor.update_window(config)?;
                }
            } else {
                self.compositor.register_window(config)?;
            }
        }
        for (z_index, placement) in placements.iter().enumerate() {
            if self.compositor.window(placement.window_id.get()).is_some() {
                self.compositor
                    .set_z_order(placement.window_id.get(), z_index)?;
            }
        }

        for window in &mut self.windows {
            window.placement = placements
                .iter()
                .find(|placement| placement.window_id == window.window_id)
                .copied();
        }
        self.focused_window = placements
            .iter()
            .find(|placement| placement.focused)
            .map(|placement| placement.window_id);

        let focused_client = self.focused_window.and_then(|focused| {
            self.windows
                .iter()
                .find(|window| window.window_id == focused)
                .map(|window| window.client_id)
        });
        Ok(DesktopRuntimeEvent::PlacementsChanged {
            window_count: placements.len(),
            focused_window: self.focused_window,
            focused_client,
        })
    }

    fn present(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
        generation: Generation,
        buffer_id: BufferId,
        damage: &[ginkgo_window::Rect],
    ) -> Result<DesktopRuntimeEvent, DesktopBrokerError> {
        let Some(index) = self.window_index(window_id) else {
            return self.reject_present(
                client_id,
                request_id,
                window_id,
                generation,
                buffer_id,
                ServerErrorCode::WindowGone,
            );
        };
        if self.windows[index].client_id != client_id
            || self.windows[index].configuration.generation != generation
        {
            return self.reject_present(
                client_id,
                request_id,
                window_id,
                generation,
                buffer_id,
                ServerErrorCode::WindowGone,
            );
        }
        if usize::from(buffer_id.get())
            >= usize::from(self.windows[index].configuration.buffer_count)
            || !damage_within_surface(damage, self.windows[index].configuration)
        {
            return self.reject_present(
                client_id,
                request_id,
                window_id,
                generation,
                buffer_id,
                ServerErrorCode::InvalidRequest,
            );
        }
        if self.windows[index]
            .submissions
            .iter()
            .any(|submission| submission.request_id == request_id)
            || self.windows[index]
                .transition
                .as_ref()
                .is_some_and(|transition| {
                    transition
                        .submissions
                        .iter()
                        .any(|submission| submission.request_id == request_id)
                })
        {
            return self.reject_present(
                client_id,
                request_id,
                window_id,
                generation,
                buffer_id,
                ServerErrorCode::InvalidRequest,
            );
        }
        let had_pending = self
            .windows
            .iter()
            .any(|window| self.handles.window_manager_pending(window.manager).is_ok());
        let stored_damage = submission_damage(damage)?;
        let queued = match self.window_present_coalescing(
            index,
            u32::from(buffer_id.get()),
            u64::from(generation.get()),
            stored_damage,
        )? {
            Ok(queued) => queued,
            Err(IpcError::InvalidMessage | IpcError::ShouldWait) => {
                return self.reject_present(
                    client_id,
                    request_id,
                    window_id,
                    generation,
                    buffer_id,
                    ServerErrorCode::InvalidRequest,
                );
            }
            Err(IpcError::PeerClosed) => {
                return self.reject_present(
                    client_id,
                    request_id,
                    window_id,
                    generation,
                    buffer_id,
                    ServerErrorCode::WindowGone,
                );
            }
            Err(error) => return Err(error.into()),
        };
        debug_assert!(
            self.windows[index].submissions.len() < self.windows[index].submissions.capacity(),
            "configured submission storage must cover every protected buffer"
        );
        if !had_pending
            && self.frame_now_ns != 0
            && self
                .frame_clock
                .next_deadline_ns()
                .is_some_and(|deadline| deadline <= self.frame_now_ns)
        {
            self.frame_clock.reset(self.frame_now_ns);
        }
        self.windows[index].submissions.push(Submission {
            serial: queued.presentation.presentation_serial,
            request_id,
            buffer_id,
            damage: queued.damage,
        });
        self.metrics.submitted_frames = self.metrics.submitted_frames.saturating_add(1);
        if let Some(release) = queued.coalesced_release {
            self.send_release_or_defer(release)?;
        }
        self.send_present_result(
            client_id,
            request_id,
            window_id,
            generation,
            buffer_id,
            PresentationResult::Accepted,
        )?;
        Ok(DesktopRuntimeEvent::PresentationQueued {
            client_id,
            request_id,
            window_id,
            generation,
            buffer_id,
            presentation_serial: queued.presentation.presentation_serial,
        })
    }

    fn window_present_coalescing(
        &mut self,
        index: usize,
        buffer_index: u32,
        generation: u64,
        damage: SubmissionDamage,
    ) -> Result<Result<QueuedPresentation, IpcError>, DesktopBrokerError> {
        let client = self.windows[index].client;
        let first = self
            .handles
            .window_present(client, buffer_index, generation);
        if !matches!(first, Err(IpcError::ShouldWait)) {
            return Ok(first.map(|presentation| QueuedPresentation {
                presentation,
                damage,
                coalesced_release: None,
            }));
        }

        let manager = self.windows[index].manager;
        let pending = match self.handles.window_manager_pending(manager) {
            Ok(pending) => pending,
            Err(IpcError::ShouldWait) => return Ok(Err(IpcError::ShouldWait)),
            Err(error) => return Err(error.into()),
        };
        let pending_damage = self.windows[index]
            .submissions
            .iter()
            .find(|submission| submission.serial == pending.presentation_serial)
            .map(|submission| submission.damage)
            .ok_or(DesktopBrokerError::UnknownPresentationSerial {
                window_id: self.windows[index].window_id,
                serial: pending.presentation_serial,
            })?;
        let replacement = match self.handles.window_manager_coalesce_pending(
            manager,
            pending,
            buffer_index,
            generation,
        ) {
            Ok(replacement) => replacement,
            Err(IpcError::ShouldWait) => return Ok(Err(IpcError::ShouldWait)),
            Err(IpcError::InvalidMessage) => return Ok(Err(IpcError::InvalidMessage)),
            Err(error) => return Err(error.into()),
        };

        let release =
            self.take_release(index)?
                .ok_or(DesktopBrokerError::UnknownPresentationSerial {
                    window_id: self.windows[index].window_id,
                    serial: pending.presentation_serial,
                })?;
        self.metrics.coalesced_frames = self.metrics.coalesced_frames.saturating_add(1);
        self.metrics.dropped_frames = self.metrics.dropped_frames.saturating_add(1);
        Ok(Ok(QueuedPresentation {
            presentation: replacement,
            damage: pending_damage.union(damage),
            coalesced_release: Some(release),
        }))
    }

    fn reject_present(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
        generation: Generation,
        buffer_id: BufferId,
        code: ServerErrorCode,
    ) -> Result<DesktopRuntimeEvent, DesktopBrokerError> {
        self.send_present_result(
            client_id,
            request_id,
            window_id,
            generation,
            buffer_id,
            PresentationResult::Rejected(code),
        )?;
        Ok(DesktopRuntimeEvent::PresentationRejected {
            client_id,
            request_id,
            window_id,
            generation,
            buffer_id,
            code,
        })
    }

    fn send_present_result(
        &mut self,
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
        generation: Generation,
        buffer_id: BufferId,
        result: PresentationResult,
    ) -> Result<(), DesktopBrokerError> {
        self.send_notice_or_defer(DeferredNotice::PresentResult(PresentResultNotice {
            client_id,
            request_id,
            window_id,
            generation,
            buffer_id,
            result,
        }))
    }

    fn send_present_result_now(
        &mut self,
        notice: PresentResultNotice,
    ) -> Result<(), DesktopBrokerError> {
        self.send_kernel_packet(RuntimePacket::new(RuntimeMessage::PresentResult {
            client_id: notice.client_id,
            request_id: notice.request_id,
            window_id: notice.window_id,
            generation: notice.generation,
            buffer_id: notice.buffer_id,
            result: notice.result,
        }))
    }

    fn send_surface_ready(
        &mut self,
        client_id: ClientId,
        window_id: WindowId,
        generation: Generation,
        memory: Handle,
    ) -> Result<(), DesktopBrokerError> {
        let packet = RuntimePacket::new(RuntimeMessage::SurfaceReady {
            client_id,
            window_id,
            generation,
            surface_attachment: AttachmentIndex::new(0),
        });
        let bytes = packet.encode_validated_into(
            RuntimeSender::KernelBroker,
            1,
            &mut self.outbound_bytes,
        )?;
        self.handles.channel_write_with_handle_operations(
            self.channel,
            bytes,
            &[HandleOperationDisposition::duplicate(
                memory,
                DESKTOP_SURFACE_RIGHTS,
            )],
        )?;
        Ok(())
    }

    fn send_release(&mut self, release: ReleaseNotice) -> Result<(), DesktopBrokerError> {
        self.send_kernel_packet(RuntimePacket::new(RuntimeMessage::BufferReleased {
            client_id: release.client_id,
            window_id: release.window_id,
            generation: release.generation,
            buffer_id: release.buffer_id,
            present_request_id: release.request_id,
        }))
    }

    fn send_release_or_defer(&mut self, release: ReleaseNotice) -> Result<(), DesktopBrokerError> {
        self.send_notice_or_defer(DeferredNotice::Release(release))
    }

    fn send_notice_now(&mut self, notice: DeferredNotice) -> Result<(), DesktopBrokerError> {
        match notice {
            DeferredNotice::Release(release) => self.send_release(release),
            DeferredNotice::PresentResult(result) => self.send_present_result_now(result),
        }
    }

    fn send_notice_or_defer(&mut self, notice: DeferredNotice) -> Result<(), DesktopBrokerError> {
        if !self.deferred_notices.is_empty() {
            if self.deferred_notices.len() == self.deferred_notices.capacity() {
                return Err(IpcError::ShouldWait.into());
            }
            self.deferred_notices.push(notice);
            return Ok(());
        }
        match self.send_notice_now(notice) {
            Ok(()) => Ok(()),
            Err(DesktopBrokerError::Ipc(IpcError::ShouldWait)) => {
                if self.deferred_notices.len() == self.deferred_notices.capacity() {
                    return Err(IpcError::ShouldWait.into());
                }
                self.deferred_notices.push(notice);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Retries ordered broker notifications retained after channel backpressure.
    pub fn flush_deferred_notices(&mut self) -> Result<(), DesktopBrokerError> {
        while let Some(notice) = self.deferred_notices.first().copied() {
            match self.send_notice_now(notice) {
                Ok(()) => {
                    self.deferred_notices.remove(0);
                }
                Err(DesktopBrokerError::Ipc(IpcError::ShouldWait)) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn take_release(&mut self, index: usize) -> Result<Option<ReleaseNotice>, DesktopBrokerError> {
        let window = &mut self.windows[index];
        take_pool_release(
            &self.handles,
            window.client_id,
            window.window_id,
            window.client,
            &mut window.submissions,
        )
    }

    fn take_transition_release(
        &mut self,
        index: usize,
    ) -> Result<Option<ReleaseNotice>, DesktopBrokerError> {
        let window = &mut self.windows[index];
        let transition = window
            .transition
            .as_mut()
            .expect("transition release requested without a transition");
        take_pool_release(
            &self.handles,
            window.client_id,
            window.window_id,
            transition.client,
            &mut transition.submissions,
        )
    }

    fn window_index(&self, window_id: WindowId) -> Option<usize> {
        self.windows
            .iter()
            .position(|window| window.window_id == window_id)
    }

    fn close_attachments(&mut self, attachments: &[Handle]) {
        for handle in attachments.iter().copied() {
            if handle.is_valid() {
                let _ = self.handles.handle_close(handle);
            }
        }
    }

    fn close_pool(&mut self, memory: Handle, client: Handle, manager: Handle) {
        let _ = self.handles.handle_close(manager);
        let _ = self.handles.handle_close(client);
        let _ = self.handles.handle_close(memory);
    }

    fn close_transition_handles(&mut self, transition: PoolTransition) {
        self.close_pool(transition.memory, transition.client, transition.manager);
    }

    fn close_window_handles(&mut self, window: BrokerWindow) {
        self.close_pool(window.memory, window.client, window.manager);
        if let Some(transition) = window.transition {
            self.close_transition_handles(transition);
        }
    }
}

fn reserved_submission_queue(buffer_count: u8) -> Result<Vec<Submission>, DesktopBrokerError> {
    let mut submissions = Vec::new();
    submissions
        .try_reserve_exact(usize::from(buffer_count))
        .map_err(|_| DesktopBrokerError::OutOfMemory)?;
    Ok(submissions)
}

fn submission_damage(
    damage: &[ginkgo_window::Rect],
) -> Result<SubmissionDamage, DesktopBrokerError> {
    if damage.is_empty() || damage.len() > DAMAGE_RECT_CAPACITY {
        return Ok(SubmissionDamage::FULL);
    }

    let mut stored = SubmissionDamage::FULL;
    for (index, rect) in damage.iter().enumerate() {
        stored.rects[index] = Rect::new(
            i64::from(rect.origin.x),
            i64::from(rect.origin.y),
            usize::try_from(rect.size.width).map_err(|_| DesktopBrokerError::ArithmeticOverflow)?,
            usize::try_from(rect.size.height)
                .map_err(|_| DesktopBrokerError::ArithmeticOverflow)?,
        );
    }
    stored.len = damage.len();
    Ok(stored)
}

fn take_pool_release(
    handles: &HandleTable,
    client_id: ClientId,
    window_id: WindowId,
    client: Handle,
    submissions: &mut Vec<Submission>,
) -> Result<Option<ReleaseNotice>, DesktopBrokerError> {
    let release = match handles.window_read_release(client) {
        Ok(release) => release,
        Err(IpcError::ShouldWait | IpcError::PeerClosed) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let submission_index = submissions
        .iter()
        .position(|submission| submission.serial == release.presentation_serial)
        .ok_or(DesktopBrokerError::UnknownPresentationSerial {
            window_id,
            serial: release.presentation_serial,
        })?;
    let submission = submissions.remove(submission_index);
    Ok(Some(release_notice(
        client_id, window_id, release, submission,
    )?))
}

fn release_notice(
    client_id: ClientId,
    window_id: WindowId,
    release: WindowRelease,
    submission: Submission,
) -> Result<ReleaseNotice, DesktopBrokerError> {
    let buffer =
        u8::try_from(release.buffer_index).map_err(|_| DesktopBrokerError::ArithmeticOverflow)?;
    let generation = u32::try_from(release.generation)
        .ok()
        .and_then(Generation::new)
        .ok_or(DesktopBrokerError::ArithmeticOverflow)?;
    Ok(ReleaseNotice {
        client_id,
        window_id,
        generation,
        buffer_id: BufferId::new(buffer),
        request_id: submission.request_id,
    })
}

fn focus_only_window_change(old: WindowConfig, new: WindowConfig) -> bool {
    old.id == new.id
        && old.manager == new.manager
        && old.source_layout == new.source_layout
        && old.source_logical_width == new.source_logical_width
        && old.source_logical_height == new.source_logical_height
        && old.placement.outer == new.placement.outer
        && old.placement.client == new.placement.client
        && old.placement.visible == new.placement.visible
        && old.placement.decorated == new.placement.decorated
        && old.placement.focused != new.placement.focused
}

fn make_window_config(
    window_id: WindowId,
    manager: Handle,
    configuration: SurfaceConfiguration,
    placement: RuntimePlacement,
) -> Result<WindowConfig, DesktopBrokerError> {
    let outer = compositor_rect(placement.outer)?;
    let client = compositor_rect(placement.client)?;
    let visible = placement.visible.map(compositor_rect).transpose()?;
    let logical_width = usize::try_from(configuration.logical_size.width)
        .map_err(|_| DesktopBrokerError::ArithmeticOverflow)?;
    let logical_height = usize::try_from(configuration.logical_size.height)
        .map_err(|_| DesktopBrokerError::ArithmeticOverflow)?;
    Ok(WindowConfig::new(
        window_id.get(),
        manager,
        configuration.graphics_layout()?,
        CompositorPlacement::new(
            outer,
            client,
            visible,
            placement.focused,
            placement.decorated,
        ),
    )
    .with_source_logical_size(logical_width, logical_height))
}

fn compositor_rect(rect: ginkgo_desktop::PlacementRect) -> Result<Rect, DesktopBrokerError> {
    Ok(Rect::new(
        rect.x,
        rect.y,
        usize::try_from(rect.width).map_err(|_| DesktopBrokerError::ArithmeticOverflow)?,
        usize::try_from(rect.height).map_err(|_| DesktopBrokerError::ArithmeticOverflow)?,
    ))
}

fn damage_within_surface(
    damage: &[ginkgo_window::Rect],
    configuration: SurfaceConfiguration,
) -> bool {
    damage.iter().all(|rect| {
        let Ok(x) = u32::try_from(rect.origin.x) else {
            return false;
        };
        let Ok(y) = u32::try_from(rect.origin.y) else {
            return false;
        };
        x.checked_add(rect.size.width)
            .is_some_and(|right| right <= configuration.pixel_size.width)
            && y.checked_add(rect.size.height)
                .is_some_and(|bottom| bottom <= configuration.pixel_size.height)
    })
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::vec;

    use ginkgo_desktop::{PlacementRect, RuntimeDecodeError};
    use ginkgo_graphics::FramebufferConfig;
    use ginkgo_window::{
        ButtonState, Modifiers, PixelFormat, PointerButton, Rect as DamageRect, ScaleFactor, Size,
        PROTOCOL_VERSION,
    };

    use super::*;
    use crate::shared_memory::test_support::TestSharedMemoryContext;

    fn client(value: u64) -> ClientId {
        ClientId::new(value).unwrap()
    }

    fn window(value: u64) -> WindowId {
        WindowId::new(value).unwrap()
    }

    fn request(value: u64) -> RequestId {
        RequestId::new(value).unwrap()
    }

    fn generation(value: u32) -> Generation {
        Generation::new(value).unwrap()
    }

    fn configuration(
        generation_value: u32,
        width: u32,
        height: u32,
        buffers: u8,
    ) -> SurfaceConfiguration {
        SurfaceConfiguration {
            logical_size: Size::new(width, height),
            pixel_size: Size::new(width, height),
            stride: width * 4,
            format: PixelFormat::Xrgb8888,
            scale: ScaleFactor::ONE,
            generation: generation(generation_value),
            buffer_count: buffers,
        }
    }

    fn placement(
        window_id: WindowId,
        x: i64,
        y: i64,
        width: u32,
        height: u32,
        focused: bool,
    ) -> RuntimePlacement {
        let rect = PlacementRect::new(x, y, width, height);
        RuntimePlacement {
            window_id,
            outer: rect,
            client: rect,
            visible: Some(rect),
            focused,
            decorated: false,
        }
    }

    fn framebuffer(bytes: &mut [u8], width: usize, height: usize) -> FramebufferWriter<'_> {
        let config = FramebufferConfig {
            address: bytes.as_mut_ptr(),
            width: width as u64,
            height: height as u64,
            pitch: (width * 4) as u64,
            bits_per_pixel: 32,
            memory_model: 1,
            red_mask_size: 8,
            red_mask_shift: 16,
            green_mask_size: 8,
            green_mask_shift: 8,
            blue_mask_size: 8,
            blue_mask_shift: 0,
        };
        unsafe { FramebufferWriter::from_raw(config) }.unwrap()
    }

    struct Fixture {
        broker: DesktopBroker,
        desktop: HandleTable,
        desktop_channel: Handle,
        client_handles: HandleTable,
        client_id: ClientId,
        shared_memory: TestSharedMemoryContext,
    }

    impl Fixture {
        fn new() -> Self {
            let mut desktop = HandleTable::new();
            let (mut broker, desktop_channel) = DesktopBroker::create(&mut desktop).unwrap();
            let mut client_handles = HandleTable::new();
            let client_id = client(1);
            broker
                .connect_client(client_id, &mut client_handles)
                .unwrap();
            let (packet, attachments) = receive(&mut desktop, desktop_channel);
            assert!(matches!(
                packet.message,
                RuntimeMessage::ClientConnected { client_id: id, .. } if id == client_id
            ));
            assert_eq!(attachments.len(), 1);
            assert_eq!(
                desktop.handle_rights(attachments[0]),
                Ok(DESKTOP_CLIENT_CHANNEL_RIGHTS)
            );
            Self {
                broker,
                desktop,
                desktop_channel,
                client_handles,
                client_id,
                shared_memory: TestSharedMemoryContext::new(4096),
            }
        }

        fn send(&mut self, message: RuntimeMessage) -> DesktopRuntimeEvent {
            let packet = RuntimePacket::new(message);
            let bytes = packet
                .encode_validated(RuntimeSender::DesktopService, 0)
                .unwrap();
            self.desktop
                .channel_write(self.desktop_channel, &bytes, &[])
                .unwrap();
            let mut factory = self.shared_memory.factory();
            self.broker.poll_desktop(&mut factory).unwrap().unwrap()
        }

        fn poll_desktop(&mut self) -> Result<Option<DesktopRuntimeEvent>, DesktopBrokerError> {
            let mut factory = self.shared_memory.factory();
            self.broker.poll_desktop(&mut factory)
        }

        fn handle_packet(
            &mut self,
            packet: RuntimePacket,
            attachments: &[Handle],
        ) -> Result<DesktopRuntimeEvent, DesktopBrokerError> {
            let mut factory = self.shared_memory.factory();
            self.broker
                .handle_desktop_packet(packet, attachments, &mut factory)
        }

        fn configure(&mut self, window_id: WindowId, config: SurfaceConfiguration) -> Handle {
            assert!(matches!(
                self.send(RuntimeMessage::Configure {
                    client_id: self.client_id,
                    window_id,
                    configuration: config,
                }),
                DesktopRuntimeEvent::SurfaceConfigured { .. }
            ));
            let (packet, attachments) = receive(&mut self.desktop, self.desktop_channel);
            assert!(matches!(
                packet.message,
                RuntimeMessage::SurfaceReady {
                    window_id: id,
                    generation: received,
                    ..
                } if id == window_id && received == config.generation
            ));
            assert_eq!(attachments.len(), 1);
            attachments[0]
        }

        fn place(&mut self, placements: Vec<RuntimePlacement>) {
            assert!(matches!(
                self.send(RuntimeMessage::SetPlacements { placements }),
                DesktopRuntimeEvent::PlacementsChanged { .. }
            ));
        }

        fn present(
            &mut self,
            window_id: WindowId,
            generation: Generation,
            buffer: u8,
            request_id: RequestId,
            width: u32,
            height: u32,
        ) -> DesktopRuntimeEvent {
            self.send(RuntimeMessage::Present {
                client_id: self.client_id,
                request_id,
                window_id,
                generation,
                buffer_id: BufferId::new(buffer),
                damage: vec![DamageRect::new(
                    InputPoint::new(0, 0),
                    Size::new(width, height),
                )]
                .into(),
            })
        }
    }

    fn receive(table: &mut HandleTable, channel: Handle) -> (RuntimePacket, Vec<Handle>) {
        let mut bytes = [0_u8; CHANNEL_MAX_BYTES];
        let mut handles = [Handle::INVALID; CHANNEL_MAX_HANDLES];
        let info = table
            .channel_read(channel, &mut bytes, &mut handles)
            .unwrap();
        let handle_count = usize::from(info.handle_count);
        let packet = RuntimePacket::decode(
            &bytes[..info.byte_count as usize],
            RuntimeSender::KernelBroker,
            handle_count,
        )
        .unwrap();
        (packet, handles[..handle_count].to_vec())
    }

    fn assert_no_message(table: &mut HandleTable, channel: Handle) {
        let mut bytes = [0_u8; CHANNEL_MAX_BYTES];
        let mut handles = [Handle::INVALID; CHANNEL_MAX_HANDLES];
        assert_eq!(
            table.channel_read(channel, &mut bytes, &mut handles),
            Err(IpcError::ShouldWait)
        );
    }

    #[test]
    fn configure_allocates_exact_protected_pool_and_attenuates_memory() {
        let mut fixture = Fixture::new();
        let id = window(10);
        let config = configuration(1, 3, 2, 3);
        let surface = fixture.configure(id, config);

        assert_eq!(
            fixture.desktop.shared_memory_len(surface),
            Ok(3 * 2 * 4 * 3)
        );
        assert_eq!(
            fixture.desktop.handle_rights(surface),
            Ok(DESKTOP_SURFACE_RIGHTS)
        );
        assert!(!DESKTOP_SURFACE_RIGHTS.contains(Rights::MANAGE | Rights::DUPLICATE));
        let state = &fixture.broker.windows[0];
        assert_eq!(
            fixture.broker.handles.window_buffer_count(state.client),
            Ok(3)
        );
        assert_eq!(
            fixture.broker.handles.window_buffer_len(state.manager),
            Ok(24)
        );
        assert!(fixture
            .desktop
            .window_create_with_generation_and_buffer_count(surface, 1, 3)
            .is_err());
    }

    #[test]
    fn present_composes_ram_framebuffer_and_releases_by_serial_request_mapping() {
        let mut fixture = Fixture::new();
        let id = window(20);
        let config = configuration(1, 2, 1, 2);
        let surface = fixture.configure(id, config);
        fixture.place(vec![placement(id, 0, 0, 2, 1, true)]);
        fixture
            .desktop
            .shared_memory_write(surface, 0, &0x00ff_0000_u32.to_le_bytes())
            .unwrap();
        fixture
            .desktop
            .shared_memory_write(surface, 4, &0x0000_ff00_u32.to_le_bytes())
            .unwrap();
        fixture
            .desktop
            .shared_memory_write(surface, 8, &0x0000_00ff_u32.to_le_bytes())
            .unwrap();

        let first_request = request(1);
        let first = fixture.present(id, config.generation, 0, first_request, 2, 1);
        assert!(matches!(
            first,
            DesktopRuntimeEvent::PresentationQueued { .. }
        ));
        let (result, attachments) = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert!(attachments.is_empty());
        assert!(matches!(
            result.message,
            RuntimeMessage::PresentResult {
                result: PresentationResult::Accepted,
                ..
            }
        ));

        let mut framebuffer_bytes = [0_u8; 8];
        let mut screen = framebuffer(&mut framebuffer_bytes, 2, 1);
        let first_composition = fixture.broker.compose_pending(&mut screen, id).unwrap();
        assert_eq!(first_composition.released_request_id, None);
        assert_eq!(screen.read_raw_pixel(0, 0), Some(0x00ff_0000));
        assert_eq!(screen.read_raw_pixel(1, 0), Some(0x0000_ff00));

        let second_request = request(2);
        fixture.present(id, config.generation, 1, second_request, 2, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        let second_composition = fixture.broker.compose_pending(&mut screen, id).unwrap();
        assert_eq!(second_composition.released_request_id, Some(first_request));
        assert_eq!(screen.read_raw_pixel(0, 0), Some(0x0000_00ff));
        let (release, attachments) = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert!(attachments.is_empty());
        assert!(matches!(
            release.message,
            RuntimeMessage::BufferReleased {
                buffer_id,
                present_request_id,
                ..
            } if buffer_id == BufferId::new(0) && present_request_id == first_request
        ));
    }

    #[test]
    fn resize_retains_old_redraw_until_first_new_frame_then_releases_it() {
        let mut fixture = Fixture::new();
        let id = window(30);
        let first = configuration(1, 1, 1, 2);
        let old_surface = fixture.configure(id, first);
        let old_placement = placement(id, 0, 0, 1, 1, true);
        fixture.place(vec![old_placement]);
        fixture
            .desktop
            .shared_memory_write(old_surface, 0, &0x00aa_0000_u32.to_le_bytes())
            .unwrap();
        let old_request = request(10);
        fixture.present(id, first.generation, 0, old_request, 1, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        let mut framebuffer_bytes = [0_u8; 8];
        let mut screen = framebuffer(&mut framebuffer_bytes, 2, 1);
        fixture.broker.compose_pending(&mut screen, id).unwrap();
        let old_compositor = *fixture.broker.compositor().window(id.get()).unwrap();

        let second = configuration(2, 2, 1, 2);
        let new_surface = fixture.configure(id, second);
        assert_eq!(fixture.broker.window_configuration(id), Some(second));
        assert!(fixture.broker.windows[0].transition.is_some());
        assert_no_message(&mut fixture.desktop, fixture.desktop_channel);

        screen.write_raw_pixel(0, 0, 0);
        fixture.broker.redraw(&mut screen).unwrap();
        assert_eq!(screen.read_raw_pixel(0, 0), Some(0x00aa_0000));

        let new_placement = placement(id, 0, 0, 2, 1, true);
        fixture.place(vec![new_placement]);
        assert_eq!(
            fixture.broker.compositor().window(id.get()),
            Some(&old_compositor)
        );

        let stale = fixture.present(id, first.generation, 0, request(11), 1, 1);
        assert!(matches!(
            stale,
            DesktopRuntimeEvent::PresentationRejected {
                code: ServerErrorCode::WindowGone,
                ..
            }
        ));
        let (rejected, _) = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert!(matches!(
            rejected.message,
            RuntimeMessage::PresentResult {
                result: PresentationResult::Rejected(ServerErrorCode::WindowGone),
                ..
            }
        ));

        for (offset, color) in [(0, 0x0000_aa00_u32), (4, 0x0000_00aa_u32)] {
            fixture
                .desktop
                .shared_memory_write(new_surface, offset, &color.to_le_bytes())
                .unwrap();
        }
        let new_request = request(12);
        fixture.present(id, second.generation, 0, new_request, 2, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert_no_message(&mut fixture.desktop, fixture.desktop_channel);

        let outcome = fixture.broker.compose_pending(&mut screen, id).unwrap();
        assert_eq!(outcome.request_id, new_request);
        assert_eq!(outcome.released_request_id, Some(old_request));
        assert_eq!(screen.read_raw_pixel(0, 0), Some(0x0000_aa00));
        assert_eq!(screen.read_raw_pixel(1, 0), Some(0x0000_00aa));
        assert!(fixture.broker.windows[0].transition.is_none());
        let compositor = fixture.broker.compositor().window(id.get()).unwrap();
        assert_eq!(compositor.manager, fixture.broker.windows[0].manager);
        assert_eq!(compositor.placement.client, Rect::new(0, 0, 2, 1));

        let (released, no_handles) = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert!(no_handles.is_empty());
        assert!(matches!(
            released.message,
            RuntimeMessage::BufferReleased {
                generation,
                present_request_id,
                ..
            } if generation == first.generation && present_request_id == old_request
        ));
    }

    #[test]
    fn transition_uses_fullscreen_and_restored_geometry_only_with_each_first_frame() {
        let mut fixture = Fixture::new();
        let id = window(31);
        let windowed = configuration(1, 2, 1, 2);
        let windowed_surface = fixture.configure(id, windowed);
        let windowed_placement = placement(id, 1, 1, 2, 1, true);
        fixture.place(vec![windowed_placement]);
        fixture
            .desktop
            .shared_memory_write(windowed_surface, 0, &0x00cc_0000_u32.to_le_bytes())
            .unwrap();
        fixture.present(id, windowed.generation, 0, request(20), 2, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        let mut framebuffer_bytes = [0_u8; 4 * 4 * 2];
        let mut screen = framebuffer(&mut framebuffer_bytes, 4, 2);
        fixture.broker.compose_pending(&mut screen, id).unwrap();

        let fullscreen = configuration(2, 4, 2, 2);
        let fullscreen_surface = fixture.configure(id, fullscreen);
        let fullscreen_placement = placement(id, 0, 0, 4, 2, true);
        fixture.place(vec![fullscreen_placement]);
        assert_eq!(
            fixture
                .broker
                .compositor()
                .window(id.get())
                .unwrap()
                .placement
                .client,
            Rect::new(1, 1, 2, 1)
        );
        fixture
            .desktop
            .shared_memory_write(fullscreen_surface, 0, &0x0000_cc00_u32.to_le_bytes())
            .unwrap();
        fixture.present(id, fullscreen.generation, 0, request(21), 4, 2);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        fixture.broker.compose_pending(&mut screen, id).unwrap();
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert_eq!(
            fixture
                .broker
                .compositor()
                .window(id.get())
                .unwrap()
                .placement
                .client,
            Rect::new(0, 0, 4, 2)
        );

        let restored = configuration(3, 2, 1, 2);
        let restored_surface = fixture.configure(id, restored);
        fixture.place(vec![windowed_placement]);
        assert_eq!(
            fixture
                .broker
                .compositor()
                .window(id.get())
                .unwrap()
                .placement
                .client,
            Rect::new(0, 0, 4, 2)
        );
        fixture
            .desktop
            .shared_memory_write(restored_surface, 0, &0x0000_00cc_u32.to_le_bytes())
            .unwrap();
        fixture.present(id, restored.generation, 0, request(22), 2, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        fixture.broker.compose_pending(&mut screen, id).unwrap();
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert_eq!(
            fixture
                .broker
                .compositor()
                .window(id.get())
                .unwrap()
                .placement
                .client,
            Rect::new(1, 1, 2, 1)
        );
    }

    #[test]
    fn configure_rejects_a_new_generation_while_resize_transition_is_pending() {
        let mut fixture = Fixture::new();
        let id = window(32);
        let first = configuration(1, 1, 1, 2);
        let surface = fixture.configure(id, first);
        fixture.place(vec![placement(id, 0, 0, 1, 1, true)]);
        fixture
            .desktop
            .shared_memory_write(surface, 0, &0x00dd_0000_u32.to_le_bytes())
            .unwrap();
        fixture.present(id, first.generation, 0, request(30), 1, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        let mut framebuffer_bytes = [0_u8; 4];
        let mut screen = framebuffer(&mut framebuffer_bytes, 1, 1);
        fixture.broker.compose_pending(&mut screen, id).unwrap();

        fixture.configure(id, configuration(2, 2, 1, 2));
        let next = RuntimePacket::new(RuntimeMessage::Configure {
            client_id: fixture.client_id,
            window_id: id,
            configuration: configuration(3, 3, 1, 2),
        });
        assert!(matches!(
            fixture.handle_packet(next, &[]),
            Err(DesktopBrokerError::PendingComposition(window_id)) if window_id == id
        ));
        assert_eq!(
            fixture.broker.window_configuration(id),
            Some(configuration(2, 2, 1, 2))
        );
        assert!(fixture.broker.windows[0].transition.is_some());
    }

    #[test]
    fn failed_first_resize_composition_restores_old_compositor_and_pool() {
        let mut fixture = Fixture::new();
        let id = window(33);
        let first = configuration(1, 1, 1, 2);
        let surface = fixture.configure(id, first);
        fixture.place(vec![placement(id, 0, 0, 1, 1, true)]);
        fixture
            .desktop
            .shared_memory_write(surface, 0, &0x00ee_0000_u32.to_le_bytes())
            .unwrap();
        fixture.present(id, first.generation, 0, request(40), 1, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        let mut framebuffer_bytes = [0_u8; 8];
        let mut screen = framebuffer(&mut framebuffer_bytes, 2, 1);
        fixture.broker.compose_pending(&mut screen, id).unwrap();
        let old_compositor = *fixture.broker.compositor().window(id.get()).unwrap();

        let second = configuration(2, 2, 1, 2);
        let new_surface = fixture.configure(id, second);
        fixture.place(vec![placement(id, 0, 0, 2, 1, true)]);
        fixture
            .desktop
            .shared_memory_write(new_surface, 0, &0x0000_ee00_u32.to_le_bytes())
            .unwrap();
        fixture.present(id, second.generation, 0, request(41), 2, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);

        fixture.broker.windows[0].configuration = configuration(2, 3, 1, 2);
        assert!(matches!(
            fixture.broker.compose_pending(&mut screen, id),
            Err(DesktopBrokerError::Compositor(
                CompositorError::ConfiguredBufferTooSmall { .. }
            ))
        ));
        assert_eq!(
            fixture.broker.compositor().window(id.get()),
            Some(&old_compositor)
        );
        assert!(fixture.broker.windows[0].transition.is_some());
        screen.write_raw_pixel(0, 0, 0);
        fixture.broker.redraw(&mut screen).unwrap();
        assert_eq!(screen.read_raw_pixel(0, 0), Some(0x00ee_0000));

        fixture.broker.windows[0].configuration = second;
        fixture.broker.compose_pending(&mut screen, id).unwrap();
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert!(fixture.broker.windows[0].transition.is_none());
    }

    #[test]
    fn placements_control_z_order_clipping_focus_and_fullscreen_geometry() {
        let mut fixture = Fixture::new();
        let first = window(40);
        let second = window(41);
        let first_surface = fixture.configure(first, configuration(1, 2, 1, 2));
        let second_surface = fixture.configure(second, configuration(1, 2, 1, 2));
        for (surface, color) in [
            (first_surface, 0x00ff_0000_u32),
            (second_surface, 0x0000_00ff_u32),
        ] {
            fixture
                .desktop
                .shared_memory_write(surface, 0, &color.to_le_bytes())
                .unwrap();
            fixture
                .desktop
                .shared_memory_write(surface, 4, &color.to_le_bytes())
                .unwrap();
        }

        let mut clipped = placement(first, -1, 0, 2, 1, false);
        clipped.visible = Some(PlacementRect::new(0, 0, 1, 1));
        fixture.place(vec![clipped, placement(second, 0, 0, 2, 1, true)]);
        assert_eq!(fixture.broker.focused_window(), Some(second));
        assert_eq!(
            fixture
                .broker
                .compositor()
                .windows()
                .iter()
                .map(|window| window.id)
                .collect::<Vec<_>>(),
            vec![first.get(), second.get()]
        );
        assert_eq!(
            fixture
                .broker
                .compositor()
                .window(first.get())
                .unwrap()
                .placement
                .visible,
            Some(Rect::new(0, 0, 1, 1))
        );

        fixture.present(first, generation(1), 0, request(20), 2, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        fixture.present(second, generation(1), 0, request(21), 2, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        let mut framebuffer_bytes = [0_u8; 8];
        let mut screen = framebuffer(&mut framebuffer_bytes, 2, 1);
        fixture.broker.compose_pending(&mut screen, first).unwrap();
        fixture.broker.compose_pending(&mut screen, second).unwrap();
        assert_eq!(screen.read_raw_pixel(0, 0), Some(0x0000_00ff));

        fixture.place(vec![placement(first, 0, 0, 2, 1, true)]);
        assert_eq!(fixture.broker.focused_window(), Some(first));
        assert_eq!(fixture.broker.compositor().windows().len(), 1);
        assert_eq!(
            fixture
                .broker
                .compositor()
                .window(first.get())
                .unwrap()
                .placement
                .client,
            Rect::new(0, 0, 2, 1)
        );
        fixture.broker.redraw(&mut screen).unwrap();
        assert_eq!(screen.read_raw_pixel(0, 0), Some(0x00ff_0000));
    }

    #[test]
    fn malformed_direction_and_overprivileged_attachments_are_rejected_and_closed() {
        let mut fixture = Fixture::new();
        let handles_before = fixture.broker.handles.len();
        fixture
            .desktop
            .channel_write(fixture.desktop_channel, &[0xff, 0x00], &[])
            .unwrap();
        assert!(matches!(
            fixture.poll_desktop(),
            Err(DesktopBrokerError::Decode(RuntimeDecodeError::Postcard(_)))
        ));

        let memory = fixture
            .shared_memory
            .factory()
            .create_handle(&mut fixture.desktop, 4096)
            .unwrap();
        let overprivileged = RuntimePacket::new(RuntimeMessage::ServiceReady {
            window_protocol_version: PROTOCOL_VERSION,
        })
        .encode()
        .unwrap();
        fixture
            .desktop
            .channel_write(fixture.desktop_channel, &overprivileged, &[memory])
            .unwrap();
        assert!(matches!(
            fixture.poll_desktop(),
            Err(DesktopBrokerError::Decode(RuntimeDecodeError::Validation(
                RuntimeValidationError::AttachmentCount {
                    expected: 0,
                    actual: 1
                }
            )))
        ));
        assert_eq!(fixture.broker.handles.len(), handles_before);

        let wrong_direction = RuntimePacket::new(RuntimeMessage::ToggleLauncher)
            .encode()
            .unwrap();
        fixture
            .desktop
            .channel_write(fixture.desktop_channel, &wrong_direction, &[])
            .unwrap();
        assert!(matches!(
            fixture.poll_desktop(),
            Err(DesktopBrokerError::Decode(RuntimeDecodeError::Validation(
                RuntimeValidationError::UnexpectedSender { .. }
            )))
        ));
    }

    #[test]
    fn semantic_validation_rejects_unknown_clients_bad_generations_and_damage() {
        let mut fixture = Fixture::new();
        let id = window(50);
        let unknown = client(99);
        let packet = RuntimePacket::new(RuntimeMessage::Configure {
            client_id: unknown,
            window_id: id,
            configuration: configuration(1, 1, 1, 2),
        });
        assert!(matches!(
            fixture.handle_packet(packet, &[]),
            Err(DesktopBrokerError::UnknownClient(value)) if value == unknown
        ));

        let config = configuration(1, 1, 1, 2);
        fixture.configure(id, config);
        let skipped = RuntimePacket::new(RuntimeMessage::Configure {
            client_id: fixture.client_id,
            window_id: id,
            configuration: configuration(3, 1, 1, 2),
        });
        assert!(matches!(
            fixture.handle_packet(skipped, &[]),
            Err(DesktopBrokerError::UnexpectedGeneration {
                expected: 2,
                actual: 3,
                ..
            })
        ));

        fixture.place(vec![placement(id, 0, 0, 1, 1, true)]);
        let bad_damage = fixture.send(RuntimeMessage::Present {
            client_id: fixture.client_id,
            request_id: request(30),
            window_id: id,
            generation: config.generation,
            buffer_id: BufferId::new(0),
            damage: vec![DamageRect::new(InputPoint::new(1, 0), Size::new(1, 1))].into(),
        });
        assert!(matches!(
            bad_damage,
            DesktopRuntimeEvent::PresentationRejected {
                code: ServerErrorCode::InvalidRequest,
                ..
            }
        ));
    }

    #[test]
    fn input_packets_and_client_channels_are_strictly_kernel_originated() {
        let mut fixture = Fixture::new();
        fixture.broker.send_toggle_launcher().unwrap();
        let (toggle, attachments) = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert!(attachments.is_empty());
        assert_eq!(toggle.message, RuntimeMessage::ToggleLauncher);

        fixture
            .broker
            .send_pointer_input(
                InputPoint::new(7, 9),
                PointerEventKind::Button {
                    button: PointerButton::Primary,
                    state: ButtonState::Pressed,
                },
            )
            .unwrap();
        let (pointer, _) = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert!(matches!(
            pointer.message,
            RuntimeMessage::PointerInput { .. }
        ));

        fixture
            .broker
            .send_keyboard_input(KeyboardEvent {
                usage: 4,
                state: ButtonState::Pressed,
                repeat: false,
                modifiers: Modifiers::default(),
            })
            .unwrap();
        let (keyboard, _) = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert!(matches!(
            keyboard.message,
            RuntimeMessage::KeyboardInput { .. }
        ));
        assert!(!fixture.client_handles.is_empty());
    }

    #[test]
    fn damage_storage_converts_source_rects_and_falls_back_to_full() {
        let damage = [
            DamageRect::new(InputPoint::new(1, 2), Size::new(3, 4)),
            DamageRect::new(InputPoint::new(5, 6), Size::new(7, 8)),
        ];
        let stored = submission_damage(&damage).unwrap();
        assert_eq!(
            stored.as_slice(),
            &[Rect::new(1, 2, 3, 4), Rect::new(5, 6, 7, 8)]
        );
        assert!(submission_damage(&[]).unwrap().as_slice().is_empty());

        let fragmented =
            vec![DamageRect::new(InputPoint::new(0, 0), Size::new(1, 1)); DAMAGE_RECT_CAPACITY + 1];
        assert!(submission_damage(&fragmented)
            .unwrap()
            .as_slice()
            .is_empty());
    }

    #[test]
    fn present_forwards_stored_partial_damage_to_compositor() {
        let mut fixture = Fixture::new();
        let id = window(55);
        let config = configuration(1, 3, 1, 2);
        let surface = fixture.configure(id, config);
        fixture.place(vec![placement(id, 0, 0, 3, 1, true)]);
        for offset in [0, 4, 8] {
            fixture
                .desktop
                .shared_memory_write(surface, offset, &0x00ff_0000_u32.to_le_bytes())
                .unwrap();
        }
        fixture.present(id, config.generation, 0, request(50), 3, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        let mut framebuffer_bytes = [0_u8; 12];
        let mut screen = framebuffer(&mut framebuffer_bytes, 3, 1);
        fixture.broker.compose_pending(&mut screen, id).unwrap();

        for offset in [12, 16, 20] {
            fixture
                .desktop
                .shared_memory_write(surface, offset, &0x0000_ff00_u32.to_le_bytes())
                .unwrap();
        }
        let partial = DamageRect::new(InputPoint::new(1, 0), Size::new(1, 1));
        fixture.send(RuntimeMessage::Present {
            client_id: fixture.client_id,
            request_id: request(51),
            window_id: id,
            generation: config.generation,
            buffer_id: BufferId::new(1),
            damage: vec![partial].into(),
        });
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert_eq!(
            fixture.broker.windows[0]
                .submissions
                .last()
                .unwrap()
                .damage
                .as_slice(),
            &[Rect::new(1, 0, 1, 1)]
        );

        fixture.broker.compose_pending(&mut screen, id).unwrap();
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert_eq!(screen.read_raw_pixel(0, 0), Some(0x00ff_0000));
        assert_eq!(screen.read_raw_pixel(1, 0), Some(0x0000_ff00));
        assert_eq!(screen.read_raw_pixel(2, 0), Some(0x00ff_0000));
    }

    #[test]
    fn frame_clock_selects_early_on_time_and_late_deadlines() {
        let mut clock = DisplayFrameClock::new(10, DisplayTimingConfidence::Measured).unwrap();
        clock.reset(100);

        let early = clock.select(99);
        assert!(!early.due);
        assert_eq!(early.deadline_ns, Some(100));
        assert_eq!(clock.next_deadline_ns(), Some(100));

        let on_time = clock.select(100);
        assert!(on_time.due);
        assert!(!on_time.late);
        assert_eq!(on_time.missed_deadlines, 0);
        assert_eq!(clock.next_deadline_ns(), Some(110));

        let late = clock.select(135);
        assert!(late.due);
        assert!(late.late);
        assert_eq!(late.deadline_ns, Some(110));
        assert_eq!(late.missed_deadlines, 2);
        assert_eq!(clock.next_deadline_ns(), Some(140));

        clock.reset(u64::MAX - 1);
        let saturated = clock.select(u64::MAX);
        assert!(saturated.due);
        assert_eq!(clock.next_deadline_ns(), Some(u64::MAX));
    }

    #[test]
    fn production_due_check_preserves_real_missed_deadlines() {
        let mut fixture = Fixture::new();
        let id = window(62);
        let config = configuration(1, 1, 1, 2);
        fixture.configure(id, config);
        fixture.place(vec![placement(id, 0, 0, 1, 1, true)]);
        fixture.broker.frame_clock =
            DisplayFrameClock::new(10, DisplayTimingConfidence::Measured).unwrap();
        fixture.broker.frame_clock.reset(100);
        fixture.present(id, config.generation, 0, request(96), 1, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);

        assert!(fixture.broker.presentation_due(135));
        let mut framebuffer_bytes = [0_u8; 4];
        let mut screen = framebuffer(&mut framebuffer_bytes, 1, 1);
        let outcome = fixture.broker.compose_due(&mut screen, 135).unwrap();
        assert!(outcome.late);
        assert_eq!(outcome.missed_deadlines, 3);
        assert_eq!(outcome.next_deadline_ns, Some(140));
    }

    #[test]
    fn compose_due_paces_early_and_late_frames_and_reports_metrics() {
        let mut fixture = Fixture::new();
        let id = window(56);
        let config = configuration(1, 1, 1, 2);
        let surface = fixture.configure(id, config);
        fixture.place(vec![placement(id, 0, 0, 1, 1, true)]);
        fixture
            .desktop
            .shared_memory_write(surface, 0, &0x00aa_0000_u32.to_le_bytes())
            .unwrap();
        fixture.present(id, config.generation, 0, request(60), 1, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);

        assert!(fixture.broker.frame_clock_mut().set_refresh_interval_ns(10));
        fixture.broker.frame_clock_mut().reset(100);
        let mut framebuffer_bytes = [0_u8; 4];
        let mut screen = framebuffer(&mut framebuffer_bytes, 1, 1);
        let early = fixture.broker.compose_due(&mut screen, 99).unwrap();
        assert!(!early.due);
        assert_eq!(early.composed_windows, 0);
        assert!(fixture
            .broker
            .handles
            .window_manager_pending(fixture.broker.windows[0].manager)
            .is_ok());

        let first = fixture.broker.compose_due(&mut screen, 100).unwrap();
        assert!(first.due);
        assert_eq!(first.composed_windows, 1);
        assert_eq!(first.next_deadline_ns, Some(110));

        fixture
            .desktop
            .shared_memory_write(surface, 4, &0x0000_aa00_u32.to_le_bytes())
            .unwrap();
        fixture.present(id, config.generation, 1, request(61), 1, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        let still_early = fixture.broker.compose_due(&mut screen, 105).unwrap();
        assert!(!still_early.due);
        assert_eq!(screen.read_raw_pixel(0, 0), Some(0x00aa_0000));

        let late = fixture.broker.compose_due(&mut screen, 135).unwrap();
        assert!(late.due);
        assert!(late.late);
        assert_eq!(late.missed_deadlines, 2);
        assert_eq!(late.next_deadline_ns, Some(140));
        assert_eq!(screen.read_raw_pixel(0, 0), Some(0x0000_aa00));
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);

        fixture.broker.record_frame_durations(7, 11);
        let metrics = fixture.broker.metrics();
        assert_eq!(metrics.submitted_frames, 2);
        assert_eq!(metrics.composed_frames, 2);
        assert_eq!(metrics.displayed_frames, 2);
        assert_eq!(metrics.late_frames, 1);
        assert_eq!(metrics.missed_deadlines, 2);
        assert_eq!(metrics.composition_duration_ns, 7);
        assert_eq!(metrics.publication_duration_ns, 11);
        assert_eq!(metrics.compositor.composed_frames, 2);
    }

    #[test]
    fn immediate_mode_composes_without_waiting_for_the_paced_deadline() {
        let mut fixture = Fixture::new();
        let id = window(57);
        let config = configuration(1, 1, 1, 2);
        fixture.configure(id, config);
        fixture.place(vec![placement(id, 0, 0, 1, 1, true)]);
        fixture.present(id, config.generation, 0, request(70), 1, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        fixture.broker.frame_clock_mut().reset(1_000);
        fixture
            .broker
            .set_frame_pacing_mode(FramePacingMode::Immediate);

        let mut framebuffer_bytes = [0_u8; 4];
        let mut screen = framebuffer(&mut framebuffer_bytes, 1, 1);
        let outcome = fixture.broker.compose_due(&mut screen, 1).unwrap();
        assert!(outcome.due);
        assert_eq!(outcome.deadline_ns, None);
        assert_eq!(outcome.next_deadline_ns, None);
        assert_eq!(outcome.composed_windows, 1);
    }

    #[test]
    fn configure_reserves_submission_capacity_for_each_new_pool() {
        let mut fixture = Fixture::new();
        let id = window(58);
        fixture.configure(id, configuration(1, 1, 1, 3));
        assert!(fixture.broker.windows[0].submissions.capacity() >= 3);

        fixture.configure(id, configuration(2, 1, 1, 4));
        assert!(fixture.broker.windows[0].transition.is_none());
        assert!(fixture.broker.windows[0].submissions.capacity() >= 4);
    }

    #[test]
    fn accepted_present_result_is_retried_after_channel_backpressure() {
        let mut fixture = Fixture::new();
        let id = window(61);
        let config = configuration(1, 1, 1, 2);
        fixture.configure(id, config);
        fixture.place(vec![placement(id, 0, 0, 1, 1, true)]);
        for _ in 0..CHANNEL_QUEUE_CAPACITY {
            fixture.broker.send_toggle_launcher().unwrap();
        }

        let event = fixture.send(RuntimeMessage::Present {
            client_id: fixture.client_id,
            request_id: request(95),
            window_id: id,
            generation: config.generation,
            buffer_id: BufferId::new(0),
            damage: Vec::new().into(),
        });
        assert!(matches!(
            event,
            DesktopRuntimeEvent::PresentationQueued { .. }
        ));
        assert_eq!(fixture.broker.deferred_notices.len(), 1);

        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        fixture.broker.flush_deferred_notices().unwrap();
        assert!(fixture.broker.deferred_notices.is_empty());
        for _ in 1..CHANNEL_QUEUE_CAPACITY {
            let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        }
        let (accepted, _) = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert!(matches!(
            accepted.message,
            RuntimeMessage::PresentResult {
                request_id,
                result: PresentationResult::Accepted,
                ..
            } if request_id == request(95)
        ));
    }

    #[test]
    fn coalescing_unions_damage_from_every_replaced_frame() {
        let mut fixture = Fixture::new();
        let id = window(60);
        let config = configuration(1, 3, 1, 3);
        let surface = fixture.configure(id, config);
        fixture.place(vec![placement(id, 0, 0, 3, 1, true)]);
        let red = 0x00ff_0000_u32.to_le_bytes();
        for offset in [0, 4, 8, 12, 20, 24, 28] {
            fixture
                .desktop
                .shared_memory_write(surface, offset, &red)
                .unwrap();
        }
        fixture
            .desktop
            .shared_memory_write(surface, 12, &0x0000_ff00_u32.to_le_bytes())
            .unwrap();
        fixture
            .desktop
            .shared_memory_write(surface, 24, &0x0000_ff00_u32.to_le_bytes())
            .unwrap();
        fixture
            .desktop
            .shared_memory_write(surface, 32, &0x0000_00ff_u32.to_le_bytes())
            .unwrap();

        fixture.present(id, config.generation, 0, request(90), 3, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        let mut framebuffer_bytes = [0_u8; 12];
        let mut screen = framebuffer(&mut framebuffer_bytes, 3, 1);
        fixture.broker.compose_pending(&mut screen, id).unwrap();

        fixture.send(RuntimeMessage::Present {
            client_id: fixture.client_id,
            request_id: request(91),
            window_id: id,
            generation: config.generation,
            buffer_id: BufferId::new(1),
            damage: vec![DamageRect::new(InputPoint::new(0, 0), Size::new(1, 1))].into(),
        });
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        fixture.send(RuntimeMessage::Present {
            client_id: fixture.client_id,
            request_id: request(92),
            window_id: id,
            generation: config.generation,
            buffer_id: BufferId::new(2),
            damage: vec![DamageRect::new(InputPoint::new(2, 0), Size::new(1, 1))].into(),
        });
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);

        fixture.broker.compose_pending(&mut screen, id).unwrap();
        assert_eq!(screen.read_raw_pixel(0, 0), Some(0x0000_ff00));
        assert_eq!(screen.read_raw_pixel(1, 0), Some(0x00ff_0000));
        assert_eq!(screen.read_raw_pixel(2, 0), Some(0x0000_00ff));
    }

    #[test]
    fn coalescing_releases_exact_pending_request_without_releasing_displayed_buffer() {
        let mut fixture = Fixture::new();
        let id = window(59);
        let config = configuration(1, 1, 1, 3);
        fixture.configure(id, config);
        fixture.place(vec![placement(id, 0, 0, 1, 1, true)]);
        let initial = fixture.present(id, config.generation, 0, request(80), 1, 1);
        let first_serial = match initial {
            DesktopRuntimeEvent::PresentationQueued {
                presentation_serial,
                ..
            } => presentation_serial,
            other => panic!("unexpected event: {other:?}"),
        };
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        let mut framebuffer_bytes = [0_u8; 4];
        let mut screen = framebuffer(&mut framebuffer_bytes, 1, 1);
        fixture.broker.compose_pending(&mut screen, id).unwrap();

        fixture.present(id, config.generation, 1, request(81), 1, 1);
        let _ = receive(&mut fixture.desktop, fixture.desktop_channel);
        let capacity = fixture.broker.windows[0].submissions.capacity();
        fixture.present(id, config.generation, 2, request(82), 1, 1);

        let (coalesced_release, attachments) =
            receive(&mut fixture.desktop, fixture.desktop_channel);
        assert!(attachments.is_empty());
        assert!(matches!(
            coalesced_release.message,
            RuntimeMessage::BufferReleased {
                buffer_id,
                present_request_id,
                ..
            } if buffer_id == BufferId::new(1) && present_request_id == request(81)
        ));
        let (accepted, _) = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert!(matches!(
            accepted.message,
            RuntimeMessage::PresentResult {
                request_id,
                result: PresentationResult::Accepted,
                ..
            } if request_id == request(82)
        ));
        assert_eq!(fixture.broker.windows[0].submissions.capacity(), capacity);
        assert!(fixture.broker.windows[0]
            .submissions
            .iter()
            .all(|submission| submission.request_id != request(81)));
        assert_eq!(
            fixture
                .broker
                .handles
                .window_manager_displayed(fixture.broker.windows[0].manager)
                .unwrap()
                .unwrap()
                .presentation_serial,
            first_serial
        );

        let metrics = fixture.broker.metrics();
        assert_eq!(metrics.submitted_frames, 3);
        assert_eq!(metrics.coalesced_frames, 1);
        assert_eq!(metrics.dropped_frames, 1);
        assert_eq!(metrics.displayed_frames, 1);

        let outcome = fixture.broker.compose_pending(&mut screen, id).unwrap();
        assert_eq!(outcome.request_id, request(82));
        assert_eq!(outcome.released_request_id, Some(request(80)));
        let (displayed_release, _) = receive(&mut fixture.desktop, fixture.desktop_channel);
        assert!(matches!(
            displayed_release.message,
            RuntimeMessage::BufferReleased {
                buffer_id,
                present_request_id,
                ..
            } if buffer_id == BufferId::new(0) && present_request_id == request(80)
        ));
    }

    #[test]
    fn destroy_and_disconnect_cleanup_remove_compositor_and_capabilities() {
        let mut fixture = Fixture::new();
        let first = window(60);
        let second = window(61);
        fixture.configure(first, configuration(1, 1, 1, 2));
        fixture.configure(second, configuration(1, 1, 1, 2));
        fixture.place(vec![
            placement(first, 0, 0, 1, 1, false),
            placement(second, 1, 0, 1, 1, true),
        ]);
        fixture.configure(first, configuration(2, 2, 1, 2));
        fixture.configure(second, configuration(2, 2, 1, 2));
        let first_current = fixture.broker.windows[0].manager;
        let first_staged = fixture.broker.windows[0]
            .transition
            .as_ref()
            .unwrap()
            .manager;
        let second_current = fixture.broker.windows[1].manager;
        let second_staged = fixture.broker.windows[1]
            .transition
            .as_ref()
            .unwrap()
            .manager;

        assert!(matches!(
            fixture.send(RuntimeMessage::DestroyWindow {
                client_id: fixture.client_id,
                window_id: first,
            }),
            DesktopRuntimeEvent::WindowDestroyed { .. }
        ));
        assert_eq!(fixture.broker.window_count(), 1);
        assert!(fixture.broker.compositor().window(first.get()).is_none());
        assert_eq!(
            fixture.broker.handles.object_type(first_current),
            Err(IpcError::InvalidHandle)
        );
        assert_eq!(
            fixture.broker.handles.object_type(first_staged),
            Err(IpcError::InvalidHandle)
        );
        assert_eq!(fixture.broker.cleanup_client(fixture.client_id).unwrap(), 1);
        assert_eq!(
            fixture.broker.handles.object_type(second_current),
            Err(IpcError::InvalidHandle)
        );
        assert_eq!(
            fixture.broker.handles.object_type(second_staged),
            Err(IpcError::InvalidHandle)
        );
        assert_eq!(fixture.broker.window_count(), 0);
        assert!(fixture.broker.compositor().windows().is_empty());
        assert!(!fixture.broker.owns_client(fixture.client_id));
        assert_eq!(fixture.broker.focused_window(), None);
        assert_eq!(fixture.broker.cleanup_client(fixture.client_id).unwrap(), 0);
    }
}
