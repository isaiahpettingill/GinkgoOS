#![no_std]
#![no_main]

extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};
use core::mem::MaybeUninit;

use ginkgo_desktop::{
    ClientId, Desktop, DesktopAction, DesktopPolicy, HorizontalAlignment, Insets,
    PresentationResult, RuntimeMessage, RuntimePacket, RuntimePlacement, RuntimeSender,
    TrustedCommand, MAX_RUNTIME_PLACEMENTS,
};
use ginkgo_userspace::{
    channel_read, channel_write, debug_write, handle_close, process_yield, Handle,
    HandleDisposition, ObjectType, ReceivedHandle, Rights, Status, CHANNEL_MAX_BYTES,
    CHANNEL_MAX_HANDLES,
};
use ginkgo_window::{
    decode_request, encode_event, Configured, ScaleFactor, ServerErrorCode, WireEvent, WireRequest,
    PROTOCOL_VERSION,
};

const MAX_CLIENTS: usize = 64;
const MAX_BROKER_QUEUE: usize = 512;
const BROKER_BACKPRESSURE_THRESHOLD: usize = 384;
const MAX_CLIENT_QUEUE: usize = 128;
const CLIENT_BACKPRESSURE_THRESHOLD: usize = 96;
const MAX_READS_PER_TURN: usize = 32;
const MAX_WRITES_PER_TURN: usize = 32;

const CLIENT_CHANNEL_RIGHTS: Rights =
    Rights::from_bits_retain(Rights::READ.bits() | Rights::WRITE.bits());
const SURFACE_SOURCE_RIGHTS: Rights = Rights::from_bits_retain(
    Rights::READ.bits() | Rights::WRITE.bits() | Rights::MAP.bits() | Rights::TRANSFER.bits(),
);
const SURFACE_CLIENT_RIGHTS: Rights =
    Rights::from_bits_retain(Rights::READ.bits() | Rights::WRITE.bits() | Rights::MAP.bits());

ginkgo_runtime::entry!(process_main);

extern "C" fn process_main(bootstrap_raw: u64, width: u64, height: u64) -> ! {
    let Some(bootstrap) = u32::try_from(bootstrap_raw)
        .ok()
        .map(Handle::from_raw)
        .filter(|handle| handle.is_valid())
    else {
        fail(b"desktop-service: invalid bootstrap handle\n", 1);
    };
    let (Ok(width), Ok(height)) = (u32::try_from(width), u32::try_from(height)) else {
        fail(b"desktop-service: invalid output dimensions\n", 1);
    };

    let mut service = match Service::new(bootstrap, ginkgo_window::Size::new(width, height)) {
        Ok(service) => service,
        Err(_) => fail(b"desktop-service: initialization failed\n", 1),
    };
    let _ = debug_write(b"desktop-service: runtime online\n");
    if let Err(error) = service.run() {
        let message = match error {
            ServiceError::InvalidBootstrap => b"desktop-service: invalid bootstrap\n".as_slice(),
            ServiceError::InvalidMessage => b"desktop-service: invalid message\n".as_slice(),
            ServiceError::Capacity => b"desktop-service: capacity exhausted\n".as_slice(),
            ServiceError::Codec => b"desktop-service: codec failure\n".as_slice(),
            ServiceError::Desktop => b"desktop-service: policy failure\n".as_slice(),
            ServiceError::Syscall(Status::ShouldWait) => {
                b"desktop-service: leaked should-wait\n".as_slice()
            }
            ServiceError::Syscall(_) => b"desktop-service: syscall failure\n".as_slice(),
        };
        fail(message, 2);
    }
    ginkgo_runtime::exit(0)
}

fn desktop_hotkey(event: ginkgo_window::KeyboardEvent) -> Option<TrustedCommand> {
    if !event.modifiers.logo || event.state != ginkgo_window::ButtonState::Pressed || event.repeat {
        return None;
    }
    Some(match event.usage {
        0x50 => TrustedCommand::FocusLeft,
        0x4f => TrustedCommand::FocusRight,
        0x14 => TrustedCommand::CloseFocused,
        0x04 => TrustedCommand::MoveFocusedLeft,
        0x16 => TrustedCommand::MoveFocusedRight,
        0x2e => TrustedCommand::AdjustFocusedWidth {
            delta_per_mille: 50,
        },
        0x2d => TrustedCommand::AdjustFocusedWidth {
            delta_per_mille: -50,
        },
        0x0f => TrustedCommand::AlignFocused {
            alignment: HorizontalAlignment::Left,
        },
        0x06 => TrustedCommand::AlignFocused {
            alignment: HorizontalAlignment::Center,
        },
        0x15 => TrustedCommand::AlignFocused {
            alignment: HorizontalAlignment::Right,
        },
        _ => return None,
    })
}

fn fail(message: &[u8], code: i32) -> ! {
    let _ = debug_write(message);
    ginkgo_runtime::exit(code)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceError {
    InvalidBootstrap,
    InvalidMessage,
    Capacity,
    Codec,
    Desktop,
    Syscall(Status),
}

struct OwnedHandle(Handle);

impl OwnedHandle {
    fn new(handle: Handle) -> Result<Self, ServiceError> {
        handle
            .is_valid()
            .then_some(Self(handle))
            .ok_or(ServiceError::InvalidMessage)
    }

    const fn get(&self) -> Handle {
        self.0
    }

    fn disarm(&mut self) {
        self.0 = Handle::INVALID;
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0.is_valid() {
            let _ = handle_close(self.0);
        }
    }
}

struct Attachment {
    handle: OwnedHandle,
    rights: Rights,
    object_type: ObjectType,
    reserved: u32,
}

impl Attachment {
    fn from_received(received: ReceivedHandle) -> Result<Self, ServiceError> {
        Ok(Self {
            handle: OwnedHandle::new(received.handle)?,
            rights: received.rights,
            object_type: received.object_type,
            reserved: received.reserved,
        })
    }

    fn validate(&self, object_type: ObjectType, required: Rights) -> Result<(), ServiceError> {
        if self.reserved != 0
            || self.object_type != object_type
            || self.rights.bits() & !Rights::all().bits() != 0
            || !self.rights.contains(required)
            || self.rights.contains(Rights::MANAGE)
        {
            return Err(ServiceError::InvalidMessage);
        }
        Ok(())
    }
}

struct IncomingMessage {
    bytes: Vec<u8>,
    attachments: Vec<Attachment>,
}

enum ClientOutbound {
    Event(Vec<u8>),
    Configured {
        bytes: Vec<u8>,
        surface: OwnedHandle,
    },
}

struct ClientConnection {
    id: ClientId,
    channel: OwnedHandle,
    outbound: VecDeque<ClientOutbound>,
}

impl ClientConnection {
    fn new(id: ClientId, channel: OwnedHandle) -> Self {
        Self {
            id,
            channel,
            outbound: VecDeque::new(),
        }
    }
}

struct Service {
    desktop: Desktop,
    broker: OwnedHandle,
    clients: Vec<ClientConnection>,
    broker_outbound: VecDeque<Vec<u8>>,
    launcher_visible: bool,
}

impl Service {
    fn new(bootstrap: Handle, output: ginkgo_window::Size) -> Result<Self, ServiceError> {
        if output.is_empty() {
            return Err(ServiceError::InvalidBootstrap);
        }
        let mut policy = DesktopPolicy::default();
        policy.scale = ScaleFactor::new(1, 1).map_err(|_| ServiceError::Desktop)?;
        policy.window_margins = Insets::new(12, 12, 12, 12);
        Ok(Self {
            desktop: Desktop::with_policy(output, policy).map_err(|_| ServiceError::Desktop)?,
            broker: OwnedHandle::new(bootstrap)?,
            clients: Vec::new(),
            broker_outbound: VecDeque::new(),
            launcher_visible: false,
        })
    }

    fn run(&mut self) -> Result<(), ServiceError> {
        self.queue_broker(RuntimeMessage::ServiceReady {
            window_protocol_version: PROTOCOL_VERSION,
        })?;

        loop {
            self.flush_broker()?;
            self.service_clients()?;

            for _ in 0..MAX_READS_PER_TURN {
                let Some(message) = read_message(self.broker.get())? else {
                    break;
                };
                self.handle_broker_message(message)?;
            }

            self.service_clients()?;
            self.flush_broker()?;
            process_yield().map_err(ServiceError::Syscall)?;
        }
    }

    fn handle_broker_message(&mut self, mut incoming: IncomingMessage) -> Result<(), ServiceError> {
        let packet = RuntimePacket::decode(
            &incoming.bytes,
            RuntimeSender::KernelBroker,
            incoming.attachments.len(),
        )
        .map_err(|_| ServiceError::Codec)?;

        match packet.message {
            RuntimeMessage::ToggleLauncher => {
                self.launcher_visible = !self.launcher_visible;
                self.queue_broker(RuntimeMessage::LauncherVisibility {
                    visible: self.launcher_visible,
                })?;
            }
            RuntimeMessage::ClientConnected {
                client_id,
                channel_attachment,
            } => {
                if self.clients.len() >= MAX_CLIENTS || self.client_index(client_id).is_some() {
                    return Err(ServiceError::Capacity);
                }
                let attachment =
                    take_attachment(&mut incoming.attachments, channel_attachment.get())?;
                attachment.validate(ObjectType::Channel, CLIENT_CHANNEL_RIGHTS)?;
                self.clients
                    .push(ClientConnection::new(client_id, attachment.handle));
            }
            RuntimeMessage::SurfaceReady {
                client_id,
                window_id,
                generation,
                surface_attachment,
            } => {
                let attachment =
                    take_attachment(&mut incoming.attachments, surface_attachment.get())?;
                attachment.validate(ObjectType::SharedMemory, SURFACE_SOURCE_RIGHTS)?;

                let Some(window) = self.desktop.window(window_id) else {
                    return Ok(());
                };
                let Some(configuration) = window.configuration else {
                    return Ok(());
                };
                if window.owner != client_id || configuration.generation != generation {
                    return Ok(());
                }
                self.queue_configured(client_id, window_id, configuration, attachment.handle)?;
            }
            RuntimeMessage::PresentResult {
                client_id,
                request_id,
                window_id: _,
                generation: _,
                buffer_id: _,
                result,
            } => {
                if self.client_index(client_id).is_none() {
                    return Ok(());
                }
                if let PresentationResult::Rejected(code) = result {
                    self.queue_client_event(
                        client_id,
                        WireEvent::RequestFailed { request_id, code },
                    )?;
                }
            }
            RuntimeMessage::BufferReleased {
                client_id,
                window_id,
                generation,
                buffer_id,
                present_request_id,
            } => {
                if self.client_index(client_id).is_none() {
                    return Ok(());
                }
                self.queue_client_event(
                    client_id,
                    WireEvent::BufferReleased {
                        window_id,
                        generation,
                        buffer_id,
                        present_request_id,
                    },
                )?;
            }
            RuntimeMessage::PointerInput { position, kind } => {
                if !self.launcher_visible {
                    let actions = self
                        .desktop
                        .handle_trusted_command(TrustedCommand::PointerInput { position, kind })
                        .map_err(|_| ServiceError::Desktop)?;
                    self.execute_actions(actions)?;
                }
            }
            RuntimeMessage::KeyboardInput { event } => {
                if !self.launcher_visible {
                    let command =
                        desktop_hotkey(event).unwrap_or(TrustedCommand::KeyboardInput { event });
                    let actions = self
                        .desktop
                        .handle_trusted_command(command)
                        .map_err(|_| ServiceError::Desktop)?;
                    self.execute_actions(actions)?;
                }
            }
            RuntimeMessage::ServiceReady { .. }
            | RuntimeMessage::LauncherVisibility { .. }
            | RuntimeMessage::Configure { .. }
            | RuntimeMessage::DestroyWindow { .. }
            | RuntimeMessage::SetPlacements { .. }
            | RuntimeMessage::Present { .. } => return Err(ServiceError::InvalidMessage),
        }
        Ok(())
    }

    fn service_clients(&mut self) -> Result<(), ServiceError> {
        let mut index = 0;
        while index < self.clients.len() {
            if self.flush_client(index).is_err() {
                self.disconnect_client(index)?;
                continue;
            }

            if self.clients[index].outbound.len() >= CLIENT_BACKPRESSURE_THRESHOLD
                || self.broker_outbound.len() >= BROKER_BACKPRESSURE_THRESHOLD
            {
                index += 1;
                continue;
            }

            let mut disconnected = false;
            let mut broker_backpressured = false;
            for _ in 0..MAX_READS_PER_TURN {
                let channel = self.clients[index].channel.get();
                let incoming = match read_message(channel) {
                    Ok(Some(incoming)) => incoming,
                    Ok(None) => break,
                    Err(ServiceError::Syscall(Status::PeerClosed)) => {
                        disconnected = true;
                        break;
                    }
                    Err(_) => {
                        disconnected = true;
                        break;
                    }
                };
                if !incoming.attachments.is_empty() {
                    disconnected = true;
                    break;
                }
                let request = match decode_request(&incoming.bytes, 0) {
                    Ok(request) => request,
                    Err(_) => {
                        disconnected = true;
                        break;
                    }
                };
                let client_id = self.clients[index].id;
                if let WireRequest::CreateWindow { request_id, .. } = &request {
                    if self.desktop.windows().len() >= MAX_RUNTIME_PLACEMENTS {
                        self.queue_client_event(
                            client_id,
                            WireEvent::RequestFailed {
                                request_id: *request_id,
                                code: ServerErrorCode::OutOfResources,
                            },
                        )?;
                        continue;
                    }
                }
                let actions = self.desktop.handle_request(client_id, request);
                self.execute_actions(actions)?;
                self.flush_broker()?;
                if self.broker_outbound.len() >= BROKER_BACKPRESSURE_THRESHOLD {
                    broker_backpressured = true;
                    break;
                }
            }

            if disconnected {
                self.disconnect_client(index)?;
            } else if broker_backpressured {
                return Ok(());
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    fn disconnect_client(&mut self, index: usize) -> Result<(), ServiceError> {
        let client = self.clients.remove(index);
        let actions = self
            .desktop
            .disconnect_client(client.id)
            .map_err(|_| ServiceError::Desktop)?;
        drop(client);
        self.execute_actions(actions)
    }

    fn execute_actions(&mut self, actions: Vec<DesktopAction>) -> Result<(), ServiceError> {
        for action in actions {
            match action {
                DesktopAction::WindowCreated {
                    client_id,
                    protocol_version,
                    request_id,
                    window_id,
                } => self.queue_client_event(
                    client_id,
                    WireEvent::WindowCreated {
                        protocol_version,
                        request_id,
                        window_id,
                    },
                )?,
                DesktopAction::Configure {
                    client_id,
                    window_id,
                    configuration,
                } => self.queue_broker(RuntimeMessage::Configure {
                    client_id,
                    window_id,
                    configuration,
                })?,
                DesktopAction::DestroyWindow {
                    client_id,
                    request_id: _,
                    window_id,
                } => self.queue_broker(RuntimeMessage::DestroyWindow {
                    client_id,
                    window_id,
                })?,
                DesktopAction::RequestFailed {
                    client_id,
                    request_id,
                    code,
                } => self
                    .queue_client_event(client_id, WireEvent::RequestFailed { request_id, code })?,
                DesktopAction::SetPlacements { placements } => {
                    let placements = placements.into_iter().map(RuntimePlacement::from).collect();
                    self.queue_broker(RuntimeMessage::SetPlacements { placements })?;
                }
                DesktopAction::FocusChanged {
                    client_id,
                    window_id,
                    focused,
                } => self.queue_client_event(
                    client_id,
                    WireEvent::FocusChanged { window_id, focused },
                )?,
                DesktopAction::CloseRequested {
                    client_id,
                    window_id,
                } => self.queue_client_event(client_id, WireEvent::CloseRequested { window_id })?,
                DesktopAction::Present {
                    client_id,
                    request_id,
                    window_id,
                    generation,
                    buffer_id,
                    damage,
                } => self.queue_broker(RuntimeMessage::Present {
                    client_id,
                    request_id,
                    window_id,
                    generation,
                    buffer_id,
                    damage,
                })?,
                DesktopAction::ForwardPointer {
                    client_id,
                    window_id,
                    event,
                } => self.queue_client_event(client_id, WireEvent::Pointer { window_id, event })?,
                DesktopAction::ForwardKeyboard {
                    client_id,
                    window_id,
                    event,
                } => {
                    self.queue_client_event(client_id, WireEvent::Keyboard { window_id, event })?
                }
            }
        }
        Ok(())
    }

    fn queue_broker(&mut self, message: RuntimeMessage) -> Result<(), ServiceError> {
        if self.broker_outbound.len() >= MAX_BROKER_QUEUE {
            return Err(ServiceError::Capacity);
        }
        let packet = RuntimePacket::new(message);
        let bytes = packet
            .encode_validated(RuntimeSender::DesktopService, 0)
            .map_err(|_| ServiceError::Codec)?;
        self.broker_outbound.push_back(bytes);
        Ok(())
    }

    fn queue_client_event(
        &mut self,
        client_id: ClientId,
        event: WireEvent,
    ) -> Result<(), ServiceError> {
        let bytes = encode_event(&event).map_err(|_| ServiceError::Codec)?;
        let client = self.client_mut(client_id)?;
        if client.outbound.len() >= MAX_CLIENT_QUEUE {
            return Err(ServiceError::Capacity);
        }
        client.outbound.push_back(ClientOutbound::Event(bytes));
        Ok(())
    }

    fn queue_configured(
        &mut self,
        client_id: ClientId,
        window_id: ginkgo_window::WindowId,
        configuration: ginkgo_window::SurfaceConfiguration,
        surface: OwnedHandle,
    ) -> Result<(), ServiceError> {
        let event = WireEvent::Configured(Configured {
            window_id,
            configuration,
            surface_handle_index: 0,
        });
        let bytes = encode_event(&event).map_err(|_| ServiceError::Codec)?;
        let client = self.client_mut(client_id)?;
        if client.outbound.len() >= MAX_CLIENT_QUEUE {
            return Err(ServiceError::Capacity);
        }
        client
            .outbound
            .push_back(ClientOutbound::Configured { bytes, surface });
        Ok(())
    }

    fn flush_broker(&mut self) -> Result<(), ServiceError> {
        for _ in 0..MAX_WRITES_PER_TURN {
            let Some(bytes) = self.broker_outbound.front() else {
                break;
            };
            match channel_write(self.broker.get(), bytes, &[]) {
                Ok(()) => {
                    self.broker_outbound.pop_front();
                }
                Err(Status::ShouldWait) => break,
                Err(status) => return Err(ServiceError::Syscall(status)),
            }
        }
        Ok(())
    }

    fn flush_client(&mut self, index: usize) -> Result<(), ServiceError> {
        for _ in 0..MAX_WRITES_PER_TURN {
            let channel = self.clients[index].channel.get();
            let Some(outbound) = self.clients[index].outbound.front_mut() else {
                break;
            };
            let result = match outbound {
                ClientOutbound::Event(bytes) => channel_write(channel, bytes, &[]),
                ClientOutbound::Configured { bytes, surface } => {
                    let disposition =
                        HandleDisposition::move_handle(surface.get(), SURFACE_CLIENT_RIGHTS);
                    let result = channel_write(channel, bytes, &[disposition]);
                    if result.is_ok() {
                        surface.disarm();
                    }
                    result
                }
            };
            match result {
                Ok(()) => {
                    self.clients[index].outbound.pop_front();
                }
                Err(Status::ShouldWait) => break,
                Err(status) => return Err(ServiceError::Syscall(status)),
            }
        }
        Ok(())
    }

    fn client_index(&self, client_id: ClientId) -> Option<usize> {
        self.clients
            .iter()
            .position(|client| client.id == client_id)
    }

    fn client_mut(&mut self, client_id: ClientId) -> Result<&mut ClientConnection, ServiceError> {
        let index = self
            .client_index(client_id)
            .ok_or(ServiceError::InvalidMessage)?;
        Ok(&mut self.clients[index])
    }
}

fn take_attachment(
    attachments: &mut Vec<Attachment>,
    index: u8,
) -> Result<Attachment, ServiceError> {
    let index = usize::from(index);
    if index >= attachments.len() {
        return Err(ServiceError::InvalidMessage);
    }
    Ok(attachments.remove(index))
}

fn read_message(channel: Handle) -> Result<Option<IncomingMessage>, ServiceError> {
    let mut bytes = [0_u8; CHANNEL_MAX_BYTES];
    let mut handles = [MaybeUninit::<ReceivedHandle>::uninit(); CHANNEL_MAX_HANDLES];
    let info = match channel_read(channel, &mut bytes, &mut handles) {
        Ok(info) => info,
        Err(Status::ShouldWait) => return Ok(None),
        Err(status) => return Err(ServiceError::Syscall(status)),
    };

    let byte_count = info.byte_count as usize;
    let handle_count = usize::from(info.handle_count);
    let mut attachments = Vec::with_capacity(handle_count);
    for received in &handles[..handle_count] {
        // SAFETY: channel_read initializes exactly handle_count entries on success.
        let received = unsafe { received.assume_init() };
        match Attachment::from_received(received) {
            Ok(attachment) => attachments.push(attachment),
            Err(error) => {
                for remaining in &handles[attachments.len() + 1..handle_count] {
                    // SAFETY: these entries are also within the initialized prefix.
                    let remaining = unsafe { remaining.assume_init() };
                    if remaining.handle.is_valid() {
                        let _ = handle_close(remaining.handle);
                    }
                }
                return Err(error);
            }
        }
    }

    Ok(Some(IncomingMessage {
        bytes: Vec::from(&bytes[..byte_count]),
        attachments,
    }))
}
